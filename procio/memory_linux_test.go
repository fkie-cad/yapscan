package procio

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/fkie-cad/yapscan/fileio"

	. "github.com/smartystreets/goconvey/convey"
)

const (
	validSegmentSMEMEntry = `7f24d6cad000-7f24d6caf000 r--p 00034000 fe:03 921010                     /usr/lib/ld-linux-x86-64.so.2
Size:                  8 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   8 kB
Pss:                   8 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         8 kB
Referenced:            8 kB
Anonymous:             8 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr mw me ac sd
`
	invalidSegmentSMEMEntry = `7f24d6cad000-7f24d6caf000 BANANA 00034000 fe:03 921010                     /usr/lib/ld-linux-x86-64.so.2
Size:                  8 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                   8 kB
Pss:                   8 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:         8 kB
Referenced:            8 kB
Anonymous:             8 kB
LazyFree:              0 kB
AnonHugePages:         0 kB
ShmemPmdMapped:        0 kB
FilePmdMapped:         0 kB
Shared_Hugetlb:        0 kB
Private_Hugetlb:       0 kB
Swap:                  0 kB
SwapPss:               0 kB
Locked:                0 kB
THPeligible:    0
VmFlags: rd mr mw me ac sd
`
)

func TestParseSMEMFile(t *testing.T) {
	Convey("Valid SMEM data should be parsed correctly", t, func() {
		rdr := bytes.NewBufferString(validSegmentSMEMEntry)
		segments, err := parseSMEMFile(rdr)
		So(err, ShouldBeNil)
		So(segments, ShouldResemble, []*MemorySegmentInfo{
			{
				ParentBaseAddress:    0x7f24d6cad000,
				BaseAddress:          0x7f24d6cad000,
				AllocatedPermissions: Permissions{Read: true},
				CurrentPermissions:   Permissions{Read: true},
				Size:                 0x2000,
				RSS:                  8 * 1024,
				State:                StateCommit,
				Type:                 SegmentTypePrivateMapped,
				MappedFile: fileio.NewFileWithInode(
					"/usr/lib/ld-linux-x86-64.so.2",
					921010,
					0xfe03,
					0x34000,
				),
				SubSegments: []*MemorySegmentInfo{},
			},
		})
	})
	Convey("An invalid SMEM entry followed by a valid entry should be parsed correctly but emit errors", t, func() {
		rdr := bytes.NewBufferString(validSegmentSMEMEntry + invalidSegmentSMEMEntry)
		segments, err := parseSMEMFile(rdr)
		So(err, ShouldNotBeNil)
		So(segments, ShouldResemble, []*MemorySegmentInfo{
			{
				ParentBaseAddress:    0x7f24d6cad000,
				BaseAddress:          0x7f24d6cad000,
				AllocatedPermissions: Permissions{Read: true},
				CurrentPermissions:   Permissions{Read: true},
				Size:                 0x2000,
				RSS:                  8 * 1024,
				State:                StateCommit,
				Type:                 SegmentTypePrivateMapped,
				MappedFile: fileio.NewFileWithInode(
					"/usr/lib/ld-linux-x86-64.so.2",
					921010,
					0xfe03,
					0x34000,
				),
				SubSegments: []*MemorySegmentInfo{},
			},
		})
	})
}

func TestParseSegmentHead(t *testing.T) {
	Convey("Invalid input format should error", t, func() {
		info, err := parseSegmentHead("invalid")
		So(info, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})

	Convey("Too large start address should error", t, func() {
		info, err := parseSegmentHead("ffffffffffffffffff-0048a000 r-xp 00000000 fd:03 960637       /bin/bash")
		So(info, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})

	Convey("Too large end address should error", t, func() {
		info, err := parseSegmentHead("00400000-ffffffffffffffffff r-xp 00000000 fd:03 960637       /bin/bash")
		So(info, ShouldBeNil)
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid permissions should error", t, func() {
		_, err := parseSegmentHead("00400000-0048a000 pppp 00000000 fd:03 960637       /bin/bash")
		So(err, ShouldNotBeNil)
	})

	Convey("Invalid mode should error", t, func() {
		_, err := parseSegmentHead("00400000-0048a000 r-xx 00000000 fd:03 960637       /bin/bash")
		So(err, ShouldNotBeNil)
	})

	Convey("A private file-backed segment should work", t, func() {
		info, err := parseSegmentHead("00400000-0048a000 r-xp 00000000 fd:03 960637       /bin/bash")
		So(err, ShouldBeNil)
		So(info, ShouldResemble, &MemorySegmentInfo{
			ParentBaseAddress: 0x400000,
			BaseAddress:       0x400000,
			AllocatedPermissions: Permissions{
				Read: true, Execute: true,
			},
			CurrentPermissions: Permissions{
				Read: true, Execute: true,
			},
			Size:  0x8a000,
			RSS:   0,
			State: StateCommit,
			Type:  SegmentTypePrivateMapped,
			MappedFile: fileio.NewFileWithInode(
				"/bin/bash",
				960637,
				0xfd03,
				0,
			),
			SubSegments: []*MemorySegmentInfo{},
		})
	})

	Convey("A private file-backed segment with whitespaces should work", t, func() {
		info, err := parseSegmentHead("00400000-0048a000 r-xp 00000000 fd:03 960637       /bin/some path/with whitespaces.txt")
		So(err, ShouldBeNil)
		So(info, ShouldResemble, &MemorySegmentInfo{
			ParentBaseAddress: 0x400000,
			BaseAddress:       0x400000,
			AllocatedPermissions: Permissions{
				Read: true, Execute: true,
			},
			CurrentPermissions: Permissions{
				Read: true, Execute: true,
			},
			Size:  0x8a000,
			RSS:   0,
			State: StateCommit,
			Type:  SegmentTypePrivateMapped,
			MappedFile: fileio.NewFileWithInode(
				"/bin/some path/with whitespaces.txt",
				960637,
				0xfd03,
				0,
			),
			SubSegments: []*MemorySegmentInfo{},
		})
	})

	Convey("A private file-backed segment with trailing whitespace should work", t, func() {
		info, err := parseSegmentHead("00400000-0048a000 r-xp 00000000 fd:03 960637       /bin/bash ")
		So(err, ShouldBeNil)
		So(info, ShouldResemble, &MemorySegmentInfo{
			ParentBaseAddress: 0x400000,
			BaseAddress:       0x400000,
			AllocatedPermissions: Permissions{
				Read: true, Execute: true,
			},
			CurrentPermissions: Permissions{
				Read: true, Execute: true,
			},
			Size:  0x8a000,
			RSS:   0,
			State: StateCommit,
			Type:  SegmentTypePrivateMapped,
			MappedFile: fileio.NewFileWithInode(
				"/bin/bash ",
				960637,
				0xfd03,
				0,
			),
			SubSegments: []*MemorySegmentInfo{},
		})
	})

	Convey("A shared file-backed segment should work", t, func() {
		info, err := parseSegmentHead("00400000-0048a000 rwxs 00000000 fd:03 960637       /bin/bash")
		So(err, ShouldBeNil)
		So(info, ShouldResemble, &MemorySegmentInfo{
			ParentBaseAddress: 0x400000,
			BaseAddress:       0x400000,
			AllocatedPermissions: Permissions{
				Read: true, Write: true, Execute: true,
			},
			CurrentPermissions: Permissions{
				Read: true, Write: true, Execute: true,
			},
			Size:  0x8a000,
			RSS:   0,
			State: StateCommit,
			Type:  SegmentTypeMapped,
			MappedFile: fileio.NewFileWithInode(
				"/bin/bash",
				960637,
				0xfd03,
				0,
			),
			SubSegments: []*MemorySegmentInfo{},
		})
	})

	Convey("A private file-backed segment with write should work", t, func() {
		info, err := parseSegmentHead("00400000-0048a000 rwxp 00000000 fd:03 960637       /bin/bash")
		So(err, ShouldBeNil)
		So(info, ShouldResemble, &MemorySegmentInfo{
			ParentBaseAddress: 0x400000,
			BaseAddress:       0x400000,
			AllocatedPermissions: Permissions{
				Read: true, Write: true, COW: true, Execute: true,
			},
			CurrentPermissions: Permissions{
				Read: true, Write: true, COW: true, Execute: true,
			},
			Size:  0x8a000,
			RSS:   0,
			State: StateCommit,
			Type:  SegmentTypePrivateMapped,
			MappedFile: fileio.NewFileWithInode(
				"/bin/bash",
				960637,
				0xfd03,
				0,
			),
			SubSegments: []*MemorySegmentInfo{},
		})
	})

	Convey("A private file-backed segment with a deleted file should work", t, func() {
		info, err := parseSegmentHead("00400000-0048a000 rwxp 00000000 fd:03 960637       /bin/bash (deleted)")
		So(err, ShouldBeNil)
		So(info, ShouldResemble, &MemorySegmentInfo{
			ParentBaseAddress: 0x400000,
			BaseAddress:       0x400000,
			AllocatedPermissions: Permissions{
				Read: true, Write: true, COW: true, Execute: true,
			},
			CurrentPermissions: Permissions{
				Read: true, Write: true, COW: true, Execute: true,
			},
			Size:  0x8a000,
			RSS:   0,
			State: StateCommit,
			Type:  SegmentTypePrivateMapped,
			MappedFile: fileio.NewFileWithInode(
				"/bin/bash",
				960637,
				0xfd03,
				0,
			),
			SubSegments: []*MemorySegmentInfo{},
		})
	})
}

func TestStateSegmentDetail(t *testing.T) {
	Convey("Reading a key-value pair should work", t, func() {
		rdr := bufio.NewReader(bytes.NewBufferString("SomeKey: Value\n"))
		seg := new(MemorySegmentInfo)

		next, err := stateSegmentDetail(rdr, nil, seg)
		So(next, ShouldEqual, stateSegmentDetail)
		So(err, ShouldBeNil)
	})

	Convey("Reading an invalid key-value pair should error", t, func() {
		rdr := bufio.NewReader(bytes.NewBufferString("Not a key value pair\n"))
		seg := new(MemorySegmentInfo)

		next, err := stateSegmentDetail(rdr, nil, seg)
		So(next, ShouldEqual, stateSegmentDetail)
		So(err, ShouldNotBeNil)
	})

	Convey("Reading an invalid RSS-value should error", t, func() {
		rdr := bufio.NewReader(bytes.NewBufferString("Rss: invalid\n"))
		seg := new(MemorySegmentInfo)

		next, err := stateSegmentDetail(rdr, nil, seg)
		So(next, ShouldEqual, stateSegmentDetail)
		So(err, ShouldNotBeNil)
	})

	Convey("Reading an RSS-value should set it", t, func() {
		rdr := bufio.NewReader(bytes.NewBufferString("Rss: 4 kB\n"))
		seg := new(MemorySegmentInfo)

		next, err := stateSegmentDetail(rdr, nil, seg)
		So(next, ShouldEqual, stateSegmentDetail)
		So(err, ShouldBeNil)
		So(seg.RSS, ShouldEqual, 4*1024)
	})

	Convey("Reading a 0-RSS-value should set it and StateReserve", t, func() {
		rdr := bufio.NewReader(bytes.NewBufferString("Rss: 0 kB\n"))
		seg := new(MemorySegmentInfo)

		next, err := stateSegmentDetail(rdr, nil, seg)
		So(next, ShouldEqual, stateSegmentDetail)
		So(err, ShouldBeNil)
		So(seg.RSS, ShouldEqual, 0)
		So(seg.State, ShouldEqual, StateReserve)
	})

	Convey("Encountering an error during reading should emit that error", t, func() {
		rdr := bufio.NewReader(bytes.NewBufferString("the missing newline will cause an EOF"))
		seg := new(MemorySegmentInfo)

		next, err := stateSegmentDetail(rdr, nil, seg)
		So(next, ShouldEqual, stateSegmentDetail)
		So(err, ShouldBeError, io.EOF)
	})
}

func TestParseKeyValue(t *testing.T) {
	Convey("Parsing a valid key-value pair should work", t, func() {
		key, value, err := parseKeyValue("somekey: someval")
		So(err, ShouldBeNil)
		So(key, ShouldEqual, "somekey")
		So(value, ShouldEqual, "someval")
	})

	Convey("Parsing invalid input should error", t, func() {
		_, _, err := parseKeyValue("notAKeyValue")
		So(err, ShouldNotBeNil)
	})
}

func TestParseBytes(t *testing.T) {
	Convey("Parsing input with multiple spaces should error", t, func() {
		_, err := parseBytes("something thats not bytes")
		So(err, ShouldNotBeNil)
	})

	Convey("Parsing input with an unsupported unit should error", t, func() {
		// Only "kB" is supported
		_, err := parseBytes("42 GB")
		So(err, ShouldNotBeNil)
	})

	Convey("Parsing input with something that's not a number should error", t, func() {
		// Only "kB" is supported
		_, err := parseBytes("allthe kB")
		So(err, ShouldNotBeNil)
	})

	Convey("Parsing valid input should work", t, func() {
		// Only "kB" is supported
		bytes, err := parseBytes("42 kB")
		So(bytes, ShouldEqual, 42*1024)
		So(err, ShouldBeNil)
	})
}

func TestPermissionsToNative(t *testing.T) {
	parameters := []struct {
		perm   Permissions
		native int
	}{
		{Permissions{}, nativeProtNone},
		{Permissions{Read: true}, nativeProtRead},
		{Permissions{Write: true}, nativeProtWrite},
		{Permissions{Execute: true}, nativeProtExec},
		{Permissions{Read: true, Write: true}, nativeProtRead | nativeProtWrite},
		{Permissions{Read: true, Execute: true}, nativeProtRead | nativeProtExec},
		{Permissions{Write: true, Execute: true}, nativeProtWrite | nativeProtExec},
		{Permissions{Read: true, Write: true, Execute: true}, nativeProtRead | nativeProtWrite | nativeProtExec},
	}

	for _, param := range parameters {
		Convey(fmt.Sprintf("%s should decode correctly", param.perm), t, func() {
			native := PermissionsToNative(param.perm)
			So(native, ShouldEqual, param.native)
		})
	}
}

func TestSanitizeMappedFile(t *testing.T) {
	Convey("Sanitizing a segment without a mapped file should do nothing", t, func() {
		proc := NewMockProcess(t)

		seg := &MemorySegmentInfo{}
		sanitizeMappedFile(proc, seg)
		So(seg, ShouldResemble, &MemorySegmentInfo{})
	})

	Convey("Sanitizing a segment with a mapped file", t, func() {
		Convey("without any special escapes should do nothing", func() {
			proc := NewMockProcess(t)

			seg := &MemorySegmentInfo{
				MappedFile: fileio.NewFile("/some/normal/path"),
			}

			sanitizeMappedFile(proc, seg)

			So(seg, ShouldResemble, &MemorySegmentInfo{
				MappedFile: fileio.NewFile("/some/normal/path"),
			})
		})

		Convey("with a newline escape sequence", func() {
			pid := 42
			proc := NewMockProcess(t)
			proc.On("PID").Return(pid)

			Convey("where the link is non-existent should do nothing", func() {
				seg := &MemorySegmentInfo{
					MappedFile: fileio.NewFile("/path/withEscapeSequence\\012"),
				}

				sanitizeMappedFile(proc, seg)

				So(seg, ShouldResemble, &MemorySegmentInfo{
					MappedFile: fileio.NewFile("/path/withEscapeSequence\\012"),
				})
			})

			Convey("but the link shows its a literal '\\012' should do nothing", func() {
				origProcPath := procPath
				defer func() {
					procPath = origProcPath
				}()

				tempdir := t.TempDir()
				procPath = tempdir

				mappedName := "/path/withEscapeSequence\\012/but/notANewline"
				seg := &MemorySegmentInfo{
					MappedFile: fileio.NewFile(mappedName),
				}

				mapFilesPath := fmt.Sprintf("%s/%d/map_files", tempdir, pid)
				os.MkdirAll(mapFilesPath, 0700)
				os.Symlink(mappedName, fmt.Sprintf("%s/%x-%x", mapFilesPath, seg.BaseAddress, seg.BaseAddress+seg.Size))

				sanitizeMappedFile(proc, seg)

				So(seg, ShouldResemble, &MemorySegmentInfo{
					MappedFile: fileio.NewFile(mappedName),
				})
			})

			Convey("and its a newline character should replace the path", func() {
				origProcPath := procPath
				defer func() {
					procPath = origProcPath
				}()

				tempdir := t.TempDir()
				procPath = tempdir

				mappedName := "/path/withEscapeSequence\\012/asNewline"
				readName := "/path/withEscapeSequence\n/asNewline"
				seg := &MemorySegmentInfo{
					MappedFile: fileio.NewFile(mappedName),
				}

				mapFilesPath := fmt.Sprintf("%s/%d/map_files", tempdir, pid)
				os.MkdirAll(mapFilesPath, 0700)
				os.Symlink(readName, fmt.Sprintf("%s/%x-%x", mapFilesPath, seg.BaseAddress, seg.BaseAddress+seg.Size))

				sanitizeMappedFile(proc, seg)

				So(seg, ShouldResemble, &MemorySegmentInfo{
					MappedFile: fileio.NewFile(readName),
				})
			})
		})
	})
}
