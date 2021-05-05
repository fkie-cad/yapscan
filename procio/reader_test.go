package procio

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"
	"testing"
	"time"

	"github.com/fkie-cad/yapscan/testutil"

	"github.com/fkie-cad/yapscan/testutil/memory"

	. "github.com/smartystreets/goconvey/convey"
)

const testCompilerTimeout = 30 * time.Second
const testerTimeout = 1 * time.Second

func testWithData(c C, tc *testutil.Compiler, data []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), testerTimeout)
	defer cancel()

	tester, err := memory.NewTester(ctx, tc, data, uintptr(PermissionsToNative(Permissions{Read: true})))
	c.Convey("process creation should not fail.", func() {
		So(err, ShouldBeNil)
	})
	if err != nil {
		return
	}
	defer tester.Close()

	address, err := tester.WriteDataAndGetAddress()
	c.Convey("writing the data via pipes should not fail.", func() {
		So(err, ShouldBeNil)
		So(address, ShouldNotEqual, 0)
	})
	if err != nil {
		return
	}

	proc, err := OpenProcess(tester.PID())
	c.Convey("opening the created process should not fail.", func() {
		So(err, ShouldBeNil)
	})
	if err != nil {
		return
	}

	segments, err := proc.MemorySegments()
	c.Convey("reading the remote segments should work.", func() {
		So(err, ShouldBeNil)
	})
	if err != nil {
		return
	}

	var seg *MemorySegmentInfo
	for _, segment := range segments {
		if segment.SubSegments == nil || len(segment.SubSegments) == 0 {
			if segment.BaseAddress <= address && address < segment.BaseAddress+segment.Size {
				// Found segment containing our target
				seg = segment
				break
			}
		} else {
			for _, subseg := range segment.SubSegments {
				if subseg.BaseAddress <= address && address < subseg.BaseAddress+subseg.Size {
					// Found segment containing our target
					seg = subseg
					break
				}
			}
			if seg != nil {
				break
			}
		}
	}

	c.Convey("there should be a segment containing our target.", func() {
		So(seg, ShouldNotBeNil)
	})
	if seg == nil {
		return
	}

	testFullRead(c, proc, seg, address, data)
}

func testFullRead(c C, proc Process, seg *MemorySegmentInfo, address uintptr, expectedData []byte) {
	rdr, err := NewMemoryReader(proc, seg)
	c.Convey("creating a reader should not fail.", func() {
		So(err, ShouldBeNil)
	})
	defer rdr.Close()

	readData, err := ioutil.ReadAll(rdr)
	c.Convey("reading the remote segment should not fail.", func() {
		So(err, ShouldBeNil)
	})

	offset := address - seg.BaseAddress
	c.Convey("the data should be correct.", func() {
		So(len(readData), ShouldBeGreaterThan, offset)
		readData = readData[offset:]
		So(len(readData), ShouldBeGreaterThanOrEqualTo, len(expectedData))
		So(readData[:len(expectedData)], ShouldResemble, expectedData)
	})

	_, err = rdr.Seek(0, io.SeekStart)
	c.Convey("resetting the reader should not fail", func() {
		So(err, ShouldBeNil)
	})

	readData, err = ioutil.ReadAll(rdr)
	c.Convey("reading the remote segment again, should not fail.", func() {
		So(err, ShouldBeNil)
	})

	offset = address - seg.BaseAddress
	c.Convey("the data should still be correct.", func() {
		So(len(readData), ShouldBeGreaterThan, offset)
		readData = readData[offset:]
		So(len(readData), ShouldBeGreaterThanOrEqualTo, len(expectedData))
		So(readData[:len(expectedData)], ShouldResemble, expectedData)
	})
}

func testPartialRead(c C, proc Process, seg *MemorySegmentInfo, address uintptr, expectedData []byte) {
	rdr, err := NewMemoryReader(proc, seg)
	c.Convey("creating a reader should not fail.", func() {
		So(err, ShouldBeNil)
	})
	defer rdr.Close()

	start := 2
	oldPos, err := rdr.Seek(int64(start), io.SeekCurrent)
	c.Convey("seeking relative should not error", func() {
		So(oldPos, ShouldEqual, 0)
		So(err, ShouldBeNil)
	})

	readData, err := ioutil.ReadAll(io.LimitReader(rdr, int64(len(expectedData)-start)))
	c.Convey("reading the remote segment should not fail.", func() {
		So(err, ShouldBeNil)
	})

	expectedData = expectedData[start:]

	offset := address - seg.BaseAddress
	c.Convey("the data should be correct.", func() {
		So(len(readData), ShouldBeGreaterThan, offset)
		readData = readData[offset:]
		So(len(readData), ShouldBeGreaterThanOrEqualTo, len(expectedData))
		So(readData[:len(expectedData)], ShouldResemble, expectedData)
	})
}

func TestReader(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory reader test in short mode")
	}

	tc, err := memory.NewTesterCompiler()
	if err != nil {
		t.Skip("could not build memory test utility, skipping", err)
	}
	compileCtx, cancel := context.WithTimeout(context.Background(), testCompilerTimeout)
	err = tc.Compile(compileCtx)
	cancel()
	if err != nil {
		t.Skip("could not build memory test utility, skipping", err)
	}
	defer tc.Close()

	Convey("Reading text from a remote process", t, func(c C) {
		data := []byte("this data should be copied into a new process and we should then be able to read it from the remote process")
		testWithData(c, tc, data)
	})
	Convey("Reading 12 Zeros from a remote process", t, func(c C) {
		data := bytes.Repeat([]byte{0}, 12)
		testWithData(c, tc, data)
	})
	Convey("Reading 4094 Zeros from a remote process", t, func(c C) {
		data := bytes.Repeat([]byte{0}, 4094)
		testWithData(c, tc, data)
	})
	Convey("Reading 4095 Zeros from a remote process", t, func(c C) {
		data := bytes.Repeat([]byte{0}, 4095)
		testWithData(c, tc, data)
	})
	Convey("Reading 4096 Zeros from a remote process", t, func(c C) {
		data := bytes.Repeat([]byte{0}, 4096)
		testWithData(c, tc, data)
	})
	Convey("Reading 1048575 (1MiB-1) Zeros from a remote process", t, func(c C) {
		data := bytes.Repeat([]byte{0}, 1048575)
		testWithData(c, tc, data)
	})
	Convey("Reading 1048576 (1MiB) Zeros from a remote process", t, func(c C) {
		data := bytes.Repeat([]byte{0}, 1048576)
		testWithData(c, tc, data)
	})
	Convey("Reading 1048577 (1MiB+1) Zeros from a remote process", t, func(c C) {
		data := bytes.Repeat([]byte{0}, 1048577)
		testWithData(c, tc, data)
	})
	Convey("Reading 4096 255's from a remote process", t, func(c C) {
		data := bytes.Repeat([]byte{255}, 4096)
		testWithData(c, tc, data)
	})
	Convey("Reading a pattern from a remote process", t, func(c C) {
		pattern := []byte{0, 1, 10, 20, 35, 60, 98, 125, 128, 190, 200, 230, 254, 255}
		data := bytes.Repeat(pattern, 4096/len(pattern))
		testWithData(c, tc, data)
	})
}
