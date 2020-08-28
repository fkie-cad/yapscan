package procIO

import (
	"io"

	"fraunhofer/fkie/yapscan/procIO/customWin32"

	"github.com/0xrawsec/golang-win32/win32"
)

type copyReader struct {
	proc Process
	seg  *MemorySegmentInfo

	position uint64
}

func NewMemoryReader(proc Process, seg *MemorySegmentInfo) MemoryReader {
	// TODO: Maybe modify non-readable segments here and restore perms on close
	rdr := &copyReader{
		proc: proc,
		seg:  seg,

		position: 0,
	}
	return rdr
}

func (rdr *copyReader) Read(data []byte) (n int, err error) {
	procHandle, ok := rdr.proc.Handle().(win32.HANDLE)
	if !ok {
		panic("expected process handle to be win32.HANDLE but wasn't; this should never happen")
	}

	if rdr.position >= rdr.seg.Size {
		return 0, io.EOF
	}

	l := uint64(len(data))
	if rdr.position+l > rdr.seg.Size {
		l = rdr.seg.Size - rdr.position
	}

	n, err = customWin32.ReadProcessMemory(procHandle, win32.LPCVOID(rdr.seg.BaseAddress+rdr.position), data[:l])
	rdr.position += uint64(n)
	return
}

func (rdr *copyReader) Close() error {
	return nil
}
