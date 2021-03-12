package procio

import (
	"errors"
	"io"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/fkie-cad/yapscan/procio/customWin32"

	"github.com/0xrawsec/golang-win32/win32"
)

type copyReader struct {
	proc Process
	seg  *MemorySegmentInfo

	position uintptr
}

func newMemoryReader(proc Process, seg *MemorySegmentInfo) (memoryReaderImpl, error) {
	// TODO: Maybe modify non-readable segments here and restore perms on close
	rdr := &copyReader{
		proc: proc,
		seg:  seg,

		position: 0,
	}
	return rdr, nil
}

func (rdr *copyReader) Read(data []byte) (n int, err error) {
	procHandle, ok := rdr.proc.Handle().(win32.HANDLE)
	if !ok {
		panic("expected process handle to be win32.HANDLE but wasn't; this should never happen")
	}

	if rdr.position >= rdr.seg.Size {
		return 0, io.EOF
	}

	l := uintptr(len(data))
	if rdr.position+l > rdr.seg.Size {
		l = rdr.seg.Size - rdr.position
	}

	n, err = customWin32.ReadProcessMemory(procHandle, win32.LPCVOID(rdr.seg.BaseAddress+rdr.position), data[:l])
	if err != nil && err.(syscall.Errno) == 299 {
		logrus.WithFields(logrus.Fields{
			"segBaseAddress":   rdr.seg.BaseAddress,
			"segSize":          rdr.seg.Size,
			"rdrPos":           rdr.position,
			"bufferSize":       len(data),
			"bufferSizeCap":    cap(data),
			"passedBufferSize": l,
		}).Debug("Got ERROR_PARTIAL_COPY.")
	}
	rdr.position += uintptr(n)
	return
}

func (rdr *copyReader) Seek(offset int64, whence int) (pos int64, err error) {
	switch whence {
	case io.SeekStart:
		pos = offset
	case io.SeekCurrent:
		pos = int64(rdr.position) + offset
	case io.SeekEnd:
		pos = int64(rdr.seg.Size) + offset
	}
	if pos < 0 {
		pos = 0
		err = errors.New("cannot seek before start of segment")
	}
	rdr.position = uintptr(pos)
	return
}

func (rdr *copyReader) Process() Process {
	return rdr.proc
}

func (rdr *copyReader) Segment() *MemorySegmentInfo {
	return rdr.seg
}

func (rdr *copyReader) Close() error {
	return nil
}
