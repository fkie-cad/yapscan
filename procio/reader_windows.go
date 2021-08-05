package procio

import (
	"errors"
	"io"

	"github.com/fkie-cad/yapscan/win32"
	"golang.org/x/sys/windows"

	"github.com/sirupsen/logrus"
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
	procHandle := rdr.proc.Handle().(windows.Handle)

	if rdr.position >= rdr.seg.Size {
		return 0, io.EOF
	}

	l := uintptr(len(data))
	if rdr.position+l > rdr.seg.Size {
		l = rdr.seg.Size - rdr.position
	}

	n, err = win32.ReadProcessMemory(procHandle, rdr.seg.BaseAddress+rdr.position, data[:l])
	if err != nil && err == windows.ERROR_PARTIAL_COPY {
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
