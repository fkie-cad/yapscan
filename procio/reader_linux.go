package procio

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/targodan/go-errors"
)

type memfileReader struct {
	proc Process
	seg  *MemorySegmentInfo

	memfile *os.File

	position uintptr
}

func newMemoryReader(proc Process, seg *MemorySegmentInfo) (memoryReaderImpl, error) {
	memfile, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", proc.PID()), os.O_RDONLY, 0400)
	if err != nil {
		return nil, fmt.Errorf("could not open process memory for reading, reason: %w", err)
	}

	rdr := &memfileReader{
		proc: proc,
		seg:  seg,

		memfile: memfile,

		position: 0,
	}

	return rdr, nil
}

func (rdr *memfileReader) computeFileOffset() uintptr {
	return rdr.seg.BaseAddress + rdr.position
}

func (rdr *memfileReader) Read(data []byte) (int, error) {
	if rdr.position >= rdr.seg.Size {
		return 0, io.EOF
	}

	l := uintptr(len(data))
	if rdr.position+l > rdr.seg.Size {
		l = rdr.seg.Size - rdr.position
		data = data[:l]
	}

	if len(data) == 0 {
		return 0, nil
	}

	fd := int(rdr.memfile.Fd())
	offset := int64(rdr.computeFileOffset())
	n, err := syscall.Pread(fd, data, offset)

	logrus.WithFields(logrus.Fields{
		"pid":         rdr.proc.PID(),
		"baseAddress": rdr.seg.BaseAddress,
		"state":       rdr.seg.State,
		"size":        rdr.seg.Size,
	}).Tracef("pread(%d, len == %d, %d) -> %d, %v", fd, len(data), offset, n, err)

	if n == 0 {
		return n, io.EOF
	}

	rdr.position += uintptr(n)
	return n, err
}

func (rdr *memfileReader) Seek(offset int64, whence int) (pos int64, err error) {
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

func (rdr *memfileReader) Process() Process {
	return rdr.proc
}

func (rdr *memfileReader) Segment() *MemorySegmentInfo {
	return rdr.seg
}

func (rdr *memfileReader) Close() error {
	return rdr.memfile.Close()
}
