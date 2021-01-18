package procIO

import (
	"fmt"
	"io"
	"os"

	"github.com/targodan/go-errors"
)

type memfileReader struct {
	proc Process
	seg  *MemorySegmentInfo

	memfile *os.File

	position uintptr
}

func newMemoryReader(proc Process, seg *MemorySegmentInfo) (memoryReaderImpl, error) {
	memfile, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", proc.PID()), os.O_RDONLY, 0600)
	if err != nil {
		return nil, errors.Errorf("could not open process memory for reading, reason: %w", err)
	}

	rdr := &memfileReader{
		proc: proc,
		seg:  seg,

		memfile: memfile,

		position: 0,
	}

	rdr.seekToPosition()

	return rdr, nil
}

func (rdr *memfileReader) seekToPosition() error {
	filePos := rdr.seg.BaseAddress + rdr.position
	_, err := rdr.memfile.Seek(int64(filePos), io.SeekStart)
	if err != nil {
		return errors.Errorf("could not access process memory at address 0x%016X, reason: %w", filePos, err)
	}
	return nil
}

func (rdr *memfileReader) Read(data []byte) (int, error) {
	if rdr.position >= rdr.seg.Size {
		return 0, io.EOF
	}

	l := uintptr(len(data))
	if rdr.position+l > rdr.seg.Size {
		l = rdr.seg.Size - rdr.position
	}

	n, err := io.LimitReader(rdr.memfile, int64(l)).Read(data)
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
	err = rdr.seekToPosition()
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
