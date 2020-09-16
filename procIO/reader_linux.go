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

func NewMemoryReader(proc Process, seg *MemorySegmentInfo) (MemoryReader, error) {
	memfile, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", proc.PID()), os.O_RDONLY, 0600)
	if err != nil {
		return nil, errors.Errorf("could not open process memory for reading, reason: %w", err)
	}

	_, err = memfile.Seek(int64(seg.BaseAddress), io.SeekStart)
	if err != nil {
		return nil, errors.Errorf("could not access process memory at address 0x%016X, reason: %w", seg.BaseAddress, err)
	}

	rdr := &memfileReader{
		proc: proc,
		seg:  seg,

		memfile: memfile,

		position: 0,
	}

	return rdr, nil
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

func (rdr *memfileReader) Close() error {
	return rdr.memfile.Close()
}
