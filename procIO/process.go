package procIO

import (
	"fmt"
	"io"
)

type Process interface {
	io.Closer
	fmt.Stringer

	Handle() interface{}
	MemorySegments() ([]*MemorySegmentInfo, error)
}

func OpenProcess(pid int) (Process, error) {
	return open(pid)
}
