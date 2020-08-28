package procIO

import "io"

type Process interface {
	io.Closer

	Handle() interface{}
	MemorySegments() ([]*MemorySegmentInfo, error)
}

func OpenProcess(pid int) (Process, error) {
	return open(pid)
}
