package procIO

type Process interface {
	Handle() interface{}
	MemorySegments() ([]*MemorySegmentInfo, error)
}

func Open(pid int) (Process, error) {
	return open(pid)
}
