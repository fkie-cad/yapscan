package procio

import (
	"io"
)

// MemoryReader provides capabilities to read and seek through
// another processes memory.
type MemoryReader interface {
	io.ReadCloser
	io.Seeker
}

// MemoryReaderFactory is a factory for MemoryReader.
type MemoryReaderFactory interface {
	NewMemoryReader(proc Process, seg *MemorySegmentInfo) (MemoryReader, error)
}

// DefaultMemoryReaderFactory is the default MemoryReaderFactory.
type DefaultMemoryReaderFactory struct{}

// NewMemoryReader calls NewMemoryReader.
func (f *DefaultMemoryReaderFactory) NewMemoryReader(proc Process, seg *MemorySegmentInfo) (MemoryReader, error) {
	return NewMemoryReader(proc, seg)
}

type memoryReaderImpl interface {
	io.ReadCloser
	io.Seeker
	Process() Process
	Segment() *MemorySegmentInfo
}

type memoryReader struct {
	impl memoryReaderImpl
}

// NewMemoryReader creates a new MemoryReader to read the given
// segment of the given Process.
func NewMemoryReader(proc Process, seg *MemorySegmentInfo) (MemoryReader, error) {
	impl, err := newMemoryReader(proc, seg)
	return &memoryReader{
		impl: impl,
	}, err
}

func (rdr *memoryReader) Read(p []byte) (n int, err error) {
	return rdr.impl.Read(p)
}

func (rdr *memoryReader) Close() error {
	return rdr.impl.Close()
}

func (rdr *memoryReader) Seek(offset int64, whence int) (int64, error) {
	return rdr.impl.Seek(offset, whence)
}
