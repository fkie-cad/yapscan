package procio

import (
	"io"
)

type MemoryReader interface {
	io.ReadCloser
	io.Seeker
}

type MemoryReaderFactory interface {
	NewMemoryReader(proc Process, seg *MemorySegmentInfo) (MemoryReader, error)
}

type DefaultMemoryReaderFactory struct{}

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
