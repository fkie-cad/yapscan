package procIO

import (
	"io"
)

type MemoryReader interface {
	io.ReadCloser
	Reset() (MemoryReader, error)
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

func (rdr *memoryReader) Reset() (MemoryReader, error) {
	seeker, ok := rdr.impl.(io.Seeker)
	if ok {
		_, err := seeker.Seek(0, io.SeekStart)
		return rdr, err
	}
	return NewMemoryReader(rdr.impl.Process(), rdr.impl.Segment())
}
