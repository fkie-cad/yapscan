package output

import (
	"context"
	"fmt"
	"io"

	"github.com/fkie-cad/yapscan/procio"
)

// Dump contains the dump of a memory segment.
type Dump struct {
	PID     int
	Segment *procio.MemorySegmentInfo
	Data    io.ReadCloser
}

// Filename returns a filename with the PID of the process
// and the address of the Segment of the dump.
func (d *Dump) Filename() string {
	return fmt.Sprintf("%d_0x%s.bin", d.PID, d.Segment.String())
}

// DumpOrError contains either a Dump or an Err.
type DumpOrError struct {
	Dump *Dump
	Err  error
}

// DumpStorage provides capability to store dumps.
type DumpStorage interface {
	// Store stores a Dump.
	Store(dump *Dump) error
	io.Closer
}

// ReadableDumpStorage is a DumpStorage that can also Retrieve
// dumps after storing.
type ReadableDumpStorage interface {
	DumpStorage
	// Retrieve retrieves the dumps stored in this DumpStorage.
	Retrieve(ctx context.Context) <-chan *DumpOrError
}

// ArchiveDumpStorage stores dumps using an Archiver.
type ArchiveDumpStorage struct {
	archiver Archiver

	// The prefix of filenames created in the Archiver.
	FilePrefix string
}

// NewArchiveDumpStorage creates a new ArchiveDumpStorage with an Archiver backend.
func NewArchiveDumpStorage(archiver Archiver) *ArchiveDumpStorage {
	return &ArchiveDumpStorage{
		archiver:   archiver,
		FilePrefix: "",
	}
}

// Store stores a new dump.
// Depending on the underlying Archiver, this must not be called in parallel.
func (s *ArchiveDumpStorage) Store(dump *Dump) error {
	f, err := s.archiver.Create(s.FilePrefix + dump.Filename())
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, dump.Data)
	return err
}

func (s *ArchiveDumpStorage) Close() error {
	return s.archiver.Close()
}
