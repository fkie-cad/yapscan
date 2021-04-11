package output

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/fkie-cad/yapscan/procio"
	"github.com/targodan/go-errors"
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
	// Hint returns a human readable hint about where/how dumps are stored.
	Hint() string
	io.Closer
}

// ReadableDumpStorage is a DumpStorage that can also Retrieve
// dumps after storing.
type ReadableDumpStorage interface {
	DumpStorage
	// Retrieve retrieves the dumps stored in this DumpStorage.
	Retrieve(ctx context.Context) <-chan *DumpOrError
}

type fileDump struct {
	Process  *procio.ProcessInfo
	Segment  *procio.MemorySegmentInfo
	Filename string
}

type fileDumpStorage struct {
	directory   string
	storedFiles []*fileDump
}

// NewFileDumpStorage create a new DumpStorage with a filesystem backend.
// Dumps will be stored in the given directory.
func NewFileDumpStorage(dir string) (ReadableDumpStorage, error) {
	isEmpty, err := isDirEmpty(dir)
	if err != nil {
		return nil, fmt.Errorf("could not determine if dump directory is empty, reason: %w", err)
	}
	if !isEmpty {
		return nil, errors.New("dump directory is not empty")
	}

	return &fileDumpStorage{
		directory:   dir,
		storedFiles: make([]*fileDump, 0),
	}, nil
}

func (s *fileDumpStorage) Store(dump *Dump) error {
	f, err := os.OpenFile(path.Join(s.directory, dump.Filename()), os.O_WRONLY|os.O_CREATE|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, dump.Data)
	return err
}

func (s *fileDumpStorage) Hint() string {
	return fmt.Sprintf("dumps are stored in directory \"%s\"", s.directory)
}

func (s *fileDumpStorage) Close() error {
	return nil
}

func (s *fileDumpStorage) Retrieve(ctx context.Context) <-chan *DumpOrError {
	c := make(chan *DumpOrError)

	go func() {
		defer close(c)
		for _, dump := range s.storedFiles {
			out := &DumpOrError{}

			f, err := os.OpenFile(dump.Filename, os.O_RDONLY, 0666)
			if err != nil {
				out.Err = err
			} else {
				out.Dump = &Dump{
					PID:     dump.Process.PID,
					Segment: dump.Segment,
					Data:    f,
				}
			}

			select {
			case c <- out:
			case <-ctx.Done():
				if out.Err == nil {
					// Not emitting the struct, so we need to close the file ourselves
					f.Close()
				}
				break
			}
		}
	}()

	return c
}

func isDirEmpty(dir string) (bool, error) {
	fInfo, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(dir, 0777)
			return true, nil
		}
		return false, err
	}

	if !fInfo.IsDir() {
		return false, errors.New("path is not a directory")
	}

	contents, err := filepath.Glob(path.Join(dir, "*"))
	if err != nil {
		return false, err
	}
	return len(contents) == 0, nil
}
