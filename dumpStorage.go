package yapscan

import (
	"context"
	"fmt"
	"fraunhofer/fkie/yapscan/procIO"
	"io"
	"os"
	"path"

	"github.com/targodan/go-errors"
)

type Dump struct {
	Process *procIO.ProcessInfo
	Segment *procIO.MemorySegmentInfo
	Data    io.ReadCloser
}

func (d *Dump) Filename() string {
	return fmt.Sprintf("%d_0x%s.bin", d.Process.PID, d.Segment.String())
}

type DumpOrError struct {
	Dump *Dump
	Err  error
}

type DumpStorage interface {
	Store(dump *Dump) error
	Hint() string
	io.Closer
}

type ReadableDumpStorage interface {
	DumpStorage
	Retrieve(ctx context.Context) <-chan *DumpOrError
}

type fileDump struct {
	Process  *procIO.ProcessInfo
	Segment  *procIO.MemorySegmentInfo
	Filename string
}

type fileDumpStorage struct {
	directory   string
	storedFiles []*fileDump
}

func NewFileDumpStorage(dir string) (ReadableDumpStorage, error) {
	isEmpty, err := isDirEmpty(dir)
	if err != nil {
		return nil, errors.Errorf("could not determine if dump directory is empty, reason: %w", err)
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
					Process: dump.Process,
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
