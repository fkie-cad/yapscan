package fileIO

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
)

var (
	FilesBuffer = 8
)

type nextEntry struct {
	File *File
	Err  error
}

type fsIterator struct {
	root string

	ctx    context.Context
	cancel context.CancelFunc
	closed bool

	dirs []string
	next chan *nextEntry
}

func IteratePath(path string, ctx context.Context) (*fsIterator, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() {
		return nil, errors.New("path must be a directory")
	}

	it := &fsIterator{
		root:   path,
		closed: false,
		dirs:   make([]string, 0, 16),
		next:   make(chan *nextEntry, FilesBuffer),
	}
	it.ctx, it.cancel = context.WithCancel(ctx)

	go it.dirScanner()

	return it, nil
}

func (it *fsIterator) Root() string {
	return it.root
}

func (it *fsIterator) dirScanner() {
	defer close(it.next)

	for {
		select {
		case <-it.ctx.Done():
			break
		default:
		}

		if len(it.dirs) == 0 {
			break
		}

		dir := it.dirs[0]
		it.dirs = it.dirs[1:]

		func() {
			f, err := os.Open(dir)
			if err != nil {
				it.next <- &nextEntry{
					File: &File{dir},
					Err:  err,
				}
				return
			}
			defer f.Close()

			for {
				// Assumes dirs only contains directories
				contents, err := f.Readdir(1)
				if err == io.EOF {
					break
				} else if err != nil {
					it.next <- &nextEntry{
						File: &File{dir},
						Err:  err,
					}
					return
				}

				path := filepath.Join(dir, contents[0].Name())
				if contents[0].IsDir() {
					if doScanDir(path) {
						it.dirs = append(it.dirs, path)
					}
				} else {
					it.next <- &nextEntry{
						File: &File{path},
					}
				}
			}
		}()
	}
}

func (it *fsIterator) Next() (*File, error) {
	if it.closed {
		return nil, io.EOF
	}

	next := <-it.next
	if next == nil {
		return nil, io.EOF
	}

	return next.File, next.Err
}

func (it *fsIterator) Close() error {
	if it.closed {
		return nil
	}

	it.closed = true
	defer it.cancel()

	return it.ctx.Err()
}
