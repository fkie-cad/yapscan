package fileio

import "os"

// File is a small abstraction layer for a file.
type File interface {
	Path() string
	Stat() (os.FileInfo, error)
}

type file struct {
	path string
}

// Path returns the path of the file.
func (f *file) Path() string {
	return f.path
}

// Stat returns the os.FileInfo associated with the file.
func (f *file) Stat() (os.FileInfo, error) {
	return os.Stat(f.path)
}
