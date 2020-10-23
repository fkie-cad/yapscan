package fileIO

import "os"

type File interface {
	Path() string
	Stat() (os.FileInfo, error)
}

type file struct {
	path string
}

func (f *file) Path() string {
	return f.path
}

func (f *file) Stat() (os.FileInfo, error) {
	return os.Stat(f.path)
}
