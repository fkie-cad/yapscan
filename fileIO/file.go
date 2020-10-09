package fileIO

import "os"

type File struct {
	path string
}

func (f *File) Path() string {
	return f.path
}

func (f *File) Stat() (os.FileInfo, error) {
	return os.Stat(f.path)
}
