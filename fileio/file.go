package fileio

import (
	"os"
)

// File is a small abstraction layer for a file.
type File interface {
	Path() string
	Stat() (os.FileInfo, error)
	Hashes() (md5sum, sha256sum string, err error)
	EnableHashMarshalling() error
}

type OSFile struct {
	FilePath  string `json:"path"`
	MD5Sum    string `json:"md5,omitempty"`
	SHA256Sum string `json:"sha256,omitempty"`
}

func NewFile(path string) File {
	return &OSFile{FilePath: path}
}

func CloneFile(f File) File {
	if f == nil {
		return nil
	}

	osFile, ok := f.(*OSFile)
	if ok {
		return &OSFile{
			FilePath:  osFile.FilePath,
			MD5Sum:    osFile.MD5Sum,
			SHA256Sum: osFile.SHA256Sum,
		}
	}
	return NewFile(f.Path())
}

// Path returns the path of the file.
func (f *OSFile) Path() string {
	return f.FilePath
}

// Stat returns the os.FileInfo associated with the file.
func (f *OSFile) Stat() (os.FileInfo, error) {
	return os.Stat(f.FilePath)
}

// Hashes returns the computed hashes of the file.
func (f *OSFile) Hashes() (md5sum, sha256sum string, err error) {
	return ComputeHashes(f.FilePath)
}

// EnableHashMarshalling computes the hashes and stores
// them for later marshalling.
func (f *OSFile) EnableHashMarshalling() (err error) {
	f.MD5Sum, f.SHA256Sum, err = f.Hashes()
	return
}
