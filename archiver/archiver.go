package archiver

import (
	"archive/tar"
	"bytes"
	"io"
	"path/filepath"
	"strings"

	"github.com/yeka/zip"

	"github.com/targodan/go-errors"
)

const (
	tarDirMode  = 0777
	tarFileMode = 0666
)

type Archiver interface {
	Create(name string) (io.WriteCloser, error)
	io.Closer
}

type zipArchiver struct {
	zipWriter         *zip.Writer
	compressionMethod uint16
	hasOpenWriter     bool
}

func NewZipArchiver(out io.Writer, compressionMethod uint16) Archiver {
	return &zipArchiver{
		zipWriter:         zip.NewWriter(out),
		compressionMethod: compressionMethod,
	}
}

func (z *zipArchiver) Create(name string) (io.WriteCloser, error) {
	if z.hasOpenWriter {
		return nil, errors.New("cannot create a new entry in archive before last writer was closed")
	}

	w, err := z.zipWriter.CreateHeader(&zip.FileHeader{
		Name:   filepath.ToSlash(name),
		Method: z.compressionMethod,
	})
	if err != nil {
		return nil, err
	}

	z.hasOpenWriter = true

	return &callbackWriteCloser{
		writer: w,
		close: func() error {
			z.hasOpenWriter = false
			return nil
		},
	}, nil
}

func (z *zipArchiver) Close() error {
	if z.hasOpenWriter {
		return errors.New("cannot close archiver before all Created writers have been closed")
	}

	return z.zipWriter.Close()
}

type tarArchiver struct {
	tarWriter  *tar.Writer
	outCloser  io.Closer
	lastBuffer *bytes.Buffer

	createdDirectories map[string]bool
}

func NewTarArchiver(out io.WriteCloser) Archiver {
	return &tarArchiver{
		tarWriter: tar.NewWriter(out),
		outCloser: out,

		createdDirectories: make(map[string]bool),
	}
}

func (t *tarArchiver) directoryWasCreated(path string) bool {
	_, ok := t.createdDirectories[path]
	return ok
}

func (t *tarArchiver) ensureDirectoryExists(path string) error {
	if path == "" || t.directoryWasCreated(path) {
		return nil
	}

	paths := strings.Split(path, "/")
	// Last element is filename, don't create that
	if len(paths) == 1 {
		return nil
	}
	paths = paths[0 : len(paths)-1]
	return t.ensureDirectoryExistsRecursive(paths[0], paths[1:])
}

func (t *tarArchiver) ensureDirectoryExistsRecursive(path string, subPaths []string) error {
	if !t.directoryWasCreated(path) {
		err := t.createDirectory(path)
		if err != nil {
			return err
		}
	}
	if len(subPaths) == 0 {
		return nil
	}
	return t.ensureDirectoryExistsRecursive(path+"/"+subPaths[0], subPaths[1:])
}

func (t *tarArchiver) createDirectory(path string) error {
	if t.lastBuffer != nil {
		return errors.New("cannot create a new entry in archive before last writer was closed")
	}
	err := t.tarWriter.WriteHeader(&tar.Header{
		Typeflag: tar.TypeDir,
		Name:     path,
		Mode:     tarDirMode,
	})
	if err != nil {
		t.createdDirectories[path] = true
	}
	return err
}

func (t *tarArchiver) Create(name string) (io.WriteCloser, error) {
	if t.lastBuffer != nil {
		return nil, errors.New("cannot create a new entry in archive before last writer was closed")
	}

	name = filepath.ToSlash(name)

	err := t.ensureDirectoryExists(name)
	if err != nil {
		return nil, err
	}

	t.lastBuffer = &bytes.Buffer{}

	return &callbackWriteCloser{
		writer: t.lastBuffer,
		close: func() error {
			err := t.tarWriter.WriteHeader(&tar.Header{
				Typeflag: tar.TypeReg,
				Name:     name,
				Size:     int64(t.lastBuffer.Len()),
				Mode:     tarFileMode,
			})
			if err != nil {
				return err
			}
			_, err = io.Copy(t.tarWriter, t.lastBuffer)
			t.lastBuffer = nil
			return err
		},
	}, nil
}

func (t *tarArchiver) Close() error {
	if t.lastBuffer != nil {
		return errors.New("cannot close archiver before all Created writers have been closed")
	}
	err1 := t.tarWriter.Close()
	err2 := t.outCloser.Close()
	return errors.NewMultiError(err1, err2)
}
