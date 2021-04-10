package output

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/yeka/zip"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/targodan/go-errors"
)

const (
	tarDirMode  = 0777
	tarFileMode = 0666
)

type AutoArchivingWriter interface {
	io.WriteCloser

	Name() string
	Reader() (io.ReadCloser, error)
	SetNotifyChannel(c chan<- AutoArchivingWriter)
	Size() (int64, error)
}

type baseAutoArchived struct {
	writer io.WriteCloser
	name   string
	notify chan<- AutoArchivingWriter
}

func (b *baseAutoArchived) Write(p []byte) (n int, err error) {
	if b.writer == nil {
		panic("buffer was already closed")
	}
	return b.writer.Write(p)
}

func (b *baseAutoArchived) notifyAndClose(notify AutoArchivingWriter) error {
	if b.writer == nil {
		return nil
	}

	err := b.writer.Close()
	if err != nil {
		b.notify <- nil
		return err
	}

	b.writer = nil
	b.notify <- notify
	return nil
}

func (b *baseAutoArchived) Name() string {
	return b.name
}

func (b *baseAutoArchived) SetNotifyChannel(c chan<- AutoArchivingWriter) {
	b.notify = c
}

type autoArchivedBuffer struct {
	baseAutoArchived
	buffer *bytes.Buffer
	size   int64
}

func NewAutoArchivedBuffer(name string, buffer *bytes.Buffer, writer io.WriteCloser) AutoArchivingWriter {
	return &autoArchivedBuffer{
		baseAutoArchived: baseAutoArchived{
			writer: writer,
			name:   name,
			notify: nil,
		},
		buffer: buffer,
	}
}

func (b *autoArchivedBuffer) Reader() (io.ReadCloser, error) {
	rdr := io.NopCloser(b.buffer)
	b.size = int64(b.buffer.Len())
	b.buffer = nil
	return rdr, nil
}

func (b *autoArchivedBuffer) Size() (int64, error) {
	return b.size, nil
}

func (b *autoArchivedBuffer) Close() error {
	return b.notifyAndClose(b)
}

type autoArchivedFile struct {
	baseAutoArchived
	file *os.File
}

func NewAutoArchivedFile(inZipName string, file *os.File, writer io.WriteCloser) (AutoArchivingWriter, error) {
	return &autoArchivedFile{
		baseAutoArchived: baseAutoArchived{
			writer: writer,
			name:   inZipName,
			notify: nil,
		},
		file: file,
	}, nil
}

func (f *autoArchivedFile) Reader() (io.ReadCloser, error) {
	return os.OpenFile(f.file.Name(), os.O_RDONLY, 0600)
}

func (f *autoArchivedFile) Size() (int64, error) {
	stat, err := os.Stat(f.file.Name())
	if err != nil {
		return 0, nil
	}
	return stat.Size(), nil
}

func (f *autoArchivedFile) Close() error {
	f.file.Close()
	return f.notifyAndClose(f)
}

type Archiver interface {
	io.Closer
	Archive(AutoArchivingWriter) error
}

type AutoArchiver struct {
	archiver Archiver

	contents   []AutoArchivingWriter
	notifyChan <-chan AutoArchivingWriter
}

func NewAutoArchiver(archiver Archiver, contents ...AutoArchivingWriter) *AutoArchiver {
	c := make(chan AutoArchivingWriter, len(contents))

	for _, z := range contents {
		z.SetNotifyChannel(c)
	}

	return &AutoArchiver{
		archiver: archiver,

		contents:   contents,
		notifyChan: c,
	}
}

func (a *AutoArchiver) Wait(ctx context.Context) error {
	var err error
	for archivingDone := 0; archivingDone < len(a.contents); archivingDone++ {
		select {
		case completedWriter := <-a.notifyChan:
			logrus.Tracef("ARCHIVER GOT ONE: %v", completedWriter)
			if completedWriter == nil {
				// Something went wrong with closing, error is handled elsewhere
				continue
			}

			tmpErr := a.archiver.Archive(completedWriter)
			if tmpErr != nil {
				err = errors.NewMultiError(err, tmpErr)
			}

		case <-ctx.Done():
			return err
		}
	}
	return err
}

func (a *AutoArchiver) Close() error {
	return a.archiver.Close()
}

type zipArchiver struct {
	zipWriter         *zip.Writer
	outCloser         io.Closer
	compressionMethod uint16
}

func NewZipArchiver(out io.WriteCloser, compressionMethod uint16) Archiver {
	return &zipArchiver{
		zipWriter:         zip.NewWriter(out),
		outCloser:         out,
		compressionMethod: compressionMethod,
	}
}

func (z *zipArchiver) Archive(completed AutoArchivingWriter) error {
	rdr, err := completed.Reader()
	if err != nil {
		return err
	}
	defer rdr.Close()

	w, err := z.zipWriter.CreateHeader(&zip.FileHeader{
		Name:   completed.Name(),
		Method: z.compressionMethod,
	})
	if err != nil {
		return err
	}
	_, err = io.Copy(w, rdr)
	return err
}

func (z *zipArchiver) Close() error {
	err1 := z.zipWriter.Close()
	err2 := z.outCloser.Close()
	return errors.NewMultiError(err1, err2)
}

type tarArchiver struct {
	tarWriter *tar.Writer
	outCloser io.Closer

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

func (t *tarArchiver) Archive(completed AutoArchivingWriter) error {
	rdr, err := completed.Reader()
	if err != nil {
		return err
	}
	defer rdr.Close()

	path := filepath.ToSlash(completed.Name())

	err = t.ensureDirectoryExists(path)
	if err != nil {
		return err
	}

	size, err := completed.Size()
	if err != nil {
		return fmt.Errorf("could not determine size of file-to-be-archived: %w", err)
	}
	err = t.tarWriter.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg,
		Name:     path,
		Size:     size,
		Mode:     tarFileMode,
	})
	if err != nil {
		return err
	}
	_, err = io.Copy(t.tarWriter, rdr)
	return err
}

func (t *tarArchiver) Close() error {
	err1 := t.tarWriter.Close()
	err2 := t.outCloser.Close()
	return errors.NewMultiError(err1, err2)
}
