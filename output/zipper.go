package output

import (
	"bytes"
	"io"

	"github.com/yeka/zip"

	"github.com/targodan/go-errors"
)

type AutoZippedWriter interface {
	io.WriteCloser

	Name() string
	Reader() (io.ReadCloser, error)
	SetNotifyChannel(c chan<- AutoZippedWriter)
}

type baseAutoZipped struct {
	writer io.WriteCloser
	name   string
	notify chan<- AutoZippedWriter
}

func (b *baseAutoZipped) Write(p []byte) (n int, err error) {
	if b.writer == nil {
		panic("buffer was already closed")
	}
	return b.writer.Write(p)
}

func (b *baseAutoZipped) notifyAndClose(notify AutoZippedWriter) error {
	err := b.writer.Close()
	if err != nil {
		b.notify <- nil
		return err
	}

	b.writer = nil
	b.notify <- notify
	return nil
}

func (b *baseAutoZipped) Name() string {
	return b.name
}

func (b *baseAutoZipped) SetNotifyChannel(c chan<- AutoZippedWriter) {
	b.notify = c
}

type autoZippedBuffer struct {
	baseAutoZipped
	buffer *bytes.Buffer
}

func NewAutoZippedBuffer(name string) io.WriteCloser {
	buffer := &bytes.Buffer{}
	return &autoZippedBuffer{
		baseAutoZipped: baseAutoZipped{
			writer: &nopWriteCloser{buffer},
			name:   name,
			notify: nil,
		},
		buffer: buffer,
	}
}

func (b *autoZippedBuffer) Reader() (io.ReadCloser, error) {
	rdr := io.NopCloser(b.buffer)
	b.buffer = nil
	return rdr, nil
}

func (b *autoZippedBuffer) Close() error {
	return b.notifyAndClose(b)
}

type autoZippedFile struct {
	baseAutoZipped
	filePath string
}

func NewAutoZippedFile(filePath, inZipName string) (io.WriteCloser, error) {
	// TODO: open file and so on
	return &autoZippedFile{
		baseAutoZipped: baseAutoZipped{
			writer: file,
			name:   inZipName,
			notify: nil,
		},
	}, nil
}

func (b *autoZippedFile) Reader() (io.ReadCloser, error) {
	rdr := io.NopCloser(b.buffer)
	b.buffer = nil
	return rdr, nil
}

func (b *autoZippedFile) Close() error {
	return b.notifyAndClose(b)
}

type Zipper struct {
	zipWriter *zip.Writer
	outCloser io.Closer

	contents   []AutoZippedWriter
	notifyChan <-chan AutoZippedWriter
}

func NewZipper(out io.WriteCloser, contents ...AutoZippedWriter) *Zipper {
	c := make(chan AutoZippedWriter, len(contents))

	for _, z := range contents {
		z.SetNotifyChannel(c)
	}

	zipper := &Zipper{
		zipWriter: zip.NewWriter(out),

		contents:   contents,
		notifyChan: c,
	}
	return zipper
}

func (z *Zipper) Wait() error {
	var err error
	for zippingDone := 0; zippingDone < len(z.contents); zippingDone++ {
		select {
		case completedWriter := <-z.notifyChan:
			if completedWriter == nil {
				// Something went wrong with closing, error is handled elsewhere
				continue
			}

			tmpErr := z.zip(completedWriter)
			if tmpErr != nil {
				err = errors.NewMultiError(err, tmpErr)
			}

			// TODO: Probably want a context here as well
		}
	}
	return err
}

func (z *Zipper) Close() error {
	return z.zipWriter.Close()
}

func (z *Zipper) zip(completed AutoZippedWriter) error {
	rdr, err := completed.Reader()
	if err != nil {
		return err
	}
	defer rdr.Close()

	w, err := z.zipWriter.Create(completed.Name())
	if err != nil {
		return err
	}
	_, err = io.Copy(w, rdr)
	return err
}

type nopWriteCloser struct {
	w io.Writer
}

func (w *nopWriteCloser) Write(p []byte) (n int, err error) {
	return w.w.Write(p)
}

func (w *nopWriteCloser) Close() error {
	return nil
}
