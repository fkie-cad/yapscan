package output

import (
	"bytes"
	"github.com/targodan/go-errors"
	"golang.org/x/crypto/openpgp"
	"io"
	"os"
)

type decoratedWriteCloser struct {
	writer io.WriteCloser
	base   io.Closer
	meta   map[string]interface{}
}

func (w *decoratedWriteCloser) Write(p []byte) (n int, err error) {
	return w.writer.Write(p)
}

func (w *decoratedWriteCloser) Close() error {
	err := w.writer.Close()
	return errors.NewMultiError(err, w.base.Close())
}

func (w *decoratedWriteCloser) GetMeta(key string) interface{} {
	if w.meta == nil {
		return nil
	}
	value, ok := w.meta[key]
	if !ok {
		return nil
	}
	return value
}

func (w *decoratedWriteCloser) FindMeta(key string) []interface{} {
	return w.findMeta(key, make([]interface{}, 0))
}

func (w *decoratedWriteCloser) findMeta(key string, collected []interface{}) []interface{} {
	value := w.GetMeta(key)
	if value != nil {
		collected = append(collected, value)
	}

	underlying, ok := w.base.(*decoratedWriteCloser)
	if !ok {
		return collected
	}
	return underlying.findMeta(key, collected)
}

func (w *decoratedWriteCloser) Unwrap() interface{} {
	underlying, ok := w.base.(*decoratedWriteCloser)
	if !ok {
		return w.base
	}
	return underlying.Unwrap()
}

type OutputDecorator func(io.WriteCloser) (io.WriteCloser, error)

func PGPEncryptionDecorator(recipient *openpgp.Entity) OutputDecorator {
	return func(out io.WriteCloser) (io.WriteCloser, error) {
		return NewPGPEncryptor(recipient, out)
	}
}

func PGPSymmetricEncryptionDecorator(password string) OutputDecorator {
	return func(out io.WriteCloser) (io.WriteCloser, error) {
		return NewPGPSymmetricEncryptor(password, out)
	}
}

func ZSTDCompressionDecorator() OutputDecorator {
	return func(out io.WriteCloser) (io.WriteCloser, error) {
		return NewZSTDCompressor(out), nil
	}
}

func unwrapDecorated(v interface{}) interface{} {
	nopWC, ok := v.(*nopWriteCloser)
	if ok {
		return unwrapDecorated(nopWC.w)
	}

	decorated, ok := v.(*decoratedWriteCloser)
	if !ok {
		return v
	}
	base := decorated.Unwrap()

	return unwrapDecorated(base)
}

func NewAutoArchivedFromDecorated(name string, decorated io.WriteCloser) (AutoArchivingWriter, error) {
	bufferOrFile := unwrapDecorated(decorated)
	buffer, ok := bufferOrFile.(*bytes.Buffer)
	if ok {
		return NewAutoArchivedBuffer(name, buffer, decorated), nil
	}
	file, ok := bufferOrFile.(*os.File)
	if ok {
		return NewAutoArchivedFile(name, file, decorated)
	}
	panic("could not decorate unexpected type of WriteCloser with AutoArchiving")
}

const metaKeySuggestedFileExtension = "SuggestedFileExtension"

func suggestedFileExtension(v interface{}) string {
	decorated, ok := v.(*decoratedWriteCloser)
	if !ok {
		return ""
	}

	ext := ""

	extensions := decorated.FindMeta(metaKeySuggestedFileExtension)
	for _, v := range extensions {
		ext += v.(string)
	}

	return ext
}
