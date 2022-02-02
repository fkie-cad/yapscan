package output

import (
	"io"
	"strings"

	"github.com/fkie-cad/yapscan/pgp"

	"github.com/targodan/go-errors"
	"golang.org/x/crypto/openpgp"
)

const metaKeySuggestedFileExtension = "SuggestedFileExtension"

type cascadingWriteCloser struct {
	writer io.WriteCloser
	base   io.Closer
}

func (w *cascadingWriteCloser) Write(p []byte) (n int, err error) {
	return w.writer.Write(p)
}

func (w *cascadingWriteCloser) Close() error {
	err1 := w.writer.Close()
	err2 := w.base.Close()
	return errors.NewMultiError(err1, err2)
}

type OutputDecorator struct {
	decorate               func(io.WriteCloser) (io.WriteCloser, error)
	suggestedFileExtension string
}

type WriteCloserBuilder struct {
	decorators []*OutputDecorator
}

func NewWriteCloserBuilder() *WriteCloserBuilder {
	return &WriteCloserBuilder{}
}

// Append appends a decorator. The appended decorator will be the first one to
// mutate any input.
func (b *WriteCloserBuilder) Append(decorator *OutputDecorator) *WriteCloserBuilder {
	b.decorators = append(b.decorators, decorator)
	return b
}

func (b *WriteCloserBuilder) SuggestedFileExtension() string {
	sb := &strings.Builder{}
	for i := len(b.decorators) - 1; i >= 0; i-- {
		sb.WriteString(b.decorators[i].suggestedFileExtension)
	}
	return sb.String()
}

func (b *WriteCloserBuilder) Build(finalOutput io.WriteCloser) (io.WriteCloser, error) {
	var err error
	out := finalOutput
	for _, dec := range b.decorators {
		out, err = dec.decorate(out)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func PGPEncryptionDecorator(ring openpgp.EntityList, dataIsBinary bool) *OutputDecorator {
	return &OutputDecorator{
		decorate: func(out io.WriteCloser) (io.WriteCloser, error) {
			in, err := pgp.NewPGPEncryptor(ring, dataIsBinary, out)
			return &cascadingWriteCloser{
				writer: in,
				base:   out,
			}, err
		},
		suggestedFileExtension: ".pgp",
	}
}

func PGPSymmetricEncryptionDecorator(password string, dataIsBinary bool) *OutputDecorator {
	return &OutputDecorator{
		decorate: func(out io.WriteCloser) (io.WriteCloser, error) {
			in, err := pgp.NewPGPSymmetricEncryptor(password, dataIsBinary, out)
			return &cascadingWriteCloser{
				writer: in,
				base:   out,
			}, err
		},
		suggestedFileExtension: ".pgp",
	}
}

func ZSTDCompressionDecorator() *OutputDecorator {
	return &OutputDecorator{
		decorate: func(out io.WriteCloser) (io.WriteCloser, error) {
			in := NewZSTDCompressor(out)
			return &cascadingWriteCloser{
				writer: in,
				base:   out,
			}, nil
		},
		suggestedFileExtension: ".zst",
	}
}
