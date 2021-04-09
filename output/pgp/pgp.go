package pgp

import (
	"io"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func ReadPublicKeyFile(publicKeyFile string) (*openpgp.Entity, error) {
	f, err := os.Open(publicKeyFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rdr := packet.NewReader(f)
	return openpgp.ReadEntity(rdr)
}

type writeCloser struct {
	writer io.Writer
	closer io.Closer
}

func (w *writeCloser) Write(p []byte) (n int, err error) {
	return w.writer.Write(p)
}

func (w *writeCloser) Close() error {
	return w.closer.Close()
}

func NewEncryptor(recipient *openpgp.Entity, output io.WriteCloser) (io.WriteCloser, error) {
	in, err := openpgp.Encrypt(output, []*openpgp.Entity{recipient}, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	return &writeCloser{
		writer: in,
		closer: output,
	}, nil
}
