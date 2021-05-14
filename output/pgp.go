package output

import (
	"io"
	"os"

	"github.com/targodan/go-errors"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var pgpConfig = &packet.Config{
	DefaultCipher: packet.CipherAES256,
}

func tryReadKeyRing(filepath string) ([]*openpgp.Entity, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return openpgp.ReadKeyRing(f)
}

func tryReadArmoredKeyRing(filepath string) ([]*openpgp.Entity, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return openpgp.ReadArmoredKeyRing(f)
}

func ReadKeyRing(filepath string) ([]*openpgp.Entity, error) {
	ring, err1 := tryReadArmoredKeyRing(filepath)
	if err1 == nil {
		return ring, nil
	}
	ring, err2 := tryReadKeyRing(filepath)
	if err2 == nil {
		return ring, nil
	}
	return nil, errors.NewMultiError(err1, err2)
}

func NewPGPEncryptor(ring []*openpgp.Entity, isBinary bool, output io.Writer) (io.WriteCloser, error) {
	return openpgp.Encrypt(output, ring, nil, &openpgp.FileHints{IsBinary: isBinary}, pgpConfig)
}

func NewPGPSymmetricEncryptor(password string, isBinary bool, output io.Writer) (io.WriteCloser, error) {
	return openpgp.SymmetricallyEncrypt(output, []byte(password), &openpgp.FileHints{IsBinary: isBinary}, pgpConfig)
}
