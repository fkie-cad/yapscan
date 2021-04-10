package output

import (
	"io"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

var pgpConfig = &packet.Config{
	DefaultCipher: packet.CipherAES256,
}

func ReadPublicKeyFile(publicKeyFile string) (*openpgp.Entity, error) {
	f, err := os.Open(publicKeyFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rdr := packet.NewReader(f)
	return openpgp.ReadEntity(rdr)
}

func NewPGPEncryptor(recipient *openpgp.Entity, output io.WriteCloser) (io.WriteCloser, error) {
	in, err := openpgp.Encrypt(output, []*openpgp.Entity{recipient}, nil, nil, pgpConfig)
	if err != nil {
		return nil, err
	}
	return &decoratedWriteCloser{
		writer: in,
		base:   output,
		meta: map[string]interface{}{
			metaKeySuggestedFileExtension: ".pgp",
		},
	}, nil
}

func NewPGPSymmetricEncryptor(password string, output io.WriteCloser) (io.WriteCloser, error) {
	in, err := openpgp.SymmetricallyEncrypt(output, []byte(password), nil, pgpConfig)
	if err != nil {
		return nil, err
	}
	return &decoratedWriteCloser{
		writer: in,
		base:   output,
		meta: map[string]interface{}{
			metaKeySuggestedFileExtension: ".pgp",
		},
	}, nil
}
