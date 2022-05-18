package pgp

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

func tryReadKeyRing(filepath string) (openpgp.EntityList, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return openpgp.ReadKeyRing(f)
}

func tryReadArmoredKeyRing(filepath string) (openpgp.EntityList, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return openpgp.ReadArmoredKeyRing(f)
}

func ReadKeyRing(filepath string) (openpgp.EntityList, error) {
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

func NewPGPEncryptor(ring openpgp.EntityList, isBinary bool, output io.Writer) (io.WriteCloser, error) {
	return openpgp.Encrypt(output, ring, nil, &openpgp.FileHints{IsBinary: isBinary}, pgpConfig)
}

func NewPGPSymmetricEncryptor(password string, isBinary bool, output io.Writer) (io.WriteCloser, error) {
	return openpgp.SymmetricallyEncrypt(output, []byte(password), &openpgp.FileHints{IsBinary: isBinary}, pgpConfig)
}

func NewPGPDecryptor(ring openpgp.EntityList, keyPassword string, input io.Reader) (io.Reader, error) {
	var prompt openpgp.PromptFunction

	if keyPassword != "" {
		prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			if symmetric {
				return nil, errors.Newf("expected asymmetric encryption but message was symmetrically encrypted")
			}
			return []byte(keyPassword), nil
		}
	}

	msg, err := openpgp.ReadMessage(input, ring, prompt, pgpConfig)
	if err != nil {
		return nil, err
	}

	return msg.UnverifiedBody, nil
}

type emptyKeyring struct{}

func (r emptyKeyring) KeysById(id uint64) []openpgp.Key {
	return make([]openpgp.Key, 0)
}

func (r emptyKeyring) KeysByIdUsage(id uint64, requiredUsage byte) []openpgp.Key {
	return make([]openpgp.Key, 0)
}

func (r emptyKeyring) DecryptionKeys() []openpgp.Key {
	return make([]openpgp.Key, 0)
}

func NewPGPSymmetricDecryptor(password string, input io.Reader) (io.Reader, error) {
	var prompt openpgp.PromptFunction

	prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if !symmetric {
			return nil, errors.Newf("expected symmetric encryption but message was asymmetrically encrypted")
		}
		return []byte(password), nil
	}

	msg, err := openpgp.ReadMessage(input, emptyKeyring{}, prompt, pgpConfig)
	if err != nil {
		return nil, err
	}

	return msg.UnverifiedBody, nil
}
