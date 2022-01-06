package report

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/openpgp"

	"github.com/klauspost/compress/zstd"
)

type Reader interface {
	SetPassword(password string)
	SetKeyring(keyring openpgp.KeyRing)
	OpenMeta() (io.ReadCloser, error)
	OpenSystemInformation() (io.ReadCloser, error)
	OpenStatistics() (io.ReadCloser, error)
	OpenProcesses() (io.ReadCloser, error)
	OpenMemoryScans() (io.ReadCloser, error)
	OpenFileScans() (io.ReadCloser, error)
	io.Closer
}

type FileReader struct {
	path     string
	password string
	keyring  openpgp.KeyRing

	hasRead   bool
	lastError error

	metaBuffer        []byte
	statsBuffer       []byte
	systemInfoBuffer  []byte
	processesBuffer   []byte
	memoryScansBuffer []byte
	fileScansBuffer   []byte
}

func NewFileReader(path string) Reader {
	return &FileReader{
		path: path,
	}
}

func (rdr *FileReader) decryptIfNecessary(in io.Reader) (io.Reader, error) {
	if rdr.password == "" && rdr.keyring == nil {
		return in, nil
	}

	var prompt openpgp.PromptFunction

	if rdr.password != "" {
		prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			return []byte(rdr.password), nil
		}
	}

	msg, err := openpgp.ReadMessage(in, rdr.keyring, prompt, nil)
	if err != nil {
		return nil, err
	}

	return msg.UnverifiedBody, nil
}

func (rdr *FileReader) readAll() {
	if rdr.hasRead {
		return
	}
	defer func() {
		rdr.hasRead = true
	}()

	file, err := os.Open(rdr.path)
	if err != nil {
		rdr.lastError = err
		return
	}
	defer file.Close()

	fileRdr, err := rdr.decryptIfNecessary(file)
	if err != nil {
		rdr.lastError = err
		return
	}

	zstdRdr, err := zstd.NewReader(fileRdr)
	if err != nil {
		rdr.lastError = err
		return
	}
	defer zstdRdr.Close()

	tarRdr := tar.NewReader(zstdRdr)
	for {
		var hdr *tar.Header
		hdr, err = tarRdr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag == tar.TypeReg {
			buf := &bytes.Buffer{}
			if _, err = io.Copy(buf, tarRdr); err != nil {
				break
			}

			switch filepath.Base(hdr.Name) {
			case MetaFileName:
				rdr.metaBuffer = buf.Bytes()
			case ScanningStatisticsFileName:
				rdr.statsBuffer = buf.Bytes()
			case SystemInfoFileName:
				rdr.systemInfoBuffer = buf.Bytes()
			case ProcessesFileName:
				rdr.processesBuffer = buf.Bytes()
			case MemoryScansFileName:
				rdr.memoryScansBuffer = buf.Bytes()
			case FileScansFileName:
				rdr.fileScansBuffer = buf.Bytes()
			}
		}
	}

	if err == io.EOF {
		err = nil
	}

	rdr.lastError = err
}

func (rdr *FileReader) SetPassword(password string) {
	rdr.password = password
}

func (rdr *FileReader) SetKeyring(keyring openpgp.KeyRing) {
	rdr.keyring = keyring
}

func (rdr *FileReader) OpenMeta() (io.ReadCloser, error) {
	rdr.readAll()
	return io.NopCloser(bytes.NewReader(rdr.metaBuffer)), rdr.lastError
}

func (rdr *FileReader) OpenSystemInformation() (io.ReadCloser, error) {
	rdr.readAll()
	return io.NopCloser(bytes.NewReader(rdr.systemInfoBuffer)), rdr.lastError
}

func (rdr *FileReader) OpenStatistics() (io.ReadCloser, error) {
	rdr.readAll()
	return io.NopCloser(bytes.NewReader(rdr.statsBuffer)), rdr.lastError
}

func (rdr *FileReader) OpenProcesses() (io.ReadCloser, error) {
	rdr.readAll()
	return io.NopCloser(bytes.NewReader(rdr.processesBuffer)), rdr.lastError
}

func (rdr *FileReader) OpenMemoryScans() (io.ReadCloser, error) {
	rdr.readAll()
	return io.NopCloser(bytes.NewReader(rdr.memoryScansBuffer)), rdr.lastError
}

func (rdr *FileReader) OpenFileScans() (io.ReadCloser, error) {
	rdr.readAll()
	return io.NopCloser(bytes.NewReader(rdr.fileScansBuffer)), rdr.lastError
}

func (rdr *FileReader) Close() error {
	return nil
}

func ReadArmoredKeyring(path string) (openpgp.KeyRing, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open keyring, reason: %w", err)
	}
	defer f.Close()

	keyring, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return nil, fmt.Errorf("could not read keyring, reason: %w", err)
	}
	return keyring, nil
}
