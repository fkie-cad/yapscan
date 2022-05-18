package report

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/fkie-cad/yapscan/pgp"

	"golang.org/x/crypto/openpgp"

	"github.com/klauspost/compress/zstd"
)

type Reader interface {
	SetPassword(password string)
	SetKeyring(keyring openpgp.EntityList)
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
	keyring  openpgp.EntityList

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
	if rdr.keyring != nil {
		return pgp.NewPGPDecryptor(rdr.keyring, rdr.password, in)
	}
	if rdr.password != "" {
		return pgp.NewPGPSymmetricDecryptor(rdr.password, in)
	}
	return in, nil
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

func (rdr *FileReader) SetKeyring(keyring openpgp.EntityList) {
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

type ReaderFactory struct {
	keyring  openpgp.EntityList
	password string
}

func NewReaderFactory() *ReaderFactory {
	return &ReaderFactory{}
}

func (f *ReaderFactory) SetPassword(password string) {
	f.password = password
}

func (f *ReaderFactory) SetKeyring(keyring openpgp.EntityList) {
	f.keyring = keyring
}

func (f *ReaderFactory) OpenFile(path string) Reader {
	rdr := NewFileReader(path)
	if f.password != "" {
		rdr.SetPassword(f.password)
	}
	if f.keyring != nil {
		rdr.SetKeyring(f.keyring)
	}
	return rdr
}
