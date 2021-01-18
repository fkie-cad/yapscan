package procio

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/fkie-cad/yapscan/arch"
)

var ErrProcIsSelf = errors.New("not supported on self")
var ErrProcIsParent = errors.New("not supported on parent")

type ProcessInfo struct {
	PID              int                  `json:"pid"`
	Bitness          arch.Bitness         `json:"bitness"`
	ExecutablePath   string               `json:"executablePath"`
	ExecutableMD5    string               `json:"executableMD5"`
	ExecutableSHA256 string               `json:"executableSHA256"`
	Username         string               `json:"username"`
	MemorySegments   []*MemorySegmentInfo `json:"memorySegments"`
}

type Process interface {
	io.Closer
	fmt.Stringer

	PID() int
	Info() (*ProcessInfo, error)
	Handle() interface{}
	MemorySegments() ([]*MemorySegmentInfo, error)
	Suspend() error
	Resume() error
}

type CachingProcess interface {
	Process
	InvalidateCache()
}

func OpenProcess(pid int) (CachingProcess, error) {
	proc, err := open(pid)
	return &cachingProcess{
		proc: proc,
	}, err
}

type cachingProcess struct {
	proc         Process
	segmentCache []*MemorySegmentInfo
	infoCache    *ProcessInfo
}

func (c *cachingProcess) Close() error {
	return c.proc.Close()
}

func (c *cachingProcess) String() string {
	return c.proc.String()
}

func (c *cachingProcess) PID() int {
	return c.proc.PID()
}

func (c *cachingProcess) Info() (*ProcessInfo, error) {
	var err error
	if c.infoCache == nil {
		c.infoCache, err = c.proc.Info()
	}
	return c.infoCache, err
}

func (c *cachingProcess) Handle() interface{} {
	return c.proc.Handle()
}

func (c *cachingProcess) Suspend() error {
	return c.proc.Suspend()
}

func (c *cachingProcess) Resume() error {
	return c.proc.Resume()
}

func (c *cachingProcess) MemorySegments() ([]*MemorySegmentInfo, error) {
	var err error
	if c.segmentCache == nil {
		c.segmentCache, err = c.proc.MemorySegments()
	}
	return c.segmentCache, err
}

func (c *cachingProcess) InvalidateCache() {
	c.segmentCache = nil
	c.infoCache = nil
}

func ComputeHashes(file string) (md5sum, sha256sum string, err error) {
	var f *os.File
	f, err = os.OpenFile(file, os.O_RDONLY, 0666)
	if err != nil {
		return
	}
	defer f.Close()

	h5 := md5.New()
	h256 := sha256.New()

	teeH5 := io.TeeReader(f, h5)
	_, err = io.Copy(h256, teeH5)
	if err != nil {
		return
	}

	md5sum = hex.EncodeToString(h5.Sum(nil))
	sha256sum = hex.EncodeToString(h256.Sum(nil))

	return
}
