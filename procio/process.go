package procio

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/fkie-cad/yapscan/arch"
)

// ErrProcIsSelf is returned when trying to suspend the current process.
var ErrProcIsSelf = errors.New("not supported on self")

// ErrProcIsParent is returned when trying to suspend the immediate parent process.
// Reason for this is the assumption that the parent process always is some form of
// console, which needs to be running in order to handle IO.
var ErrProcIsParent = errors.New("not supported on parent")

// ProcessInfo represents information about a Process.
type ProcessInfo struct {
	PID              int                  `json:"pid"`
	Bitness          arch.Bitness         `json:"bitness"`
	ExecutablePath   string               `json:"executablePath"`
	ExecutableMD5    string               `json:"executableMD5"`
	ExecutableSHA256 string               `json:"executableSHA256"`
	Username         string               `json:"username"`
	MemorySegments   []*MemorySegmentInfo `json:"memorySegments"`
}

// Process provides capability to interact with or retrieve information about
// other processes.
type Process interface {
	io.Closer
	fmt.Stringer

	PID() int
	Info() (*ProcessInfo, error)
	Handle() interface{}
	MemorySegments() ([]*MemorySegmentInfo, error)
	Suspend() error
	Resume() error
	Crash(CrashMethod) error
}

// CachingProcess is a Process that caches *ProcessInfo and
// *MemorySegmentInfo.
// This cache will only be updated after InvalidateCache was called.
type CachingProcess interface {
	Process
	InvalidateCache()
}

// OpenProcess opens another process.
func OpenProcess(pid int) (CachingProcess, error) {
	proc, err := open(pid)
	return &cachingProcess{
		proc:         proc,
		infoMutex:    &sync.RWMutex{},
		segmentMutex: &sync.RWMutex{},
	}, err
}

type cachingProcess struct {
	proc         Process
	segmentCache []*MemorySegmentInfo
	infoCache    *ProcessInfo
	infoMutex    *sync.RWMutex
	segmentMutex *sync.RWMutex
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
	info := func() *ProcessInfo {
		c.infoMutex.RLock()
		defer c.infoMutex.RUnlock()

		return c.infoCache
	}()

	var err error
	if info == nil {
		info, err = func() (*ProcessInfo, error) {
			c.infoMutex.Lock()
			defer c.infoMutex.Unlock()

			c.infoCache, err = c.proc.Info()
			return c.infoCache, err
		}()
	}
	return info, err
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
	segments := func() []*MemorySegmentInfo {
		c.segmentMutex.RLock()
		defer c.segmentMutex.RUnlock()

		return c.segmentCache
	}()

	var err error
	if segments == nil {
		segments, err = func() ([]*MemorySegmentInfo, error) {
			c.segmentMutex.Lock()
			defer c.segmentMutex.Unlock()

			c.segmentCache, err = c.proc.MemorySegments()
			return c.segmentCache, err
		}()
	}

	return segments, err
}

func (c *cachingProcess) InvalidateCache() {
	c.segmentCache = nil
	c.infoCache = nil
}

// ComputeHashes computes the md5 and sha256 hashes of a given file.
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

func (c *cachingProcess) Crash(m CrashMethod) error {
	return c.proc.Crash(m)
}
