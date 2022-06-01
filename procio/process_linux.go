package procio

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/fkie-cad/yapscan/arch"
	"github.com/fkie-cad/yapscan/fileio"

	"github.com/targodan/go-errors"
)

type processLinux struct {
	pid    int
	paused bool
}

func tryReadingSmaps(pid int) error {
	smaps, err := os.OpenFile(fmt.Sprintf("%s/%d/smaps", procPath, pid), os.O_RDONLY, 0444)
	if err != nil {
		return err
	}
	buf := make([]byte, 8)
	_, err = smaps.Read(buf)
	return err
}

// GetRunningPIDs returns the PIDs of all running processes.
func GetRunningPIDs() ([]int, error) {
	maps, _ := filepath.Glob(fmt.Sprintf("%s/*/smaps", procPath))

	pids := make([]int, 0, len(maps)-2)
	for _, path := range maps {
		pid, err := strconv.Atoi(strings.Split(path, "/")[2])
		if err != nil {
			// This is fine, it can happen e.g. with /proc/self/smaps
			continue
		}

		err = tryReadingSmaps(pid)
		if err == io.EOF {
			// smaps is empty, this happens sometimes
			continue
		}

		// If there are other errors, such as permission based ones we don't
		// want to handle them here. They will pop up when actually accessing the process.

		pids = append(pids, pid)
	}

	return pids, nil
}

func open(pid int) (Process, error) {
	_, err := os.Stat(fmt.Sprintf("%s/%d", procPath, pid))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("process does not exist")
	}
	if os.IsPermission(err) {
		return nil, fmt.Errorf("insufficient permissions")
	}
	if err != nil {
		return nil, fmt.Errorf("unexpected error: %w", err)
	}
	return &processLinux{pid: pid}, nil
}

func (p *processLinux) PID() int {
	return p.pid
}

func (p *processLinux) Info() (*ProcessInfo, error) {
	var err error

	info := &ProcessInfo{
		PID: p.pid,
	}

	procInfo, tmpErr := os.Stat(fmt.Sprintf("%s/%d", procPath, p.pid))
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not determine process owner, reason: %w", tmpErr))
	} else if stat, ok := procInfo.Sys().(*syscall.Stat_t); ok {
		u, tmpErr := user.LookupId(fmt.Sprintf("%v", stat.Uid))
		if tmpErr != nil {
			err = errors.NewMultiError(err, fmt.Errorf("could not determine process owner, reason: %w", tmpErr))
		}
		info.Username = u.Username
	}

	procExeLink := fmt.Sprintf("%s/%d/exe", procPath, p.pid)
	info.ExecutablePath, tmpErr = os.Readlink(procExeLink)
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not determine executable path, reason: %w", tmpErr))
	}

	// Using procExeLink here is more robust, as the OS sometimes does more magic.
	// One example is a flatpak application. The resolved path cannot be found, while the link
	// can still be resolved correctly.
	info.ExecutableMD5, info.ExecutableSHA256, tmpErr = fileio.ComputeHashes(procExeLink)
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not determine executable hashes, reason: %w", tmpErr))
	}

	exe, tmpErr := os.OpenFile(procExeLink, os.O_RDONLY, 0666)
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not determine bitness, reason: %w", tmpErr))
	}
	magic := make([]byte, 5)
	_, tmpErr = io.ReadFull(exe, magic)
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not determine bitness, reason: %w", tmpErr))
	}
	switch string(magic) {
	case "\x7FELF\x01":
		info.Bitness = arch.Bitness32Bit
	case "\x7FELF\x02":
		info.Bitness = arch.Bitness64Bit
	default:
		err = errors.NewMultiError(err, fmt.Errorf("could not determine bitness, reason: unknown magic number of executable %v", magic))
	}

	info.MemorySegments, tmpErr = p.MemorySegments()
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not query memory segments, reason: %w", tmpErr))
	}

	return info, err
}

func (p *processLinux) String() string {
	return FormatPID(p.pid)
}

func (p *processLinux) Handle() interface{} {
	return p.pid
}

func (p *processLinux) Suspend() error {
	if p.pid == os.Getpid() {
		return ErrProcIsSelf
	}
	if p.pid == os.Getppid() {
		return ErrProcIsParent
	}

	cmd := exec.Command("kill", "-STOP", strconv.Itoa(p.pid))
	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, exitErr) {
			return fmt.Errorf("could not suspend process, reason: %w", errors.New(string(exitErr.Stderr)))
		}
		return fmt.Errorf("could not suspend process, reason: %w", err)
	}
	p.paused = true
	return nil
}

func (p *processLinux) Resume() error {
	if p.paused {
		cmd := exec.Command("kill", "-CONT", strconv.Itoa(p.pid))
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("could not resume process, reason: %w", err)
		}
	}
	return nil
}

func (p *processLinux) Close() error {
	return p.Resume()
}

func (p *processLinux) MemorySegments() ([]*MemorySegmentInfo, error) {
	smaps, err := os.OpenFile(fmt.Sprintf("%s/%d/smaps", procPath, p.pid), os.O_RDONLY, 0444)
	if err != nil {
		return nil, err
	}
	defer smaps.Close()

	segments, err := parseSMEMFile(smaps)
	for _, seg := range segments {
		sanitizeMappedFile(p, seg)
	}
	return segments, err
}

func (p *processLinux) Crash(m CrashMethod) error {
	return &arch.ErrNotImplemented{"crashing processes is not implemented on linux"}
}
