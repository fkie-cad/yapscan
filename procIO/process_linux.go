package procIO

import (
	"bufio"
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

	"github.com/targodan/go-errors"
)

type processLinux struct {
	pid    int
	paused bool
}

func GetRunningPIDs() ([]int, error) {
	maps, _ := filepath.Glob("/proc/*/maps")

	pids := make([]int, 0, len(maps)-2)
	for _, path := range maps {
		pid, err := strconv.Atoi(strings.Split(path, "/")[2])
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}

	return pids, nil
}

func open(pid int) (Process, error) {
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

	procInfo, tmpErr := os.Stat(fmt.Sprintf("/proc/%d", p.pid))
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not determine process owner, reason: %w", tmpErr))
	} else if stat, ok := procInfo.Sys().(*syscall.Stat_t); ok {
		u, tmpErr := user.LookupId(fmt.Sprintf("%v", stat.Uid))
		if tmpErr != nil {
			err = errors.NewMultiError(err, fmt.Errorf("could not determine process owner, reason: %w", tmpErr))
		}
		info.Username = u.Username
	}

	procExeLink := fmt.Sprintf("/proc/%d/exe", p.pid)
	info.ExecutablePath, tmpErr = os.Readlink(procExeLink)
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not determine executable path, reason: %w", tmpErr))
	}

	// Using procExeLink here is more robust, as the OS sometimes does more magic.
	// One example is a flatpak application. The resolved path cannot be found, while the link
	// can still be resolved correctly.
	info.ExecutableMD5, info.ExecutableSHA256, tmpErr = ComputeHashes(procExeLink)
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
			return errors.Errorf("could not suspend process, reason: %w", errors.New(string(exitErr.Stderr)))
		} else {
			return errors.Errorf("could not suspend process, reason: %w", err)
		}
	}
	p.paused = true
	return nil
}

func (p *processLinux) Resume() error {
	if p.paused {
		cmd := exec.Command("kill", "-CONT", strconv.Itoa(p.pid))
		err := cmd.Run()
		if err != nil {
			return errors.Errorf("could not resume process, reason: %w", err)
		}
	}
	return nil
}

func (p *processLinux) Close() error {
	return p.Resume()
}

func (p *processLinux) MemorySegments() ([]*MemorySegmentInfo, error) {
	maps, err := os.OpenFile(fmt.Sprintf("/proc/%d/maps", p.pid), os.O_RDONLY, 0444)
	if err != nil {
		return nil, err
	}
	defer maps.Close()

	segments := make([]*MemorySegmentInfo, 0)

	rdr := bufio.NewReader(maps)
	for {
		line, err := rdr.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}

		seg, err := memorySegmentFromLine(line)
		if err != nil {
			return nil, errors.Newf("could not parse memory segment info, reason: %w", err)
		}
		segments = append(segments, seg)
	}

	return segments, nil
}
