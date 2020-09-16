package procIO

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

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
	return &ProcessInfo{
		PID: p.pid,
	}, nil
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
