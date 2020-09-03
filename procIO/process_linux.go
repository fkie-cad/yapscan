package procIO

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/targodan/go-errors"
)

type processLinux struct {
	pid int
}

func open(pid int) (Process, error) {
	return &processLinux{pid: pid}, nil
}

func (p *processLinux) PID() int {
	return p.pid
}

func (p *processLinux) String() string {
	return FormatPID(p.pid)
}

func (p *processLinux) Handle() interface{} {
	return p.pid
}

func (p *processLinux) Close() error {
	return nil
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
