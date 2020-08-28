package yapscan

import (
	"io/ioutil"

	"fraunhofer/fkie/yapscan/procIO"

	"github.com/hillu/go-yara/v4"
	"github.com/targodan/go-errors"
)

type MemorySegmentFilter func(info *procIO.MemorySegmentInfo) bool

type MemoryScanner struct {
	proc    procIO.Process
	filter  MemorySegmentFilter
	scanner *yara.Scanner
}

func NewMemoryScanner(pid int, filter MemorySegmentFilter, scanner *yara.Scanner) (*MemoryScanner, error) {
	proc, err := procIO.OpenProcess(pid)
	if err != nil {
		return nil, err
	}

	return &MemoryScanner{
		proc:    proc,
		filter:  filter,
		scanner: scanner,
	}, nil
}

func (s *MemoryScanner) Scan() error {
	segments, err := s.proc.MemorySegments()
	if err != nil {
		return err
	}
	err = nil
	for _, segment := range segments {
		err = errors.NewMultiError(s.scanSegment(segment))
		for _, subSegment := range segment.SubSegments {
			err = errors.NewMultiError(s.scanSegment(subSegment))
		}
	}
	return err
}

func (s *MemoryScanner) scanSegment(seg *procIO.MemorySegmentInfo) error {
	if !s.filter(seg) {
		return nil
	}

	rdr := procIO.NewMemoryReader(s.proc, seg)
	defer rdr.Close()

	data, err := ioutil.ReadAll(rdr)
	if err != nil {
		return err
	}

	return s.scanner.ScanMem(data)
}
