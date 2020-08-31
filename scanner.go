package yapscan

import (
	"io/ioutil"

	"github.com/sirupsen/logrus"

	"fraunhofer/fkie/yapscan/procIO"

	"github.com/hillu/go-yara/v4"
	"github.com/targodan/go-errors"
)

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
		logrus.WithFields(logrus.Fields{
			"process":       s.proc,
			logrus.ErrorKey: err,
		}).Error("Could not retrieve memory segments for process.")
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
	match := s.filter.Filter(seg)
	if !match.Result {
		logrus.WithFields(logrus.Fields{
			"segment": seg,
			"reason":  match.Reason,
		}).Debug("Memory segment skipped.")
		return nil
	}

	logrus.WithFields(logrus.Fields{
		"segment": seg,
	}).Info("Scanning memory segment.")

	rdr := procIO.NewMemoryReader(s.proc, seg)
	defer rdr.Close()

	data, err := ioutil.ReadAll(rdr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"process":       s.proc,
			"segment":       seg,
			logrus.ErrorKey: err,
		}).Info("Could not read memory from process.")
		return err
	}

	return s.scanner.ScanMem(data)
}
