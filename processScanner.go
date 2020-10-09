package yapscan

import (
	"io/ioutil"
	"os"

	"github.com/hillu/go-yara/v4"

	"github.com/sirupsen/logrus"

	"fraunhofer/fkie/yapscan/procIO"

	"github.com/targodan/go-errors"
)

type MemoryScanner interface {
	ScanMem(buf []byte) (results []yara.MatchRule, err error)
}

type ProcessScanner struct {
	proc    procIO.Process
	filter  MemorySegmentFilter
	scanner MemoryScanner
}

func NewProcessScanner(proc procIO.Process, filter MemorySegmentFilter, scanner MemoryScanner) *ProcessScanner {
	return &ProcessScanner{
		proc:    proc,
		filter:  filter,
		scanner: scanner,
	}
}

var ErrSkipped = errors.New("skipped memory segment")

type MemoryScanProgress struct {
	Process       procIO.Process
	MemorySegment *procIO.MemorySegmentInfo
	Dump          []byte
	Matches       []yara.MatchRule
	Error         error
}

func (s *ProcessScanner) Scan() (<-chan *MemoryScanProgress, error) {
	segments, err := s.proc.MemorySegments()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"process":       s.proc,
			logrus.ErrorKey: err,
		}).Error("Could not retrieve memory segments for process.")
		return nil, err
	}

	progress := make(chan *MemoryScanProgress)

	go func() {
		defer close(progress)
		for _, segment := range segments {
			if len(segment.SubSegments) == 0 {
				// Only scan leaf segments
				matches, data, err := s.scanSegment(segment)
				progress <- &MemoryScanProgress{
					Process:       s.proc,
					MemorySegment: segment,
					Dump:          data,
					Matches:       matches,
					Error:         err,
				}
				if errors.Is(err, os.ErrPermission) {
					return
				}
			}

			for _, subSegment := range segment.SubSegments {
				matches, data, err := s.scanSegment(subSegment)
				progress <- &MemoryScanProgress{
					Process:       s.proc,
					MemorySegment: subSegment,
					Dump:          data,
					Matches:       matches,
					Error:         err,
				}
				if errors.Is(err, os.ErrPermission) {
					return
				}
			}
		}
	}()

	return progress, nil
}

func (s *ProcessScanner) scanSegment(seg *procIO.MemorySegmentInfo) ([]yara.MatchRule, []byte, error) {
	match := s.filter.Filter(seg)
	if !match.Result {
		logrus.WithFields(logrus.Fields{
			"segment": seg,
			"reason":  match.Reason,
		}).Debug("Memory segment skipped.")
		return nil, nil, ErrSkipped
	}

	logrus.WithFields(logrus.Fields{
		"segment": seg,
	}).Info("Scanning memory segment.")

	rdr, err := procIO.NewMemoryReader(s.proc, seg)
	if err != nil {
		return nil, nil, err
	}
	defer rdr.Close()

	data, err := ioutil.ReadAll(rdr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"process":       s.proc,
			"segment":       seg,
			logrus.ErrorKey: err,
		}).Error("Could not read memory of process.")
		return nil, nil, err
	}

	matches, err := s.scanner.ScanMem(data)
	return matches, data, err
}
