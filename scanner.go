package yapscan

import (
	"io/ioutil"

	"github.com/hillu/go-yara/v4"

	"github.com/sirupsen/logrus"

	"fraunhofer/fkie/yapscan/procIO"

	"github.com/targodan/go-errors"
)

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

type ScanProgress struct {
	Process       procIO.Process
	MemorySegment *procIO.MemorySegmentInfo
	Matches       []yara.MatchRule
	Error         error
}

func (s *ProcessScanner) Scan() (<-chan *ScanProgress, error) {
	segments, err := s.proc.MemorySegments()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"process":       s.proc,
			logrus.ErrorKey: err,
		}).Error("Could not retrieve memory segments for process.")
		return nil, err
	}

	progress := make(chan *ScanProgress)

	go func() {
		defer close(progress)
		for _, segment := range segments {
			matches, err := s.scanSegment(segment)
			progress <- &ScanProgress{
				Process:       s.proc,
				MemorySegment: segment,
				Matches:       matches,
				Error:         err,
			}

			for _, subSegment := range segment.SubSegments {
				matches, err := s.scanSegment(subSegment)
				progress <- &ScanProgress{
					Process:       s.proc,
					MemorySegment: subSegment,
					Matches:       matches,
					Error:         err,
				}
			}
		}
	}()

	return progress, nil
}

func (s *ProcessScanner) scanSegment(seg *procIO.MemorySegmentInfo) ([]yara.MatchRule, error) {
	match := s.filter.Filter(seg)
	if !match.Result {
		logrus.WithFields(logrus.Fields{
			"segment": seg,
			"reason":  match.Reason,
		}).Debug("Memory segment skipped.")
		return nil, ErrSkipped
	}

	logrus.WithFields(logrus.Fields{
		"segment": seg,
	}).Info("Scanning memory segment.")

	rdr, err := procIO.NewMemoryReader(s.proc, seg)
	if err != nil {
		return nil, err
	}
	defer rdr.Close()

	data, err := ioutil.ReadAll(rdr)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"process":       s.proc,
			"segment":       seg,
			logrus.ErrorKey: err,
		}).Info("Could not read memory from process.")
		return nil, err
	}

	return s.scanner.ScanMem(data)
}
