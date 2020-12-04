package yapscan

import (
	"io/ioutil"
	"os"

	"github.com/hillu/go-yara/v4"

	"github.com/sirupsen/logrus"

	"github.com/fkie-cad/yapscan/procIO"

	"github.com/targodan/go-errors"
)

type segmentScanner interface {
	ScanSegment(seg *procIO.MemorySegmentInfo) ([]yara.MatchRule, []byte, error)
}

// ProcessScanner implements scanning of memory segments, allocated by a process.
// This scanning is done using an underlying MemoryScanner on segments, matching
// a MemorySegmentFilter.
type ProcessScanner struct {
	proc    procIO.Process
	scanner segmentScanner
}

// MemoryScanner is a yara.Rules compatible interface, defining the subset of
// functions required for scanning memory buffers.
type MemoryScanner interface {
	ScanMem(buf []byte) (results []yara.MatchRule, err error)
}

type process interface {
	procIO.Process
}

type memoryReader interface {
	procIO.MemoryReader
}

type memoryReaderFactory interface {
	procIO.MemoryReaderFactory
}

type defaultSegmentScanner struct {
	proc       procIO.Process
	filter     MemorySegmentFilter
	scanner    MemoryScanner
	rdrFactory procIO.MemoryReaderFactory
}

// NewProcessScanner create a new ProcessScanner with for the given procIO.Process.
// It uses the given MemoryScanner in order to scan memory segments of the process,
// which match the given MemoryScanner.
func NewProcessScanner(proc procIO.Process, filter MemorySegmentFilter, scanner MemoryScanner) *ProcessScanner {
	return &ProcessScanner{
		proc: proc,
		scanner: &defaultSegmentScanner{
			proc:       proc,
			filter:     filter,
			scanner:    scanner,
			rdrFactory: &procIO.DefaultMemoryReaderFactory{},
		},
	}
}

// ErrSkipped is returned, when a memory segment is skipped due to
// the applied filter.
var ErrSkipped = errors.New("skipped")

// MemoryScanProgress contains all information, generated during scanning.
type MemoryScanProgress struct {
	// Process contains information about the process being scanned.
	Process procIO.Process
	// MemorySegment contains information about the specific memory segment which was just scanned.
	MemorySegment *procIO.MemorySegmentInfo
	// Dump contains the raw contents of the memory segment.
	Dump []byte
	// Matches contains the yara.MatchRule results.
	Matches []yara.MatchRule
	// Error contains the encountered error or nil, if no error was encountered.
	Error error
}

func (s *ProcessScanner) handleSegment(progress chan<- *MemoryScanProgress, segment *procIO.MemorySegmentInfo) bool {
	if len(segment.SubSegments) == 0 {
		// Only scan leaf segments
		matches, data, err := s.scanner.ScanSegment(segment)
		progress <- &MemoryScanProgress{
			Process:       s.proc,
			MemorySegment: segment,
			Dump:          data,
			Matches:       matches,
			Error:         err,
		}
		return errors.Is(err, os.ErrPermission)
	}

	for _, subSegment := range segment.SubSegments {
		abort := s.handleSegment(progress, subSegment)
		if abort {
			return true
		}
	}

	return false
}

// Scan starts an asynchronous scan.
// The returned unbuffered channel will yield MemoryScanProgress instances
// every time a memory segment has been processed. The channel will be closed
// when all segments have been processed.
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
			abort := s.handleSegment(progress, segment)
			if abort {
				return
			}
		}
	}()

	return progress, nil
}

func (s *defaultSegmentScanner) ScanSegment(seg *procIO.MemorySegmentInfo) ([]yara.MatchRule, []byte, error) {
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

	rdr, err := s.rdrFactory.NewMemoryReader(s.proc, seg)
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
