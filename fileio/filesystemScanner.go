package fileio

import (
	"io"
	"sync"

	"github.com/hillu/go-yara/v4"
)

// FileScanner provides functionality to scan files.
type FileScanner interface {
	ScanFile(filename string) (results []yara.MatchRule, err error)
}

// FSScanner is a scanner for the filesystem.
type FSScanner struct {
	NGoroutines int
	scanner     FileScanner
}

// NewFSScanner create a new FSScanner, which will use the given FileScanner
// to scan any encountered file.
func NewFSScanner(scanner FileScanner) *FSScanner {
	return &FSScanner{
		scanner: scanner,
	}
}

// FSScanProgress provides information about the scanning progress.
type FSScanProgress struct {
	File    File
	Matches []yara.MatchRule
	Error   error
}

// Scan scans all files, emitted by the given Iterator.
func (s *FSScanner) Scan(it Iterator) (<-chan *FSScanProgress, error) {
	if s.NGoroutines <= 0 {
		s.NGoroutines = 1
	}

	progress := make(chan *FSScanProgress)

	wg := &sync.WaitGroup{}
	wg.Add(s.NGoroutines)
	for i := 0; i < s.NGoroutines; i++ {
		go func() {
			defer wg.Done()

			for {
				file, err := it.Next()
				if err == io.EOF {
					break
				} else if err != nil {
					progress <- &FSScanProgress{
						File:    file,
						Matches: nil,
						Error:   err,
					}
					continue
				}

				matches, err := s.scanner.ScanFile(file.Path())
				progress <- &FSScanProgress{
					File:    file,
					Matches: matches,
					Error:   err,
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(progress)
	}()

	return progress, nil
}
