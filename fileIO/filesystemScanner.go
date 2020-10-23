package fileIO

import (
	"io"
	"sync"

	"github.com/hillu/go-yara/v4"
)

type FileScanner interface {
	ScanFile(filename string) (results []yara.MatchRule, err error)
}

type FSScanner struct {
	NGoroutines int
	scanner     FileScanner
}

func NewFSScanner(scanner FileScanner) *FSScanner {
	return &FSScanner{
		scanner: scanner,
	}
}

type FSScanProgress struct {
	File    File
	Matches []yara.MatchRule
	Error   error
}

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
