package output

import (
	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/hillu/go-yara/v4"
	"github.com/targodan/go-errors"
	"sync"
)

// MultiReporter is a Reporter which reports all information it recieves
// to all given Reporters.
type MultiReporter struct {
	Reporters []Reporter
}

// ReportSystemInfo retrieves and reports info about the running system.
func (r *MultiReporter) ReportSystemInfo() error {
	var err error
	for _, rep := range r.Reporters {
		err = errors.NewMultiError(err, rep.ReportSystemInfo())
	}
	return err
}

// ReportRules reports the given *yara.Rules.
func (r *MultiReporter) ReportRules(rules *yara.Rules) error {
	var err error
	for _, rep := range r.Reporters {
		err = errors.NewMultiError(err, rep.ReportRules(rules))
	}
	return err
}

// ConsumeMemoryScanProgress consumes and reports all *yapscan.MemoryScanProgress
// instances sent in the given channel.
func (r *MultiReporter) ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error {
	wg := &sync.WaitGroup{}
	chans := make([]chan *yapscan.MemoryScanProgress, len(r.Reporters))
	wg.Add(len(chans))
	for i := range chans {
		chans[i] = make(chan *yapscan.MemoryScanProgress)

		go func(i int) {
			r.Reporters[i].ConsumeMemoryScanProgress(chans[i])
			wg.Done()
		}(i)
	}
	for prog := range progress {
		for i := range chans {
			chans[i] <- prog
		}
	}
	for i := range chans {
		close(chans[i])
	}
	wg.Wait()
	return nil
}

// ConsumeFSScanProgress consumes and reports all *yapscan.FSScanProgress
// instances sent in the given channel.
func (r *MultiReporter) ConsumeFSScanProgress(progress <-chan *fileio.FSScanProgress) error {
	wg := &sync.WaitGroup{}
	chans := make([]chan *fileio.FSScanProgress, len(r.Reporters))
	wg.Add(len(chans))
	for i := range chans {
		chans[i] = make(chan *fileio.FSScanProgress)

		go func(i int) {
			r.Reporters[i].ConsumeFSScanProgress(chans[i])
			wg.Done()
		}(i)
	}
	for prog := range progress {
		for i := range chans {
			chans[i] <- prog
		}
	}
	for i := range chans {
		close(chans[i])
	}
	wg.Wait()
	return nil
}

// Close closes all reporters.
func (r *MultiReporter) Close() error {
	var err error
	for _, rep := range r.Reporters {
		err = errors.NewMultiError(err, rep.Close())
	}
	return err
}
