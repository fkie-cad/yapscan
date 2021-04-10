package output

import (
	"bytes"
	"encoding/json"
	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/fkie-cad/yapscan/procio"
	"github.com/fkie-cad/yapscan/system"
	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
	"github.com/targodan/go-errors"
	"io"
	"io/ioutil"
)

// AnalysisReporter implements a Reporter, which is
// specifically intended for later analysis of the report
// in order to determine rule quality.
type AnalysisReporter struct {
	SystemInfoOut         io.WriteCloser
	RulesOut              io.WriteCloser
	ProcessInfoOut        io.WriteCloser
	MemoryScanProgressOut io.WriteCloser
	FSScanProgressOut     io.WriteCloser
	DumpStorage           DumpStorage

	systemInfoOutClosed bool
	rulesOutClosed      bool

	seen map[int]bool
}

func (r *AnalysisReporter) WithArchiver(archiver Archiver, filePrefix string) (*AutoArchiver, error) {
	var err error
	archiveContents := make([]AutoArchivingWriter, 5)

	archiveContents[0], err = NewAutoArchivedFromDecorated(
		filePrefix+SystemInfoFileName+suggestedFileExtension(r.SystemInfoOut),
		r.SystemInfoOut)
	r.SystemInfoOut = archiveContents[0]
	if err != nil {
		return nil, err
	}

	archiveContents[1], err = NewAutoArchivedFromDecorated(
		filePrefix+RulesFileName+suggestedFileExtension(r.SystemInfoOut),
		r.RulesOut)
	r.RulesOut = archiveContents[1]
	if err != nil {
		return nil, err
	}

	archiveContents[2], err = NewAutoArchivedFromDecorated(
		filePrefix+SystemInfoFileName+suggestedFileExtension(r.ProcessInfoOut),
		r.ProcessInfoOut)
	r.ProcessInfoOut = archiveContents[2]
	if err != nil {
		return nil, err
	}

	archiveContents[3], err = NewAutoArchivedFromDecorated(
		filePrefix+SystemInfoFileName+suggestedFileExtension(r.MemoryScanProgressOut),
		r.MemoryScanProgressOut)
	r.MemoryScanProgressOut = archiveContents[3]
	if err != nil {
		return nil, err
	}

	archiveContents[4], err = NewAutoArchivedFromDecorated(
		filePrefix+SystemInfoFileName+suggestedFileExtension(r.FSScanProgressOut),
		r.FSScanProgressOut)
	r.FSScanProgressOut = archiveContents[4]
	if err != nil {
		return nil, err
	}

	ar := NewAutoArchiver(archiver, archiveContents...)
	return ar, nil
}

func (r *AnalysisReporter) WithOutputDecorator(decorator OutputDecorator) error {
	var err error
	r.SystemInfoOut, err = decorator(r.SystemInfoOut)
	if err != nil {
		return err
	}
	r.RulesOut, err = decorator(r.RulesOut)
	if err != nil {
		return err
	}
	r.ProcessInfoOut, err = decorator(r.ProcessInfoOut)
	if err != nil {
		return err
	}
	r.MemoryScanProgressOut, err = decorator(r.MemoryScanProgressOut)
	if err != nil {
		return err
	}
	r.FSScanProgressOut, err = decorator(r.FSScanProgressOut)
	if err != nil {
		return err
	}

	// TODO: Handle DumpStorage?

	return nil
}

// ReportSystemInfo retrieves and reports info about the running system.
func (r *AnalysisReporter) ReportSystemInfo() error {
	if r.SystemInfoOut == nil {
		return nil
	}
	if r.systemInfoOutClosed {
		return errors.New("SystemInfo already reported, can only report once")
	}

	info, err := system.GetInfo()
	if err != nil {
		logrus.WithError(err).Warn("Could not determine complete system info.")
	}
	err = json.NewEncoder(r.SystemInfoOut).Encode(info)
	if err != nil {
		return err
	}

	r.systemInfoOutClosed = true
	return r.SystemInfoOut.Close()
}

// ReportRules reports the given *yara.Rules.
func (r *AnalysisReporter) ReportRules(rules *yara.Rules) error {
	if r.RulesOut == nil {
		return nil
	}
	if r.rulesOutClosed {
		return errors.New("rules already reported, can only report once")
	}

	err := rules.Write(r.RulesOut)
	if err != nil {
		return err
	}

	r.rulesOutClosed = true
	return r.RulesOut.Close()
}

func (r *AnalysisReporter) reportProcess(info *procio.ProcessInfo) error {
	if r.ProcessInfoOut == nil {
		return nil
	}

	return json.NewEncoder(r.ProcessInfoOut).Encode(info)
}

// ConsumeMemoryScanProgress consumes and reports all *yapscan.MemoryScanProgress
// instances sent in the given channel.
func (r *AnalysisReporter) ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error {
	if r.seen == nil {
		r.seen = make(map[int]bool)
	}

	for prog := range progress {
		info, err := prog.Process.Info()
		if err != nil {
			logrus.WithError(err).Warn("Could not retrieve complete process info.")
		}
		_, seen := r.seen[info.PID]
		if !seen {
			r.seen[info.PID] = true
			err = r.reportProcess(info)
			if err != nil {
				logrus.WithError(err).Error("Could not report process info.")
			}
		}

		var jsonErr interface{}
		if prog.Error != nil {
			jsonErr = prog.Error.Error()
		}
		err = json.NewEncoder(r.MemoryScanProgressOut).Encode(&MemoryScanProgressReport{
			PID:           info.PID,
			MemorySegment: prog.MemorySegment.BaseAddress,
			Matches:       ConvertYaraMatchRules(prog.Matches),
			Error:         jsonErr,
		})
		if err != nil {
			logrus.WithError(err).Error("Could not report progress.")
		}
		if r.DumpStorage != nil && prog.Error == nil && prog.Matches != nil && len(prog.Matches) > 0 {
			err = r.DumpStorage.Store(&Dump{
				PID:     info.PID,
				Segment: prog.MemorySegment,
				Data:    ioutil.NopCloser(bytes.NewReader(prog.Dump)),
			})
			if err != nil {
				logrus.WithError(err).Error("Could not store dump.")
			}
		}
	}
	return nil
}

// ConsumeFSScanProgress consumes and reports all *yapscan.FSScanProgress
// instances sent in the given channel.
func (r *AnalysisReporter) ConsumeFSScanProgress(progress <-chan *fileio.FSScanProgress) error {
	if r.seen == nil {
		r.seen = make(map[int]bool)
	}

	for prog := range progress {
		var jsonErr interface{}
		if prog.Error != nil {
			jsonErr = prog.Error.Error()
		}
		err := json.NewEncoder(r.FSScanProgressOut).Encode(&FSScanProgressReport{
			Path:    prog.File.Path(),
			Matches: ConvertYaraMatchRules(prog.Matches),
			Error:   jsonErr,
		})
		if err != nil {
			logrus.WithError(err).Error("Could not report progress.")
		}
		// TODO: Maybe add dumping capability by copying the offending file.
	}
	return nil
}

// Close closes the AnalysisReporter and all associated files.
func (r *AnalysisReporter) Close() error {
	var err error
	if !r.systemInfoOutClosed {
		err = errors.NewMultiError(err, r.SystemInfoOut.Close())
	}
	if !r.rulesOutClosed {
		err = errors.NewMultiError(err, r.RulesOut.Close())
	}
	err = errors.NewMultiError(err, r.ProcessInfoOut.Close())
	err = errors.NewMultiError(err, r.MemoryScanProgressOut.Close())
	err = errors.NewMultiError(err, r.FSScanProgressOut.Close())
	return err
}
