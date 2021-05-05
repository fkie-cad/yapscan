package output

import (
	"bytes"
	"encoding/json"
	"io/ioutil"

	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/fkie-cad/yapscan/procio"
	"github.com/fkie-cad/yapscan/system"
	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
	"github.com/targodan/go-errors"
)

// SystemInfoFileName is the name of the file, where system info is stored.
const SystemInfoFileName = "systeminfo.json"

// RulesFileName is the name of the file, where the used rules will be stored.
const RulesFileName = "rules.yarc"

// ProcessFileName is the name of the file used to report information about processes.
const ProcessFileName = "processes.json"

// MemoryProgressFileName is the name of the file used to report information about memory scans.
const MemoryProgressFileName = "memory-scans.json"

// FSProgressFileName is the name of the file used to report information about file scans.
const FSProgressFileName = "file-scans.json"

// AnalysisReporter implements a Reporter, which is
// specifically intended for later analysis of the report
// in order to determine rule quality.
type AnalysisReporter struct {
	archiver      Archiver
	closeArchiver bool

	filenamePrefix string
	dumpStorage    DumpStorage

	processInfos map[int]*procio.ProcessInfo
}

// ReportSystemInfo retrieves and reports info about the running system.
// This function may only called once, otherwise the behaviour depends on the
// used Archiver.
func (r *AnalysisReporter) ReportSystemInfo() error {
	w, err := r.archiver.Create(r.filenamePrefix + SystemInfoFileName)
	if err != nil {
		return err
	}

	info, err := system.GetInfo()
	if err != nil {
		logrus.WithError(err).Warn("Could not determine complete system info.")
	}
	err = json.NewEncoder(w).Encode(info)
	if err != nil {
		return errors.NewMultiError(err, w.Close())
	}

	return w.Close()
}

// ReportRules reports the given *yara.Rules.
// This function may only called once, otherwise the behaviour depends on the
// used Archiver.
func (r *AnalysisReporter) ReportRules(rules *yara.Rules) error {
	w, err := r.archiver.Create(r.filenamePrefix + RulesFileName)
	if err != nil {
		return err
	}

	err = rules.Write(w)
	if err != nil {
		return errors.NewMultiError(err, w.Close())
	}

	return w.Close()
}

func (r *AnalysisReporter) reportProcessInfos() error {
	w, err := r.archiver.Create(r.filenamePrefix + ProcessFileName)
	if err != nil {
		return err
	}

	if r.processInfos == nil {
		return w.Close()
	}

	encoder := json.NewEncoder(w)

	for _, info := range r.processInfos {
		err = encoder.Encode(info)
		logrus.WithError(err).Error("Could not report process info.")
	}

	return w.Close()
}

// ConsumeMemoryScanProgress consumes and reports all *yapscan.MemoryScanProgress
// instances sent in the given channel.
// This function may only called once, otherwise the behaviour depends on the
// used Archiver.
func (r *AnalysisReporter) ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error {
	w, err := r.archiver.Create(r.filenamePrefix + MemoryProgressFileName)
	if err != nil {
		return err
	}

	if r.processInfos == nil {
		r.processInfos = make(map[int]*procio.ProcessInfo)
	}

	encoder := json.NewEncoder(w)

	for prog := range progress {
		info, err := prog.Process.Info()
		if err != nil {
			logrus.WithError(err).Warn("Could not retrieve complete process info.")
		}
		// Store info for later output
		r.processInfos[info.PID] = info

		var jsonErr interface{}
		if prog.Error != nil {
			jsonErr = prog.Error.Error()
		}
		err = encoder.Encode(&MemoryScanProgressReport{
			PID:           info.PID,
			MemorySegment: prog.MemorySegment.BaseAddress,
			Matches:       ConvertYaraMatchRules(prog.Matches),
			Error:         jsonErr,
		})
		if err != nil {
			logrus.WithError(err).Error("Could not report progress.")
		}
		if r.dumpStorage != nil && prog.Error == nil && prog.Matches != nil && len(prog.Matches) > 0 {
			err = r.dumpStorage.Store(&Dump{
				PID:     info.PID,
				Segment: prog.MemorySegment,
				Data:    ioutil.NopCloser(bytes.NewReader(prog.Dump)),
			})
			if err != nil {
				logrus.WithError(err).Error("Could not store dump.")
			}
		}
	}
	return w.Close()
}

// ConsumeFSScanProgress consumes and reports all *yapscan.FSScanProgress
// instances sent in the given channel.
// This function may only called once, otherwise the behaviour depends on the
// used Archiver.
func (r *AnalysisReporter) ConsumeFSScanProgress(progress <-chan *fileio.FSScanProgress) error {
	w, err := r.archiver.Create(r.filenamePrefix + FSProgressFileName)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(w)

	for prog := range progress {
		var jsonErr interface{}
		if prog.Error != nil {
			jsonErr = prog.Error.Error()
		}
		err := encoder.Encode(&FSScanProgressReport{
			Path:    prog.File.Path(),
			Matches: ConvertYaraMatchRules(prog.Matches),
			Error:   jsonErr,
		})
		if err != nil {
			logrus.WithError(err).Error("Could not report progress.")
		}
		// TODO: Maybe add dumping capability by copying the offending file.
	}
	return w.Close()
}

// Close closes the AnalysisReporter and all associated files.
func (r *AnalysisReporter) Close() error {
	var err1, err2, err3 error
	err1 = r.reportProcessInfos()
	if r.closeArchiver {
		err2 = r.archiver.Close()
	}
	if r.dumpStorage != nil {
		err3 = r.dumpStorage.Close()
	}
	return errors.NewMultiError(err1, err2, err3)
}
