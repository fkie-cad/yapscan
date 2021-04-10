package output

import (
	"bytes"
	"fmt"
	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
	"github.com/targodan/go-errors"
	"os"
	"path"
	"path/filepath"
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

func NewInMemoryAnalysisReporter() *AnalysisReporter {
	return &AnalysisReporter{
		SystemInfoOut:         &nopWriteCloser{&bytes.Buffer{}},
		RulesOut:              &nopWriteCloser{&bytes.Buffer{}},
		ProcessInfoOut:        &nopWriteCloser{&bytes.Buffer{}},
		MemoryScanProgressOut: &nopWriteCloser{&bytes.Buffer{}},
		FSScanProgressOut:     &nopWriteCloser{&bytes.Buffer{}},
	}
}

type TempFileAnalysisReporter struct {
	AnalysisReporter *AnalysisReporter

	directory             string
	DeleteDirOnClose      bool
	ForceDeleteDirOnClose bool
}

func NewTempFileAnalysisReporter(tempDir string) (*TempFileAnalysisReporter, error) {
	isEmpty, err := isDirEmpty(tempDir)
	if err != nil {
		return nil, fmt.Errorf("could not determine if analysis directory is empty, reason: %w", err)
	}
	if !isEmpty {
		return nil, errors.New("analysis output directory is not empty")
	}

	sysinfo, err := os.OpenFile(path.Join(tempDir, SystemInfoFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open systeminfo file, reason: %w", err)
	}
	rules, err := os.OpenFile(path.Join(tempDir, RulesFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open rules file, reason: %w", err)
	}
	process, err := os.OpenFile(path.Join(tempDir, ProcessFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open processes file, reason: %w", err)
	}
	memProgress, err := os.OpenFile(path.Join(tempDir, MemoryProgressFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open memory progress file, reason: %w", err)
	}
	fileProgress, err := os.OpenFile(path.Join(tempDir, FSProgressFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open filesystem progress file, reason: %w", err)
	}

	return &TempFileAnalysisReporter{
		AnalysisReporter: &AnalysisReporter{
			SystemInfoOut:         sysinfo,
			RulesOut:              rules,
			ProcessInfoOut:        process,
			MemoryScanProgressOut: memProgress,
			FSScanProgressOut:     fileProgress,
		},
		directory: tempDir,
	}, nil
}

func (r *TempFileAnalysisReporter) ReportSystemInfo() error {
	return r.AnalysisReporter.ReportSystemInfo()
}

func (r *TempFileAnalysisReporter) ReportRules(rules *yara.Rules) error {
	return r.AnalysisReporter.ReportRules(rules)
}

func (r *TempFileAnalysisReporter) ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error {
	return r.AnalysisReporter.ConsumeMemoryScanProgress(progress)
}

func (r *TempFileAnalysisReporter) ConsumeFSScanProgress(progress <-chan *fileio.FSScanProgress) error {
	return r.AnalysisReporter.ConsumeFSScanProgress(progress)
}

func (r *TempFileAnalysisReporter) Close() error {
	err := r.AnalysisReporter.Close()
	if err != nil && !r.ForceDeleteDirOnClose {
		return err
	}
	if !r.DeleteDirOnClose && !r.ForceDeleteDirOnClose {
		return nil
	}

	delErr := os.RemoveAll(r.directory)
	if delErr != nil {
		fmt.Printf("Could not delete temporary directory \"%s\".\n", r.directory)
		logrus.WithFields(logrus.Fields{
			"dir":           r.directory,
			logrus.ErrorKey: delErr,
		}).Error("Could not delete temporary directory.")
	}

	return errors.NewMultiError(err, delErr)
}

func isDirEmpty(dir string) (bool, error) {
	fInfo, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(dir, 0777)
			return true, nil
		}
		return false, err
	}

	if !fInfo.IsDir() {
		return false, errors.New("path is not a directory")
	}

	contents, err := filepath.Glob(path.Join(dir, "*"))
	if err != nil {
		return false, err
	}
	return len(contents) == 0, nil
}
