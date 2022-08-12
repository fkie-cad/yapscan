package output

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/archiver"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/fkie-cad/yapscan/procio"
	"github.com/fkie-cad/yapscan/report"
	"github.com/fkie-cad/yapscan/system"
	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
	"github.com/targodan/go-errors"
)

// FileScan represents all matches on a file.
type FileScan struct {
	File    fileio.File     `json:"file"`
	Matches []*report.Match `json:"match"`
	Error   interface{}     `json:"error"`
}

// AnalysisReporter implements a Reporter, which is
// specifically intended for later analysis of the report
// in order to determine rule quality.
type AnalysisReporter struct {
	archiver      archiver.Archiver
	closeArchiver bool

	filenamePrefix string
	dumpStorage    DumpStorage

	processInfos map[int]*procio.ProcessInfo
}

func (r *AnalysisReporter) reportMeta() error {
	w, err := r.archiver.Create(r.filenamePrefix + report.MetaFileName)
	if err != nil {
		return err
	}

	err = json.NewEncoder(w).Encode(report.GetMetaInformation())
	if err != nil {
		return errors.NewMultiError(err, w.Close())
	}

	return w.Close()
}

// ReportSystemInfo reports info about the running system.
// This function may only called once, otherwise the behaviour depends on the
// used Archiver.
func (r *AnalysisReporter) ReportSystemInfo(info *system.Info) error {
	w, err := r.archiver.Create(r.filenamePrefix + report.SystemInfoFileName)
	if err != nil {
		return err
	}

	err = json.NewEncoder(w).Encode(info)
	if err != nil {
		return errors.NewMultiError(err, w.Close())
	}

	return w.Close()
}

// ReportScanningStatistics reports about scanning statistics.
// This function may only called once, otherwise the behaviour depends on the
// used Archiver.
func (r *AnalysisReporter) ReportScanningStatistics(stats *yapscan.ScanningStatistics) error {
	w, err := r.archiver.Create(r.filenamePrefix + report.ScanningStatisticsFileName)
	if err != nil {
		return err
	}

	err = json.NewEncoder(w).Encode(stats)
	if err != nil {
		return errors.NewMultiError(err, w.Close())
	}

	return w.Close()
}

// ReportRules reports the given *yara.Rules.
// This function may only called once, otherwise the behaviour depends on the
// used Archiver.
func (r *AnalysisReporter) ReportRules(rules *yara.Rules) error {
	w, err := r.archiver.Create(r.filenamePrefix + report.RulesFileName)
	if err != nil {
		return err
	}

	err = rules.Write(w)
	if err != nil {
		return errors.NewMultiError(err, w.Close())
	}

	return w.Close()
}

func (r *AnalysisReporter) flattenSubsegments(segments []*procio.MemorySegmentInfo) []*procio.MemorySegmentInfo {
	newSegments := make([]*procio.MemorySegmentInfo, 0, len(segments))
	for _, seg := range segments {
		newSegments = append(newSegments, seg)
		if len(seg.SubSegments) > 0 {
			subSegments := r.flattenSubsegments(seg.SubSegments)
			newSegments = append(newSegments, subSegments...)
		}
	}
	return newSegments
}

func (r *AnalysisReporter) reportProcessInfos() error {
	w, err := r.archiver.Create(r.filenamePrefix + report.ProcessesFileName)
	if err != nil {
		return err
	}

	if r.processInfos == nil {
		return w.Close()
	}

	encoder := json.NewEncoder(w)

	for _, info := range r.processInfos {
		info.MemorySegments = r.flattenSubsegments(info.MemorySegments)

		err = encoder.Encode(info)
		if err != nil {
			logrus.WithError(err).Error("Could not report process info.")
		}
	}

	return w.Close()
}

// ConsumeMemoryScanProgress consumes and reports all *yapscan.MemoryScanProgress
// instances sent in the given channel.
// This function may only called once, otherwise the behaviour depends on the
// used Archiver.
func (r *AnalysisReporter) ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error {
	w, err := r.archiver.Create(r.filenamePrefix + report.MemoryScansFileName)
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

		if prog.Matches != nil && len(prog.Matches) > 0 {
			for _, seg := range info.MemorySegments {
				if (seg.BaseAddress == prog.MemorySegment.ParentBaseAddress || seg.BaseAddress == prog.MemorySegment.BaseAddress) &&
					seg.MappedFile != nil {
					err = seg.MappedFile.EnableHashMarshalling()
					if err != nil {
						logrus.WithError(err).Error("Could not determine hash of memory mapped file.")
					}
				}
			}
		}

		// Store info for later output
		r.processInfos[info.PID] = info

		var jsonErr interface{}
		if prog.Error != nil {
			jsonErr = prog.Error.Error()
		}
		err = encoder.Encode(&report.MemoryScan{
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
				Data:    io.NopCloser(bytes.NewReader(prog.Dump)),
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
	w, err := r.archiver.Create(r.filenamePrefix + report.FileScansFileName)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(w)

	for prog := range progress {
		var jsonErr interface{}
		if prog.Error != nil {
			jsonErr = prog.Error.Error()
		}

		var err error

		if prog.Matches != nil && len(prog.Matches) > 0 {
			err = prog.File.EnableHashMarshalling()
			if err != nil {
				logrus.WithError(err).Error("Could not determine hash of memory mapped file.")
			}
		}

		err = encoder.Encode(&FileScan{
			File:    prog.File,
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
