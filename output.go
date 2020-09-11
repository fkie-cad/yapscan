package yapscan

import (
	"fmt"
	"fraunhofer/fkie/yapscan/procIO"
	"io"

	"github.com/hillu/go-yara/v4"

	"github.com/sirupsen/logrus"

	"github.com/doun/terminal/color"
)

type Reporter interface {
	ReportSystemInfos() error
	ReportRules(rules *yara.Rules) error
	ConsumeScanProgress(progress <-chan *ScanProgress) error
	io.Closer
}

type progressReporter struct {
	out       io.Writer
	formatter ProgressFormatter

	pid              int
	procSegmentCount int
	procSegmentIndex int
}

func NewProgressReporter(out io.Writer, formatter ProgressFormatter) Reporter {
	return &progressReporter{out: out, formatter: formatter, pid: -1}
}

func (r *progressReporter) ReportSystemInfos() error {
	// Don't report systeminfo to stdout
	return nil
}

func (r *progressReporter) ReportRules(rules *yara.Rules) error {
	// Don't report rules to stdout
	return nil
}

func (r *progressReporter) Close() error {
	closer, ok := r.out.(io.Closer)
	if ok {
		return closer.Close()
	}
	return nil
}

func (r *progressReporter) reportProcess(proc procIO.Process) error {
	_, err := fmt.Fprintf(r.out, "\nScanning process %d...\n", proc.PID())
	return err
}

func (r *progressReporter) receive(progress *ScanProgress) {
	if r.pid != progress.Process.PID() {
		r.pid = progress.Process.PID()
		segments, _ := progress.Process.MemorySegments()
		r.procSegmentCount = 0
		for _, seg := range segments {
			l := len(seg.SubSegments)
			if l > 0 {
				r.procSegmentCount += l
			} else {
				r.procSegmentCount += 1
			}
		}
		r.procSegmentIndex = 0
		err := r.reportProcess(progress.Process)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"process":       progress.Process.PID(),
				logrus.ErrorKey: err,
			}).Error("Could not report on process.")
		}
	}
	r.procSegmentIndex += 1
	percent := int(float64(r.procSegmentIndex)/float64(r.procSegmentCount)*100. + 0.5)
	fmt.Fprintf(r.out, "\r%-64s", fmt.Sprintf("Scanning %d: %3d %%", progress.Process.PID(), percent))

	if progress.Error == nil {
		logrus.WithFields(logrus.Fields{
			"process": progress.Process.PID(),
			"segment": progress.MemorySegment,
		}).Info("Scan of segment complete.")
	} else if progress.Error != ErrSkipped {
		logrus.WithFields(logrus.Fields{
			"process":       progress.Process.PID(),
			"segment":       progress.MemorySegment,
			logrus.ErrorKey: progress.Error,
		}).Error("Scan of segment failed.")
	}

	if (progress.Error != nil && progress.Error != ErrSkipped) || (progress.Matches != nil && len(progress.Matches) > 0) {
		fmt.Sprintln(r.out)
		fmt.Sprintln(r.out, r.formatter.FormatScanProgress(progress))
	}
}

func (r *progressReporter) ConsumeScanProgress(progress <-chan *ScanProgress) error {
	for prog := range progress {
		r.receive(prog)
	}
	fmt.Sprintln(r.out)
	return nil
}

type ProgressFormatter interface {
	FormatScanProgress(progress *ScanProgress) string
}

type prettyFormatter struct{}

func NewPrettyFormatter() ProgressFormatter {
	return &prettyFormatter{}
}

func (p prettyFormatter) FormatScanProgress(progress *ScanProgress) string {
	if progress.Error != nil {
		msg := ""
		if progress.Error == ErrSkipped {
			msg = "Skipped " + procIO.FormatMemorySegmentAddress(progress.MemorySegment)
		} else {
			msg = "Error during scan of segment " + procIO.FormatMemorySegmentAddress(progress.MemorySegment) + ": " + progress.Error.Error()
		}
		return msg
	}

	if progress.Matches == nil || len(progress.Matches) == 0 {
		return ""
	}

	ret := ""

	for _, match := range progress.Matches {
		ret += color.Sprintf("@rMATCH:@| Rule \"%s\" matches segment %s at ", match.Rule, procIO.FormatMemorySegmentAddress(progress.MemorySegment))
		for _, str := range match.Strings {
			ret += fmt.Sprintf("0x%X (%s), ", str.Offset, str.Name)
		}
		ret = ret[:len(ret)-2] + "\n"
	}

	return ret[:len(ret)-1]
}
