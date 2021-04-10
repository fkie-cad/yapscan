package output

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/fkie-cad/yapscan/procio"
	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
	"io"
	"path/filepath"
	"strings"
)

type progressReporter struct {
	out       io.WriteCloser
	formatter ProgressFormatter

	pid              int
	procMatched      bool
	procSegmentCount int
	procSegmentIndex int
	allClean         bool
}

// NewProgressReporter creates a new Reporter, which will write memory and file scanning
// progress to the given io.WriteCloser out using the ProgressFormatter formatter for
// formatting.
// This Reporter is intended for live updates to the console, hence ReportSystemInfo()
// and ReportRules() do nothing.
func NewProgressReporter(out io.WriteCloser, formatter ProgressFormatter) Reporter {
	return &progressReporter{out: out, formatter: formatter, pid: -1, allClean: true}
}

func (r *progressReporter) ReportSystemInfo() error {
	// Don't report systeminfo to stdout
	return nil
}

func (r *progressReporter) ReportRules(rules *yara.Rules) error {
	// Don't report rules to stdout
	return nil
}

func (r *progressReporter) Close() error {
	fmt.Fprintln(r.out)
	if r.allClean {
		fmt.Fprintln(r.out, color.GreenString("No matches were found."))
	} else {
		fmt.Fprintln(r.out, color.RedString("Some processes matched the provided rules, see above."))
	}
	return r.out.Close()
}

func (r *progressReporter) reportProcess(proc procio.Process) error {
	info, err := proc.Info()
	if err != nil {
		logrus.WithError(err).Warn("Could not retrieve complete process info.")
	}
	procname := filepath.Base(info.ExecutablePath)
	username := info.Username
	_, err = fmt.Fprintf(r.out, "\nScanning process \"%s\" (%d) by user \"%s\"...\n", procname, proc.PID(), username)
	return err
}

func (r *progressReporter) receiveMem(progress *yapscan.MemoryScanProgress) {
	if r.pid != progress.Process.PID() {
		r.pid = progress.Process.PID()
		r.procMatched = false
		segments, _ := progress.Process.MemorySegments()
		r.procSegmentCount = 0
		for _, seg := range segments {
			l := len(seg.SubSegments)
			if l > 0 {
				r.procSegmentCount += l
			} else {
				r.procSegmentCount++
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

	if progress.Matches != nil && len(progress.Matches) > 0 {
		r.procMatched = true
		r.allClean = false
	}

	matchOut := r.formatter.FormatMemoryScanProgress(progress)
	if matchOut != "" {
		fmt.Fprintln(r.out, "\r", matchOut)
	}

	r.procSegmentIndex++
	percent := int(float64(r.procSegmentIndex)/float64(r.procSegmentCount)*100. + 0.5)

	var format string
	if r.procMatched {
		format = "Scanning " + color.RedString("%d") + ": %3d %%"
	} else {
		format = "Scanning %d: %3d %%"
	}
	fmt.Fprintf(r.out, "\r%-64s", fmt.Sprintf(format, progress.Process.PID(), percent))

	if progress.Error == nil {
		logrus.WithFields(logrus.Fields{
			"process": progress.Process.PID(),
			"segment": progress.MemorySegment,
		}).Info("Scan of segment complete.")
	} else if progress.Error != yapscan.ErrSkipped {
		logrus.WithFields(logrus.Fields{
			"process":       progress.Process.PID(),
			"segment":       progress.MemorySegment,
			logrus.ErrorKey: progress.Error,
		}).Error("Scan of segment failed.")
	}

	if (progress.Error != nil && progress.Error != yapscan.ErrSkipped) || (progress.Matches != nil && len(progress.Matches) > 0) {
		fmt.Sprintln(r.out)
		fmt.Sprintln(r.out, r.formatter.FormatMemoryScanProgress(progress))
	}
}

func (r *progressReporter) ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error {
	for prog := range progress {
		r.receiveMem(prog)
	}
	fmt.Sprintln(r.out)
	return nil
}

func (r *progressReporter) receiveFS(progress *fileio.FSScanProgress) {
	if progress.Matches != nil && len(progress.Matches) > 0 {
		r.allClean = false
	}

	matchOut := r.formatter.FormatFSScanProgress(progress)
	if matchOut != "" {
		fmt.Fprintln(r.out, "\r", matchOut)
	}

	if progress.Error == nil {
		format := "Scanning \"%s\""
		fmt.Fprintf(r.out, "\r%-128s", fmt.Sprintf(format, r.formatter.FormatPath(progress.File.Path(), 117)))

		logrus.WithFields(logrus.Fields{
			"file": progress.File.Path(),
		}).Info("Scan of file complete.")
	} else if progress.Error != yapscan.ErrSkipped {
		logrus.WithFields(logrus.Fields{
			"file":          progress.File.Path(),
			logrus.ErrorKey: progress.Error,
		}).Error("Scan of file failed.")
	}

	if (progress.Error != nil && progress.Error != yapscan.ErrSkipped) || (progress.Matches != nil && len(progress.Matches) > 0) {
		fmt.Sprintln(r.out)
		fmt.Sprintln(r.out, r.formatter.FormatFSScanProgress(progress))
	}
}

func (r *progressReporter) ConsumeFSScanProgress(progress <-chan *fileio.FSScanProgress) error {
	for prog := range progress {
		r.receiveFS(prog)
	}
	fmt.Sprintln(r.out)
	return nil
}

// ProgressFormatter formats progress information.
type ProgressFormatter interface {
	FormatMemoryScanProgress(progress *yapscan.MemoryScanProgress) string
	FormatFSScanProgress(progress *fileio.FSScanProgress) string
	FormatPath(path string, maxlen int) string
}

type prettyFormatter struct{}

// NewPrettyFormatter creates a new pretty formatter for human readable console output.
func NewPrettyFormatter() ProgressFormatter {
	return &prettyFormatter{}
}

func (p prettyFormatter) FormatMemoryScanProgress(progress *yapscan.MemoryScanProgress) string {
	if progress.Error != nil {
		msg := ""
		// TODO: Maybe enable via a verbose flag
		//if progress.Error == ErrSkipped {
		//	msg = "Skipped " + procio.FormatMemorySegmentAddress(progress.MemorySegment)
		//} else {
		//	msg = "Error during scan of segment " + procio.FormatMemorySegmentAddress(progress.MemorySegment) + ": " + progress.Error.Error()
		//}
		return msg
	}

	if progress.Matches == nil || len(progress.Matches) == 0 {
		return ""
	}

	txt := make([]string, len(progress.Matches))
	for i, match := range progress.Matches {
		txt[i] = fmt.Sprintf(
			color.RedString("MATCH:")+" Rule \"%s\" matches segment %s.",
			match.Rule, procio.FormatMemorySegmentAddress(progress.MemorySegment),
		)
		if len(match.Strings) > 0 {
			addrs := yapscan.FormatSlice("0x%X", yapscan.AddressesFromMatches(match.Strings, uint64(progress.MemorySegment.BaseAddress)))
			txt[i] += fmt.Sprintf("\n\tRule-strings matched at %s.", yapscan.Join(addrs, ", ", " and "))
		}
	}
	return strings.Join(txt, "\n")
}

func (p prettyFormatter) FormatPath(path string, maxlen int) string {
	// TODO: This needs improvement.
	if len(path) <= maxlen {
		return path
	}
	parts := strings.Split(path, fmt.Sprintf("%c", filepath.Separator))
	res := parts[0]
	if len(parts) == 1 {
		if len(res)-maxlen-3 < 0 {
			return res
		}
		return "..." + res[len(res)-maxlen-3:]
	}
	if len(parts) == 2 {
		if len(parts[1])-len(res)-1-maxlen-3 < 0 {
			return filepath.Join(res, parts[1])
		}
		return filepath.Join(res, "..."+parts[1][len(parts[1])-len(res)-1-maxlen-3:])
	}
	res = filepath.Join(res, "...", parts[len(parts)-1])
	if len(res) <= maxlen {
		return res
	}
	dir, file := filepath.Split(res)
	if len(dir) < maxlen {
		if len(file)-len(dir)-1-maxlen-3 < 0 {
			return res
		}
		return filepath.Join(dir, "..."+file[len(file)-len(dir)-1-maxlen-3:])
	}
	if len(res)-maxlen-3 < 0 {
		return res
	}
	return "..." + res[len(res)-maxlen-3:]
}

func (p prettyFormatter) FormatFSScanProgress(progress *fileio.FSScanProgress) string {
	if progress.Error != nil {
		// TODO: Maybe enable via a verbose flag
		return ""
	}

	if progress.Matches == nil || len(progress.Matches) == 0 {
		return ""
	}

	txt := make([]string, len(progress.Matches))
	for i, match := range progress.Matches {
		txt[i] = fmt.Sprintf(
			color.RedString("MATCH:")+" Rule \"%s\" matches file %s.",
			match.Rule, progress.File.Path(),
		)
		if len(match.Strings) > 0 {
			addrs := yapscan.FormatSlice("0x%X", yapscan.AddressesFromMatches(match.Strings, 0))
			txt[i] += fmt.Sprintf("\n\tRule-strings matched at %s.", yapscan.Join(addrs, ", ", " and "))
		}
	}
	return strings.Join(txt, "\n")
}
