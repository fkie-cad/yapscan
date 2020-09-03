package yapscan

import (
	"fmt"
	"fraunhofer/fkie/yapscan/procIO"

	"github.com/doun/terminal/color"
)

type Reporter interface {
	Receive(progress *ScanProgress) error
	Consume(progress <-chan *ScanProgress) error
}

type stdoutReporter struct {
	formatter ProgressFormatter

	pid              int
	procSegmentCount int
	procSegmentIndex int
}

func NewStdoutReporter(formatter ProgressFormatter) Reporter {
	return &stdoutReporter{formatter: formatter, pid: -1}
}

func (r *stdoutReporter) Receive(progress *ScanProgress) error {
	if r.pid != progress.Process.PID() {
		r.pid = progress.Process.PID()
		segments, _ := progress.Process.MemorySegments()
		r.procSegmentCount = len(segments)
		r.procSegmentIndex = 0
	}
	r.procSegmentIndex += 1
	percent := int(float64(r.procSegmentIndex)/float64(r.procSegmentCount)*100. + 0.5)
	fmt.Printf("\r%-64s", fmt.Sprintf("Scanning %d: %3d %%", progress.Process.PID(), percent))

	if (progress.Error != nil && progress.Error != ErrSkipped) || (progress.Matches != nil && len(progress.Matches) > 0) {
		fmt.Println()
		fmt.Println(r.formatter.Format(progress))
	}
	return nil
}

func (r *stdoutReporter) Consume(progress <-chan *ScanProgress) error {
	for prog := range progress {
		r.Receive(prog)
	}
	fmt.Println()
	return nil
}

type ProgressFormatter interface {
	Format(progress *ScanProgress) string
}

type prettyFormatter struct{}

func NewPrettyFormatter() ProgressFormatter {
	return &prettyFormatter{}
}

func (p prettyFormatter) Format(progress *ScanProgress) string {
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
