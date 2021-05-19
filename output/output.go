package output

import (
	"io"

	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/fkie-cad/yapscan/system"
	"github.com/hillu/go-yara/v4"
)

// Reporter provides capability to report on scanning progress.
type Reporter interface {
	ReportSystemInfo(info *system.Info) error
	ReportRules(rules *yara.Rules) error
	ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error
	ConsumeFSScanProgress(progress <-chan *fileio.FSScanProgress) error
	ReportScanningStatistics(stats *yapscan.ScanningStatistics) error
	io.Closer
}

// Match represents the match of a yara Rule.
type Match struct {
	Rule      string         `json:"rule"`
	Namespace string         `json:"namespace"`
	Strings   []*MatchString `json:"strings"`
}

// A MatchString represents a string declared and matched in a rule.
type MatchString struct {
	Name   string `json:"name"`
	Base   uint64 `json:"base"`
	Offset uint64 `json:"offset"`
}

// ConvertYaraMatchRules converts the given slice of yara.MatchRule to
// a slice of *Match.
func ConvertYaraMatchRules(mr []yara.MatchRule) []*Match {
	ret := make([]*Match, len(mr))
	for i, match := range mr {
		ret[i] = &Match{
			Rule:      match.Rule,
			Namespace: match.Namespace,
			Strings:   make([]*MatchString, len(match.Strings)),
		}
		for j, s := range match.Strings {
			ret[i].Strings[j] = &MatchString{
				Name:   s.Name,
				Base:   s.Base,
				Offset: s.Offset,
			}
		}
	}
	return ret
}

// MemoryScanProgressReport represents all matches on a single memory
// segment of a process.
type MemoryScanProgressReport struct {
	PID           int         `json:"pid"`
	MemorySegment uintptr     `json:"memorySegment"`
	Matches       []*Match    `json:"match"`
	Error         interface{} `json:"error"`
}

// FSScanProgressReport represents all matches on a file.
type FSScanProgressReport struct {
	Path    string      `json:"path"`
	Matches []*Match    `json:"match"`
	Error   interface{} `json:"error"`
}
