package output

import (
	"io"

	"github.com/fkie-cad/yapscan/report"

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

// ConvertYaraMatchRules converts the given slice of yara.MatchRule to
// a slice of *Match.
func ConvertYaraMatchRules(mr []yara.MatchRule) []*report.Match {
	ret := make([]*report.Match, len(mr))
	for i, match := range mr {
		ret[i] = &report.Match{
			Rule:      match.Rule,
			Namespace: match.Namespace,
			Strings:   make([]*report.MatchString, len(match.Strings)),
		}
		for j, s := range match.Strings {
			ret[i].Strings[j] = &report.MatchString{
				Name:   s.Name,
				Base:   s.Base,
				Offset: s.Offset,
			}
		}
	}
	return ret
}
