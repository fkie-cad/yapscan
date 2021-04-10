package output

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
	"github.com/targodan/go-errors"
	"github.com/yeka/zip"
	"io"
	"math/rand"
	"os"
	"path"
)

// Reporter provides capability to report on scanning progress.
type Reporter interface {
	ReportSystemInfo() error
	ReportRules(rules *yara.Rules) error
	ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error
	ConsumeFSScanProgress(progress <-chan *fileio.FSScanProgress) error
	io.Closer
}

// GatheredAnalysisReporter wraps an *AnalysisReporter and creates a single
// encrypted ZIP file on Close.
type GatheredAnalysisReporter struct {
	directory string
	// If ZIP is set, the output files will be zipped into the
	// specified ZIP file.
	ZIP                string
	ZIPPassword        string
	DeleteAfterZipping bool
	reporter           *AnalysisReporter
}

// NewGatheredAnalysisReporter creates a new *GatheredAnalysisReporter
// which will store temporary report files in the given outPath and
// create an encrypted ZIP with the path *GatheredAnalysisReporter.ZIP on
// *GatheredAnalysisReporter.Close.
func NewGatheredAnalysisReporter(outPath string) (*GatheredAnalysisReporter, error) {
	isEmpty, err := isDirEmpty(outPath)
	if err != nil {
		return nil, fmt.Errorf("could not determine if analysis directory is empty, reason: %w", err)
	}
	if !isEmpty {
		return nil, errors.New("analysis output directory is not empty")
	}

	sysinfo, err := os.OpenFile(path.Join(outPath, SystemInfoFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open systeminfo file, reason: %w", err)
	}
	rules, err := os.OpenFile(path.Join(outPath, RulesFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open rules file, reason: %w", err)
	}
	process, err := os.OpenFile(path.Join(outPath, ProcessFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open processes file, reason: %w", err)
	}
	memProgress, err := os.OpenFile(path.Join(outPath, MemoryProgressFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open memory progress file, reason: %w", err)
	}
	fileProgress, err := os.OpenFile(path.Join(outPath, FSProgressFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, fmt.Errorf("could not open filesystem progress file, reason: %w", err)
	}

	return &GatheredAnalysisReporter{
		directory: outPath,
		reporter: &AnalysisReporter{
			SystemInfoOut:         sysinfo,
			RulesOut:              rules,
			ProcessInfoOut:        process,
			MemoryScanProgressOut: memProgress,
			FSScanProgressOut:     fileProgress,
			DumpStorage:           nil,
			seen:                  make(map[int]bool),
		},
	}, nil
}

// Directory returns the output directory of the underlying *AnalysisReporter.
func (r *GatheredAnalysisReporter) Directory() string {
	return r.directory
}

// WithDumpStorage registers the given DumpStorage with the underlying
// *AnalysisReporter and
func (r *GatheredAnalysisReporter) WithDumpStorage(ds DumpStorage) {
	r.reporter.DumpStorage = ds
}

// ReportSystemInfo retrieves and reports info about the running system
// using the underlying *AnalysisReporter.
func (r *GatheredAnalysisReporter) ReportSystemInfo() error {
	return r.reporter.ReportSystemInfo()
}

// ReportRules reports the given *yara.Rules using the underlying *AnalysisReporter.
func (r *GatheredAnalysisReporter) ReportRules(rules *yara.Rules) error {
	return r.reporter.ReportRules(rules)
}

// ConsumeMemoryScanProgress consumes and reports all *yapscan.MemoryScanProgress
// instances sent in the given channel using the underlying *AnalysisReporter.
func (r *GatheredAnalysisReporter) ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error {
	return r.reporter.ConsumeMemoryScanProgress(progress)
}

// ConsumeFSScanProgress consumes and reports all *yapscan.FSScanProgress
// instances sent in the given channel using the underlying *AnalysisReporter.
func (r *GatheredAnalysisReporter) ConsumeFSScanProgress(progress <-chan *fileio.FSScanProgress) error {
	return r.reporter.ConsumeFSScanProgress(progress)
}

// SuggestZIPName returns a suggestion for the zip name, based on the
// hostname of the running system.
func (r *GatheredAnalysisReporter) SuggestZIPName() string {
	var fname string
	hostname, err := os.Hostname()
	if err != nil {
		logrus.WithError(err).Warn("Could not determine hostname.")
		fname = "yapscan.zip"
	} else {
		fname = fmt.Sprintf("yapscan_%s.zip", hostname)
	}
	return fname
}

func (r *GatheredAnalysisReporter) zip() error {
	zFile, err := os.OpenFile(r.ZIP, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		return fmt.Errorf("could not create zip file, reason: %w", err)
	}
	defer zFile.Close()

	z := zip.NewWriter(zFile)
	defer z.Close()

	hostname, err := os.Hostname()
	if err != nil {
		logrus.WithError(err).Warn("Could not determine hostname.")
		h := md5.New()
		binary.Write(h, binary.LittleEndian, rand.Int())
		binary.Write(h, binary.LittleEndian, rand.Int())
		hostname = hex.EncodeToString(h.Sum(nil))
	}

	var out io.Writer

	var zipper func(name string) (io.Writer, error)
	if r.ZIPPassword == "" {
		zipper = func(name string) (io.Writer, error) {
			return z.Create(name)
		}
	} else {
		zipper = func(name string) (io.Writer, error) {
			return z.Encrypt(name, r.ZIPPassword, zip.AES256Encryption)
		}
	}

	var in *os.File

	out, err = zipper(path.Join(hostname, SystemInfoFileName))
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}
	in = r.reporter.SystemInfoOut.(*os.File)
	_, err = in.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}
	_, err = io.Copy(out, in)
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}

	out, err = zipper(path.Join(hostname, RulesFileName))
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}
	in = r.reporter.RulesOut.(*os.File)
	_, err = in.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}
	_, err = io.Copy(out, in)
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}

	out, err = zipper(path.Join(hostname, ProcessFileName))
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}
	in = r.reporter.ProcessInfoOut.(*os.File)
	_, err = in.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}
	_, err = io.Copy(out, in)
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}

	out, err = zipper(path.Join(hostname, MemoryProgressFileName))
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}
	in = r.reporter.MemoryScanProgressOut.(*os.File)
	_, err = in.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}
	_, err = io.Copy(out, in)
	if err != nil {
		return fmt.Errorf("could not write to zip file, reason: %w", err)
	}

	if r.reporter.DumpStorage != nil {
		if st, ok := r.reporter.DumpStorage.(ReadableDumpStorage); ok {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			for dump := range st.Retrieve(ctx) {
				if dump.Err != nil {
					return dump.Err
				}

				out, err := zipper(path.Join(hostname, "dumps", dump.Dump.Filename()))
				if err != nil {
					dump.Dump.Data.Close()
					return fmt.Errorf("could not write dump to zip file, reason: %w", err)
				}
				_, err = io.Copy(out, dump.Dump.Data)
				if err != nil {
					dump.Dump.Data.Close()
					return fmt.Errorf("could not write dump to zip file, reason: %w", err)
				}
				dump.Dump.Data.Close()
			}
		}
	}

	return nil
}

// Close creates the combined zip if GatheredAnalysisReporter.ZIP is set
// and closes the underlying *AnalysisReporter.
func (r *GatheredAnalysisReporter) Close() error {
	var err error

	err = r.reporter.Close()
	if err != nil {
		return err
	}

	if r.ZIP != "" {
		err = r.zip()
		if err != nil {
			return err
		}

		if r.DeleteAfterZipping {
			defer func() {
				err := os.RemoveAll(r.directory)
				if err != nil {
					fmt.Printf("Could not delete temporary directory \"%s\".\n", r.directory)
					logrus.WithFields(logrus.Fields{
						"dir":           r.directory,
						logrus.ErrorKey: err,
					}).Error("Could not delete temporary directory.")
				}
			}()
		}
	}

	return nil
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
