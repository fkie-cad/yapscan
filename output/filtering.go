package output

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/fkie-cad/yapscan/procio"

	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/fkie-cad/yapscan/system"
	"github.com/hillu/go-yara/v4"
)

type Filter interface {
	Chain(f Filter) Filter

	FilterSystemInfo(info *system.Info) *system.Info
	FilterRules(rules *yara.Rules) *yara.Rules
	FilterMemoryScanProgress(scan *yapscan.MemoryScanProgress) *yapscan.MemoryScanProgress
	FilterFSScanProgress(scan *fileio.FSScanProgress) *fileio.FSScanProgress
}

type FilteringReporter struct {
	Reporter Reporter
	Filter   Filter
}

func (r *FilteringReporter) ReportSystemInfo(info *system.Info) error {
	info = r.Filter.FilterSystemInfo(info)
	if info == nil {
		return nil
	}
	return r.Reporter.ReportSystemInfo(info)
}

func (r *FilteringReporter) ReportRules(rules *yara.Rules) error {
	rules = r.Filter.FilterRules(rules)
	if rules == nil {
		return nil
	}
	return r.Reporter.ReportRules(rules)
}

func (r *FilteringReporter) ReportScanningStatistics(stats *yapscan.ScanningStatistics) error {
	return r.Reporter.ReportScanningStatistics(stats)
}

func (r *FilteringReporter) ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error {
	c := make(chan *yapscan.MemoryScanProgress)

	go func() {
		defer close(c)

		for scan := range progress {
			scan = r.Filter.FilterMemoryScanProgress(scan)
			if scan == nil {
				continue
			}
			c <- scan
		}
	}()

	return r.Reporter.ConsumeMemoryScanProgress(c)
}

func (r *FilteringReporter) ConsumeFSScanProgress(progress <-chan *fileio.FSScanProgress) error {
	c := make(chan *fileio.FSScanProgress)

	go func() {
		defer close(c)

		for scan := range progress {
			scan = r.Filter.FilterFSScanProgress(scan)
			if scan == nil {
				continue
			}
			c <- scan
		}
	}()

	return r.Reporter.ConsumeFSScanProgress(c)
}

func (r *FilteringReporter) Close() error {
	return r.Reporter.Close()
}

type chainedFilter struct {
	chain []Filter
}

func chain(f1, f2 Filter) Filter {
	return &chainedFilter{
		chain: []Filter{f1, f2},
	}
}

func (c *chainedFilter) Chain(f Filter) Filter {
	return &chainedFilter{
		chain: append(c.chain, f),
	}
}

func (c *chainedFilter) FilterSystemInfo(info *system.Info) *system.Info {
	for _, f := range c.chain {
		info = f.FilterSystemInfo(info)
		if info == nil {
			return nil
		}
	}
	return info
}

func (c *chainedFilter) FilterRules(rules *yara.Rules) *yara.Rules {
	for _, f := range c.chain {
		rules = f.FilterRules(rules)
		if rules == nil {
			return nil
		}
	}
	return rules
}

func (c *chainedFilter) FilterMemoryScanProgress(scan *yapscan.MemoryScanProgress) *yapscan.MemoryScanProgress {
	for _, f := range c.chain {
		scan = f.FilterMemoryScanProgress(scan)
		if scan == nil {
			return nil
		}
	}
	return scan
}

func (c *chainedFilter) FilterFSScanProgress(scan *fileio.FSScanProgress) *fileio.FSScanProgress {
	for _, f := range c.chain {
		scan = f.FilterFSScanProgress(scan)
		if scan == nil {
			return nil
		}
	}
	return scan
}

// NOPFilter is a filter that does nothing.
// Any FilteringReporter which uses this behave as an unfiltered Reporter.
type NOPFilter struct{}

func (c *NOPFilter) Chain(f Filter) Filter {
	return f
}

func (c *NOPFilter) FilterSystemInfo(info *system.Info) *system.Info {
	return info
}

func (c *NOPFilter) FilterRules(rules *yara.Rules) *yara.Rules {
	return rules
}

func (c *NOPFilter) FilterMemoryScanProgress(scan *yapscan.MemoryScanProgress) *yapscan.MemoryScanProgress {
	return scan
}

func (c *NOPFilter) FilterFSScanProgress(scan *fileio.FSScanProgress) *fileio.FSScanProgress {
	return scan
}

type NoEmptyScansFilter struct{}

func (f *NoEmptyScansFilter) Chain(other Filter) Filter {
	return chain(f, other)
}

func (f *NoEmptyScansFilter) FilterSystemInfo(info *system.Info) *system.Info {
	return info
}

func (f *NoEmptyScansFilter) FilterRules(rules *yara.Rules) *yara.Rules {
	return rules
}

func (f *NoEmptyScansFilter) FilterMemoryScanProgress(scan *yapscan.MemoryScanProgress) *yapscan.MemoryScanProgress {
	if scan.Error == nil && (scan.Matches == nil || len(scan.Matches) == 0) {
		logrus.WithField("segment", scan.MemorySegment).Info("Filtering empty scan result.")
		return nil
	}
	return scan
}

func (f *NoEmptyScansFilter) FilterFSScanProgress(scan *fileio.FSScanProgress) *fileio.FSScanProgress {
	if scan.Error == nil && (scan.Matches == nil || len(scan.Matches) == 0) {
		logrus.WithField("file", scan.File.Path()).Info("Filtering empty scan result.")
		return nil
	}
	return scan
}

type Anonymizer struct {
	homeDirectoryParent string
	fsIsCaseSensitive   bool
	Salt                []byte
}

func NewAnonymizer(salt []byte) *Anonymizer {
	var homeDirectoryParent string
	var fsIsCaseSensitive bool
	if runtime.GOOS == "windows" {
		homeDirectoryParent = "users"
		fsIsCaseSensitive = true
	} else {
		homeDirectoryParent = "home"
		fsIsCaseSensitive = false
	}
	return &Anonymizer{
		homeDirectoryParent: homeDirectoryParent,
		fsIsCaseSensitive:   fsIsCaseSensitive,
		Salt:                salt,
	}
}

func (a *Anonymizer) Anonymize(data string) string {
	hash := sha256.New()
	hash.Write(a.Salt)
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

func (a *Anonymizer) AnonymizeCaseInsensitive(data string) string {
	return a.Anonymize(strings.ToLower(data))
}

func (a *Anonymizer) AnonymizePath(path string) string {
	if path == "" {
		return path
	}
	if a.fsIsCaseSensitive {
		path = strings.ToLower(path)
	}

	path = filepath.FromSlash(path)
	elements := strings.Split(filepath.Clean(path), string(filepath.Separator))
	lastWasHomeDirParent := false
	for i := range elements {
		if lastWasHomeDirParent {
			elements[i] = a.Anonymize(elements[i])
		}

		lastWasHomeDirParent = elements[i] == a.homeDirectoryParent
	}
	result := filepath.Join(elements...)
	if path[0] == filepath.Separator {
		result = string(filepath.Separator) + result
	}
	return result
}

func (a *Anonymizer) AnonymizeMemorySegment(segment *procio.MemorySegmentInfo) *procio.MemorySegmentInfo {
	return &procio.MemorySegmentInfo{
		ParentBaseAddress:    segment.ParentBaseAddress,
		BaseAddress:          segment.BaseAddress,
		AllocatedPermissions: segment.AllocatedPermissions,
		CurrentPermissions:   segment.CurrentPermissions,
		Size:                 segment.Size,
		State:                segment.State,
		Type:                 segment.Type,
		FilePath:             a.AnonymizePath(segment.FilePath),
		SubSegments:          a.AnonymizeMemorySegments(segment.SubSegments),
	}
}

func (a *Anonymizer) AnonymizeMemorySegments(segments []*procio.MemorySegmentInfo) []*procio.MemorySegmentInfo {
	anon := make([]*procio.MemorySegmentInfo, len(segments))
	for i := range segments {
		anon[i] = &procio.MemorySegmentInfo{
			ParentBaseAddress:    segments[i].ParentBaseAddress,
			BaseAddress:          segments[i].BaseAddress,
			AllocatedPermissions: segments[i].AllocatedPermissions,
			CurrentPermissions:   segments[i].CurrentPermissions,
			Size:                 segments[i].Size,
			State:                segments[i].State,
			Type:                 segments[i].Type,
			FilePath:             a.AnonymizePath(segments[i].FilePath),
			SubSegments:          a.AnonymizeMemorySegments(segments[i].SubSegments),
		}
	}
	return anon
}

type AnonymizingFilter struct {
	Anonymizer *Anonymizer
}

func NewAnonymizingFilter(salt []byte) *AnonymizingFilter {
	return &AnonymizingFilter{Anonymizer: NewAnonymizer(salt)}
}

func NewAnonymizingFilterWithRandomSalt(saltLength int) (*AnonymizingFilter, error) {
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return NewAnonymizingFilter(salt), nil
}

func (f *AnonymizingFilter) Chain(other Filter) Filter {
	return chain(f, other)
}

func (f *AnonymizingFilter) FilterSystemInfo(info *system.Info) *system.Info {
	info.Hostname = f.Anonymizer.AnonymizeCaseInsensitive(info.Hostname)
	for i := range info.IPs {
		info.IPs[i] = f.Anonymizer.AnonymizeCaseInsensitive(info.IPs[i])
	}
	return info
}

func (f *AnonymizingFilter) FilterRules(rules *yara.Rules) *yara.Rules {
	return rules
}

func (f *AnonymizingFilter) FilterMemoryScanProgress(scan *yapscan.MemoryScanProgress) *yapscan.MemoryScanProgress {
	return &yapscan.MemoryScanProgress{
		Process: procio.Cache(&anonymizedProcess{
			orig:       scan.Process,
			anonymizer: f.Anonymizer,
		}),
		MemorySegment: &procio.MemorySegmentInfo{
			ParentBaseAddress:    scan.MemorySegment.ParentBaseAddress,
			BaseAddress:          scan.MemorySegment.BaseAddress,
			AllocatedPermissions: scan.MemorySegment.AllocatedPermissions,
			CurrentPermissions:   scan.MemorySegment.CurrentPermissions,
			Size:                 scan.MemorySegment.Size,
			State:                scan.MemorySegment.State,
			Type:                 scan.MemorySegment.Type,
			FilePath:             f.Anonymizer.AnonymizePath(scan.MemorySegment.FilePath),
			SubSegments:          f.Anonymizer.AnonymizeMemorySegments(scan.MemorySegment.SubSegments),
		},
		Dump:    nil,
		Matches: scan.Matches,
		Error:   scan.Error,
	}
}

func (f *AnonymizingFilter) FilterFSScanProgress(scan *fileio.FSScanProgress) *fileio.FSScanProgress {
	scan.File = newAnonymizedFile(f.Anonymizer.AnonymizePath(scan.File.Path()), scan.File)
	return scan
}

type anonymizedFile struct {
	path    string
	stat    os.FileInfo
	statErr error
}

func newAnonymizedFile(anonPath string, f fileio.File) fileio.File {
	stat, err := f.Stat()
	return &anonymizedFile{
		path:    anonPath,
		stat:    stat,
		statErr: err,
	}
}

func (f *anonymizedFile) Path() string {
	return f.path
}

func (f *anonymizedFile) Stat() (os.FileInfo, error) {
	return f.stat, f.statErr
}

type anonymizedProcess struct {
	orig       procio.Process
	anonymizer *Anonymizer
}

func (p *anonymizedProcess) Close() error {
	return p.orig.Close()
}

func (p *anonymizedProcess) String() string {
	return p.orig.String()
}

func (p *anonymizedProcess) PID() int {
	return p.orig.PID()
}

func (p *anonymizedProcess) Info() (*procio.ProcessInfo, error) {
	info, err := p.orig.Info()
	if info == nil {
		return nil, err
	}
	anonInfo := &procio.ProcessInfo{
		PID:              info.PID,
		Bitness:          info.Bitness,
		ExecutablePath:   p.anonymizer.AnonymizePath(info.ExecutablePath),
		ExecutableMD5:    info.ExecutableMD5,
		ExecutableSHA256: info.ExecutableSHA256,
		Username:         p.anonymizer.AnonymizeCaseInsensitive(info.Username),
		MemorySegments:   p.anonymizer.AnonymizeMemorySegments(info.MemorySegments),
	}
	return anonInfo, err
}

func (p *anonymizedProcess) Handle() interface{} {
	return p.Handle()
}

func (p *anonymizedProcess) MemorySegments() ([]*procio.MemorySegmentInfo, error) {
	segments, err := p.orig.MemorySegments()
	if segments != nil {
		segments = p.anonymizer.AnonymizeMemorySegments(segments)
	}
	return segments, err
}

func (p *anonymizedProcess) Suspend() error {
	return p.Suspend()
}

func (p *anonymizedProcess) Resume() error {
	return p.Resume()
}

func (p *anonymizedProcess) Crash(method procio.CrashMethod) error {
	return p.Crash(method)
}
