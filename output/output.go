package output

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"fraunhofer/fkie/yapscan"
	"fraunhofer/fkie/yapscan/fileIO"
	"fraunhofer/fkie/yapscan/procIO"
	"fraunhofer/fkie/yapscan/system"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
	"github.com/targodan/go-errors"
	"github.com/yeka/zip"
)

type Reporter interface {
	ReportSystemInfo() error
	ReportRules(rules *yara.Rules) error
	ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error
	ConsumeFSScanProgress(progress <-chan *fileIO.FSScanProgress) error
	io.Closer
}

const SystemInfoFileName = "systeminfo.json"
const RulesFileName = "rules.yarc"
const ProcessFileName = "processes.json"
const MemoryProgressFileName = "memory-scans.json"
const FSProgressFileName = "file-scans.json"

const DefaultZIPPassword = "infected"

type MultiReporter struct {
	Reporters []Reporter
}

func (r *MultiReporter) ReportSystemInfo() error {
	var err error
	for _, rep := range r.Reporters {
		err = errors.NewMultiError(err, rep.ReportSystemInfo())
	}
	return err
}

func (r *MultiReporter) ReportRules(rules *yara.Rules) error {
	var err error
	for _, rep := range r.Reporters {
		err = errors.NewMultiError(err, rep.ReportRules(rules))
	}
	return err
}

func (r *MultiReporter) ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error {
	wg := &sync.WaitGroup{}
	chans := make([]chan *yapscan.MemoryScanProgress, len(r.Reporters))
	wg.Add(len(chans))
	for i := range chans {
		chans[i] = make(chan *yapscan.MemoryScanProgress)

		go func(i int) {
			r.Reporters[i].ConsumeMemoryScanProgress(chans[i])
			wg.Done()
		}(i)
	}
	for prog := range progress {
		for i := range chans {
			chans[i] <- prog
		}
	}
	for i := range chans {
		close(chans[i])
	}
	wg.Wait()
	return nil
}

func (r *MultiReporter) ConsumeFSScanProgress(progress <-chan *fileIO.FSScanProgress) error {
	wg := &sync.WaitGroup{}
	chans := make([]chan *fileIO.FSScanProgress, len(r.Reporters))
	wg.Add(len(chans))
	for i := range chans {
		chans[i] = make(chan *fileIO.FSScanProgress)

		go func(i int) {
			r.Reporters[i].ConsumeFSScanProgress(chans[i])
			wg.Done()
		}(i)
	}
	for prog := range progress {
		for i := range chans {
			chans[i] <- prog
		}
	}
	for i := range chans {
		close(chans[i])
	}
	wg.Wait()
	return nil
}

func (r *MultiReporter) Close() error {
	var err error
	for _, rep := range r.Reporters {
		err = errors.NewMultiError(err, rep.Close())
	}
	return err
}

type GatheredAnalysisReporter struct {
	directory string
	// If ZIP is set, the output files will be zipped into the
	// specified ZIP file.
	ZIP                string
	ZIPPassword        string
	DeleteAfterZipping bool
	reporter           *AnalysisReporter
}

func isDirEmpty(dir string) (bool, error) {
	fInfo, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(dir, 0777)
			return true, nil
		} else {
			return false, err
		}
	} else {
		if !fInfo.IsDir() {
			return false, errors.New("path is not a directory")
		}

		contents, err := filepath.Glob(path.Join(dir, "*"))
		if err != nil {
			return false, err
		}
		return len(contents) == 0, nil
	}
}

func NewGatheredAnalysisReporter(outPath string) (*GatheredAnalysisReporter, error) {
	isEmpty, err := isDirEmpty(outPath)
	if err != nil {
		return nil, errors.Errorf("could not determine if analysis directory is empty, reason: %w", err)
	}
	if !isEmpty {
		return nil, errors.New("analysis output directory is not empty")
	}

	sysinfo, err := os.OpenFile(path.Join(outPath, SystemInfoFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, errors.Errorf("could not open systeminfo file, reason: %w", err)
	}
	rules, err := os.OpenFile(path.Join(outPath, RulesFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, errors.Errorf("could not open rules file, reason: %w", err)
	}
	process, err := os.OpenFile(path.Join(outPath, ProcessFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, errors.Errorf("could not open processes file, reason: %w", err)
	}
	memProgress, err := os.OpenFile(path.Join(outPath, MemoryProgressFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, errors.Errorf("could not open memory progress file, reason: %w", err)
	}
	fileProgress, err := os.OpenFile(path.Join(outPath, FSProgressFileName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, errors.Errorf("could not open filesystem progress file, reason: %w", err)
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

func (r *GatheredAnalysisReporter) WithFileDumpStorage(outPath string) (err error) {
	r.reporter.DumpStorage, err = NewFileDumpStorage(path.Join(r.directory, outPath))
	return
}

func (r *GatheredAnalysisReporter) ReportSystemInfo() error {
	return r.reporter.ReportSystemInfo()
}

func (r *GatheredAnalysisReporter) ReportRules(rules *yara.Rules) error {
	return r.reporter.ReportRules(rules)
}

func (r *GatheredAnalysisReporter) ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error {
	return r.reporter.ConsumeMemoryScanProgress(progress)
}

func (r *GatheredAnalysisReporter) ConsumeFSScanProgress(progress <-chan *fileIO.FSScanProgress) error {
	return r.reporter.ConsumeFSScanProgress(progress)
}

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
		return errors.Errorf("could not create zip file, reason: %w", err)
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
		return errors.Errorf("could not write to zip file, reason: %w", err)
	}
	in = r.reporter.SystemInfoOut.(*os.File)
	_, err = in.Seek(0, io.SeekStart)
	if err != nil {
		return errors.Errorf("could not write to zip file, reason: %w", err)
	}
	_, err = io.Copy(out, in)
	if err != nil {
		return errors.Errorf("could not write to zip file, reason: %w", err)
	}

	out, err = zipper(path.Join(hostname, RulesFileName))
	if err != nil {
		return errors.Errorf("could not write to zip file, reason: %w", err)
	}
	in = r.reporter.RulesOut.(*os.File)
	_, err = in.Seek(0, io.SeekStart)
	if err != nil {
		return errors.Errorf("could not write to zip file, reason: %w", err)
	}
	_, err = io.Copy(out, in)
	if err != nil {
		return errors.Errorf("could not write to zip file, reason: %w", err)
	}

	out, err = zipper(path.Join(hostname, ProcessFileName))
	if err != nil {
		return errors.Errorf("could not write to zip file, reason: %w", err)
	}
	in = r.reporter.ProcessInfoOut.(*os.File)
	_, err = in.Seek(0, io.SeekStart)
	if err != nil {
		return errors.Errorf("could not write to zip file, reason: %w", err)
	}
	_, err = io.Copy(out, in)
	if err != nil {
		return errors.Errorf("could not write to zip file, reason: %w", err)
	}

	out, err = zipper(path.Join(hostname, MemoryProgressFileName))
	if err != nil {
		return errors.Errorf("could not write to zip file, reason: %w", err)
	}
	in = r.reporter.MemoryScanProgressOut.(*os.File)
	_, err = in.Seek(0, io.SeekStart)
	if err != nil {
		return errors.Errorf("could not write to zip file, reason: %w", err)
	}
	_, err = io.Copy(out, in)
	if err != nil {
		return errors.Errorf("could not write to zip file, reason: %w", err)
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
					return errors.Errorf("could not write dump to zip file, reason: %w", err)
				}
				_, err = io.Copy(out, dump.Dump.Data)
				if err != nil {
					dump.Dump.Data.Close()
					return errors.Errorf("could not write dump to zip file, reason: %w", err)
				}
				dump.Dump.Data.Close()
			}
		}
	}

	return nil
}

func (r *GatheredAnalysisReporter) Close() error {
	var err error

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

	err = r.reporter.Close()
	if err != nil {
		return err
	}
	return nil
}

func tryFlush(w io.Writer) error {
	if w == nil {
		return nil
	}
	if syncable, ok := w.(interface {
		Sync() error
	}); ok {
		return syncable.Sync()
	}
	if flushable, ok := w.(interface {
		Flush() error
	}); ok {
		return flushable.Flush()
	}
	return nil
}

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

func FilterMatches(mr []yara.MatchRule) []*Match {
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

type MemoryScanProgressReport struct {
	PID           int      `json:"pid"`
	MemorySegment uintptr  `json:"memorySegment"`
	Matches       []*Match `json:"match"`
	Error         error    `json:"error"`
}

type FSScanProgressReport struct {
	Path    string   `json:"path"`
	Matches []*Match `json:"match"`
	Error   error    `json:"error"`
}

// AnalysisReporter implements a Reporter, which is
// specifically intended for later analysis of the report
// in order to determine rule quality.
type AnalysisReporter struct {
	SystemInfoOut         io.WriteCloser
	RulesOut              io.WriteCloser
	ProcessInfoOut        io.WriteCloser
	MemoryScanProgressOut io.WriteCloser
	FSScanProgressOut     io.WriteCloser
	DumpStorage           DumpStorage

	seen map[int]bool
}

func (r *AnalysisReporter) ReportSystemInfo() error {
	if r.SystemInfoOut == nil {
		return nil
	}

	info, err := system.GetInfo()
	if err != nil {
		return err
	}
	err = json.NewEncoder(r.SystemInfoOut).Encode(info)
	if err != nil {
		return err
	}

	// This is only called once, so we might want to flush any buffers if possible
	err = tryFlush(r.SystemInfoOut)
	if err != nil {
		logrus.WithError(err).Error("Trying to sync/flush the SystemInfoOut failed.")
	}
	return nil
}

func (r *AnalysisReporter) ReportRules(rules *yara.Rules) error {
	if r.RulesOut == nil {
		return nil
	}
	err := rules.Write(r.RulesOut)
	if err != nil {
		return err
	}

	// This is only called once, so we might want to flush any buffers if possible
	err = tryFlush(r.RulesOut)
	if err != nil {
		logrus.WithError(err).Error("Trying to sync/flush the RulesOut failed.")
	}
	return nil
}

func (r *AnalysisReporter) reportProcess(info *procIO.ProcessInfo) error {
	if r.ProcessInfoOut == nil {
		return nil
	}

	return json.NewEncoder(r.ProcessInfoOut).Encode(info)
}

func (r *AnalysisReporter) ConsumeMemoryScanProgress(progress <-chan *yapscan.MemoryScanProgress) error {
	if r.seen == nil {
		r.seen = make(map[int]bool)
	}

	for prog := range progress {
		info, err := prog.Process.Info()
		if err != nil {
			logrus.WithError(err).Warn("Could not retrieve complete process info.")
		}
		_, seen := r.seen[info.PID]
		if !seen {
			r.seen[info.PID] = true
			err = r.reportProcess(info)
			if err != nil {
				logrus.WithError(err).Error("Could not report process info.")
			}
		}

		err = json.NewEncoder(r.MemoryScanProgressOut).Encode(&MemoryScanProgressReport{
			PID:           info.PID,
			MemorySegment: prog.MemorySegment.BaseAddress,
			Matches:       FilterMatches(prog.Matches),
			Error:         prog.Error,
		})
		if err != nil {
			logrus.WithError(err).Error("Could not report progress.")
		}
		if r.DumpStorage != nil && prog.Error == nil && prog.Matches != nil && len(prog.Matches) > 0 {
			err = r.DumpStorage.Store(&Dump{
				PID:     info.PID,
				Segment: prog.MemorySegment,
				Data:    ioutil.NopCloser(bytes.NewReader(prog.Dump)),
			})
			if err != nil {
				logrus.WithError(err).Error("Could not store dump.")
			}
		}
	}
	return nil
}

func (r *AnalysisReporter) ConsumeFSScanProgress(progress <-chan *fileIO.FSScanProgress) error {
	if r.seen == nil {
		r.seen = make(map[int]bool)
	}

	for prog := range progress {
		err := json.NewEncoder(r.FSScanProgressOut).Encode(&FSScanProgressReport{
			Path:    prog.File.Path(),
			Matches: FilterMatches(prog.Matches),
			Error:   prog.Error,
		})
		if err != nil {
			logrus.WithError(err).Error("Could not report progress.")
		}
		// TODO: Maybe add dumping capability by copying the offending file.
	}
	return nil
}

func (r *AnalysisReporter) Close() error {
	var err error
	err = errors.NewMultiError(err, r.SystemInfoOut.Close())
	err = errors.NewMultiError(err, r.ProcessInfoOut.Close())
	err = errors.NewMultiError(err, r.RulesOut.Close())
	err = errors.NewMultiError(err, r.MemoryScanProgressOut.Close())
	err = errors.NewMultiError(err, r.FSScanProgressOut.Close())
	return err
}

type progressReporter struct {
	out       io.WriteCloser
	formatter ProgressFormatter

	pid              int
	procMatched      bool
	procSegmentCount int
	procSegmentIndex int
	allClean         bool
}

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

func (r *progressReporter) reportProcess(proc procIO.Process) error {
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

	if progress.Matches != nil && len(progress.Matches) > 0 {
		r.procMatched = true
		r.allClean = false
	}

	matchOut := r.formatter.FormatMemoryScanProgress(progress)
	if matchOut != "" {
		fmt.Fprintln(r.out, "\r", matchOut)
	}

	r.procSegmentIndex += 1
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

func (r *progressReporter) receiveFS(progress *fileIO.FSScanProgress) {
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

func (r *progressReporter) ConsumeFSScanProgress(progress <-chan *fileIO.FSScanProgress) error {
	for prog := range progress {
		r.receiveFS(prog)
	}
	fmt.Sprintln(r.out)
	return nil
}

type ProgressFormatter interface {
	FormatMemoryScanProgress(progress *yapscan.MemoryScanProgress) string
	FormatFSScanProgress(progress *fileIO.FSScanProgress) string
	FormatPath(path string, maxlen int) string
}

type prettyFormatter struct{}

func NewPrettyFormatter() ProgressFormatter {
	return &prettyFormatter{}
}

func (p prettyFormatter) FormatMemoryScanProgress(progress *yapscan.MemoryScanProgress) string {
	if progress.Error != nil {
		msg := ""
		// TODO: Maybe enable via a verbose flag
		//if progress.Error == ErrSkipped {
		//	msg = "Skipped " + procIO.FormatMemorySegmentAddress(progress.MemorySegment)
		//} else {
		//	msg = "Error during scan of segment " + procIO.FormatMemorySegmentAddress(progress.MemorySegment) + ": " + progress.Error.Error()
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
			match.Rule, procIO.FormatMemorySegmentAddress(progress.MemorySegment),
		)
		if len(match.Strings) > 0 {
			addrs := yapscan.FormatSlice("0x%X", yapscan.AddressesFromMatches(match.Strings, uint64(progress.MemorySegment.BaseAddress)))
			txt[i] += fmt.Sprintf("\n\tRule-strings matched at %s.", yapscan.Join(addrs, ", ", " and "))
		}
	}
	return strings.Join(txt, "\n")
}

func (p prettyFormatter) FormatPath(path string, maxlen int) string {
	if len(path) <= maxlen {
		return path
	}
	parts := strings.Split(path, fmt.Sprintf("%c", filepath.Separator))
	res := parts[0]
	if len(parts) == 1 {
		return "..." + res[len(res)-maxlen-3:]
	}
	if len(parts) == 2 {
		return filepath.Join(res, parts[1][len(parts[1])-len(res)-1-maxlen-3:])
	}
	// TODO: This needs improvement.
	res = filepath.Join(res, "...", parts[len(parts)-1])
	if len(res) <= maxlen {
		return res
	}
	dir, file := filepath.Split(res)
	if len(dir) < maxlen {
		return filepath.Join(dir, file[len(file)-1-maxlen:])
	}
	return "..." + res[len(res)-maxlen-3:]
}

func (p prettyFormatter) FormatFSScanProgress(progress *fileIO.FSScanProgress) string {
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
