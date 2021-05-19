package yapscan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fkie-cad/yapscan/system"

	"github.com/yeka/zip"

	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
)

// RulesZIPPassword is the password yapscan uses to de-/encrypt the rules zip file.
const RulesZIPPassword = "infected"

// DefaultYaraRulesNamespace is the default namespace when compiling rules.
var DefaultYaraRulesNamespace = ""

// YaraRulesFileExtensions are the file extensions yapscan expects rules files to have.
// This is used when loading files from a directory.
var YaraRulesFileExtensions = []string{
	".yar",
	".yara",
}

type MemoryProfile struct {
	Time    time.Time `json:"time"`
	FreeRAM uintptr   `json:"freeRAM"`
}

// ScanningStatistics holds statistic information about a scan.
type ScanningStatistics struct {
	Start                    time.Time        `json:"start"`
	End                      time.Time        `json:"end"`
	NumberOfProcessesScanned uint64           `json:"numberOfProcessesScanned"`
	NumberOfSegmentsScanned  uint64           `json:"numberOfSegmentsScanned"`
	NumberOfBytesScanned     uint64           `json:"numberOfBytesScanned"`
	NumberOfFilesScanned     uint64           `json:"numberOfFilesScanned"`
	MemoryProfile            []*MemoryProfile `json:"memoryProfile"`

	mux          *sync.Mutex
	ctx          context.Context
	ctxCancel    context.CancelFunc
	profilerDone chan interface{}
}

func NewScanningStatistics() *ScanningStatistics {
	return &ScanningStatistics{
		Start: time.Now(),
		mux:   &sync.Mutex{},
	}
}

// StartMemoryProfiler starts a goroutine, regularly saving information about free memory.
func (s *ScanningStatistics) StartMemoryProfiler(ctx context.Context, scanInterval time.Duration) {
	s.MemoryProfile = make([]*MemoryProfile, 0, 16)
	s.ctx, s.ctxCancel = context.WithCancel(ctx)
	s.profilerDone = make(chan interface{})
	go func() {
		defer func() {
			s.profilerDone <- nil
			close(s.profilerDone)
		}()
		for {
			select {
			case <-s.ctx.Done():
				break
			case <-time.After(scanInterval):
				freeRAM, err := system.FreeRAM()
				if err != nil {
					continue
				}
				s.MemoryProfile = append(s.MemoryProfile, &MemoryProfile{
					Time:    time.Now(),
					FreeRAM: freeRAM,
				})
			}
		}
	}()
}

// IncrementFileCount increments the number of files scanned.
// This function is thread safe.
func (s *ScanningStatistics) IncrementFileCount() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.NumberOfFilesScanned++
}

// IncrementMemorySegmentsScanned increments the number of segments scanned as
// well as the number of bytes scanned.
// This function is thread safe.
func (s *ScanningStatistics) IncrementMemorySegmentsScanned(numOfBytes uint64) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.NumberOfSegmentsScanned++
	s.NumberOfBytesScanned += numOfBytes
}

// IncrementNumberOfProcessesScanned increments the number of scanned processes.
// This function is thread safe.
func (s *ScanningStatistics) IncrementNumberOfProcessesScanned() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.NumberOfProcessesScanned++
}

// Finalize finalizes the statistics, stopping the memory profile routine if its running.
// Use this function before processing the statistics further.
// This function is thread safe.
func (s *ScanningStatistics) Finalize() {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.ctxCancel != nil {
		s.ctxCancel()
		<-s.profilerDone
	}

	s.End = time.Now()
}

// YaraScanner is a wrapper for yara.Rules, with a more go-like interface.
type YaraScanner struct {
	rules Rules
	stats *ScanningStatistics
}

// Rules are a yara.Rules compatible interface, defining the functions required by yapscan.
// The choice of an interface over the concrete struct yara.Rules is mostly to make testing
// easier.
type Rules interface {
	ScanFile(filename string, flags yara.ScanFlags, timeout time.Duration, cb yara.ScanCallback) (err error)
	ScanMem(buf []byte, flags yara.ScanFlags, timeout time.Duration, cb yara.ScanCallback) (err error)
}

// NewYaraScanner creates a new YaraScanner from the given yara.Rules.
func NewYaraScanner(rules Rules) (*YaraScanner, error) {
	if rules == nil {
		return nil, fmt.Errorf("cannot create a yara scanner with nil rules")
	}
	return &YaraScanner{
		rules: rules,
		stats: NewScanningStatistics(),
	}, nil
}

// ScanFile scans the file with the given filename.
// This function simply calls ScanFile on the underlying yara.Rules object.
func (s *YaraScanner) ScanFile(filename string) ([]yara.MatchRule, error) {
	s.stats.IncrementFileCount()
	var matches yara.MatchRules
	err := s.rules.ScanFile(filename, 0, 0, &matches)
	return matches, err
}

// ScanMem scans the given buffer.
// This function simply calls ScanMem on the underlying yara.Rules object.
func (s *YaraScanner) ScanMem(buf []byte) ([]yara.MatchRule, error) {
	s.stats.IncrementMemorySegmentsScanned(uint64(len(buf)))
	var matches yara.MatchRules
	err := s.rules.ScanMem(buf, 0, 0, &matches)
	return matches, err
}

// Statistics returns the mutable statistics of the scanner.
func (s *YaraScanner) Statistics() *ScanningStatistics {
	return s.stats
}

// LoadYaraRules loads yara.Rules from a file (or files) and compiles if necessary.
// The given path can be a path to a directory, a compiled rules-file, a plain text
// file containing rules, or an encrypted zip file containing rules.
//
// If the path is a directory, all files with one of the file extensions in YaraRulesFileExtensions
// are loaded (recursively if recurseIfDir is true). All files are assumed to be
// uncompiled and will be compiled. Loading multiple already compiled files into one
// yara.Rules object is not supported.
// Each file will be compiled with the namespace equal to its filename, relative to
// the given path.
//
// If the path is a single file, it may be compiled, uncompiled or a zip file.
// An uncompiled file will be compiled with the namespace
// `DefaultYaraRulesNamespace+"/"+filename`. A zip file will be opened and decrypted
// with the RulesZIPPassword. The contents of the zip file will be treated similar to
// the way a directory is treated (see above), however *all* files are assumed to be
// rules-files, recursion is always enabled and there may be either a single compiled
// file or arbitrarily many uncompiled files in the zip.
func LoadYaraRules(path string, recurseIfDir bool) (*yara.Rules, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("could not stat file \"%s\", reason: %w", path, err)
	}
	if stat.IsDir() {
		return loadYaraRulesDirectory(path, recurseIfDir)
	}
	return loadYaraRulesSingleFile(path)
}

// IsYaraRulesFile returns true, if the given filename has one of the extensions
// in YaraRulesFileExtensions.
func IsYaraRulesFile(name string) bool {
	for _, ext := range YaraRulesFileExtensions {
		nLen := len(name)
		eLen := len(ext)
		if nLen < eLen {
			continue
		}
		if strings.ToLower(name[nLen-eLen:]) == ext {
			return true
		}
	}
	return false
}

func loadYaraRulesDirectory(rulesPath string, recurse bool) (*yara.Rules, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("could not create yara compiler, reason: %w", err)
	}

	compileFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if !IsYaraRulesFile(info.Name()) {
			return nil
		}

		namespace, err := filepath.Rel(rulesPath, path)
		if err != nil {
			namespace = path
		}
		namespace = filepath.ToSlash(namespace)

		file, err := os.OpenFile(path, os.O_RDONLY, 0666)
		if err != nil {
			return fmt.Errorf("could not open rules file \"%s\", reason: %w", path, err)
		}
		defer file.Close()

		err = compiler.AddFile(file, namespace)
		if err != nil {
			return fmt.Errorf("could not compile rules file \"%s\", reason: %w", path, err)
		}
		return nil
	}

	if recurse {
		err = filepath.Walk(rulesPath, compileFn)
		if err != nil {
			return nil, err
		}
	} else {
		f, err := os.Open(rulesPath)
		if err != nil {
			return nil, fmt.Errorf("could not read directory \"%s\", reason: %w", rulesPath, err)
		}
		names, err := f.Readdirnames(-1)
		if err != nil {
			return nil, fmt.Errorf("could not read directory \"%s\", reason: %w", rulesPath, err)
		}
		for _, name := range names {
			filename := filepath.Join(rulesPath, name)
			stat, err := os.Stat(filename)
			err = compileFn(filename, stat, err)
			if err != nil {
				return nil, err
			}
		}
	}

	return compiler.GetRules()
}

func loadCompiledRules(in io.Reader) (*yara.Rules, error) {
	logrus.Debug("Yara rules file contains compiled rules.")

	rules, err := yara.ReadRules(in)
	if err != nil {
		err = fmt.Errorf("could not read rules file, reason: %w", err)
	}
	return rules, err
}

func loadUncompiledRules(compiler *yara.Compiler, in io.Reader, name string) error {
	logrus.Debug("Yara rules file needs to be compiled.")

	data, err := ioutil.ReadAll(in)
	if err != nil {
		return fmt.Errorf("could not read yara rules, reason: %w", err)
	}
	err = compiler.AddString(string(data), DefaultYaraRulesNamespace+"/"+name)
	if err != nil {
		return fmt.Errorf("could not compile yara rules, reason: %w", err)
	}
	return nil
}

func loadZippedRules(in io.ReaderAt, size int64) (*yara.Rules, error) {
	zipRdr, err := zip.NewReader(in, size)
	if err != nil {
		return nil, fmt.Errorf("could not open zipped rules file, reason: %w", err)
	}

	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("could not intialize compiler")
	}
	// includes will not work in zips
	compiler.DisableIncludes()

	for _, file := range zipRdr.File {
		if file.IsEncrypted() {
			file.SetPassword(RulesZIPPassword)
		}
		if file.FileInfo().IsDir() {
			continue
		}

		f, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("could not read rules file in zip, reason: %w", err)
		}

		t, rdr, err := detectRuleType(f)
		switch t {
		case ruleTypeCompiled:
			if len(zipRdr.File) != 1 {
				return nil, fmt.Errorf("invalid rules zip, it must either contain a single compiled rules file or multiple *un*compiled rules files")
			}
			rules, err := loadCompiledRules(rdr)
			f.Close()
			return rules, err
		case ruleTypePlain:
			if !IsYaraRulesFile(file.Name) {
				continue
			}
			err = loadUncompiledRules(compiler, rdr, file.FileInfo().Name())
			f.Close()
			if err != nil {
				return nil, err
			}
		default:
			f.Close()
			return nil, fmt.Errorf("invalid rules zip, it cannot contain other zip files")
		}
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("could not compile rules in zip, reason: %w", err)
	}

	return rules, nil
}

type ruleType int

const (
	ruleTypeCompiled ruleType = iota
	ruleTypeZipped
	ruleTypePlain
)

func detectRuleType(in io.Reader) (ruleType, io.Reader, error) {
	buff := make([]byte, 4)
	_, err := io.ReadFull(in, buff)
	if err != nil {
		return 0, in, fmt.Errorf("could not read rules file, reason: %w", err)
	}

	inWithMagic := io.MultiReader(bytes.NewReader(buff), in)

	if bytes.Equal(buff, []byte("YARA")) {
		return ruleTypeCompiled, inWithMagic, nil
	} else if bytes.Equal(buff, []byte("PK\x03\x04")) {
		return ruleTypeZipped, inWithMagic, nil
	} else {
		// Uncompiled rules are just plain text without magic number
		return ruleTypePlain, inWithMagic, nil
	}
}

func loadYaraRulesSingleFile(path string) (*yara.Rules, error) {
	rulesFile, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("could not open rules file, reason: %w", err)
	}
	defer rulesFile.Close()

	var t ruleType
	t, _, err = detectRuleType(rulesFile)
	if err != nil {
		return nil, fmt.Errorf("could not determine rules type, reason: %w", err)
	}
	_, err = rulesFile.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("could not determine rules type, reason: %w", err)
	}

	switch t {
	case ruleTypePlain:
		compiler, err := yara.NewCompiler()
		if err != nil {
			return nil, fmt.Errorf("could not create yara compiler, reason: %w", err)
		}
		err = loadUncompiledRules(compiler, rulesFile, rulesFile.Name())
		if err != nil {
			return nil, err
		}
		rules, err := compiler.GetRules()
		if err != nil {
			err = fmt.Errorf("could not compile yara rules, reason: %w", err)
		}
		return rules, err
	case ruleTypeZipped:
		s, err := rulesFile.Stat()
		if err != nil {
			return nil, fmt.Errorf("could not stat file \"%s\", reason: %w", rulesFile.Name(), err)
		}
		return loadZippedRules(rulesFile, s.Size())
	case ruleTypeCompiled:
		return loadCompiledRules(rulesFile)
	}

	panic("invalid rules type, this should never happen")
}
