package yapscan

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
)

var DefaultYaraRulesNamespace = ""
var YaraRulesFileExtensions = []string{
	".yar",
	".yara",
}

type MemoryScanner interface {
	ScanMem(buf []byte) (results []yara.MatchRule, err error)
}

type yaraScanner struct {
	rules *yara.Rules
}

func NewYaraMemoryScanner(rules *yara.Rules) (MemoryScanner, error) {
	return &yaraScanner{rules}, nil
}

func (s *yaraScanner) ScanMem(buf []byte) ([]yara.MatchRule, error) {
	var matches yara.MatchRules
	err := s.rules.ScanMem(buf, 0, 0, &matches)
	return matches, err
}

func LoadYaraRules(path string, recurseIfDir bool) (*yara.Rules, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("could not stat file \"%s\", reason: %w", path, err)
	}
	if stat.IsDir() {
		return loadYaraRulesDirectory(path, recurseIfDir)
	} else {
		return loadYaraRulesSingleFile(path)
	}
}

func IsYaraRulesFile(name string) bool {
	for _, ext := range YaraRulesFileExtensions {
		nLen := len(name)
		eLen := len(ext)
		if nLen < eLen {
			continue
		}
		if name[nLen-eLen:] == ext {
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

func loadYaraRulesSingleFile(path string) (*yara.Rules, error) {
	rulesFile, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("could not open rules file, reason: %w", err)
	}
	defer rulesFile.Close()

	buff := make([]byte, 4)
	_, err = io.ReadFull(rulesFile, buff)
	if err != nil {
		return nil, fmt.Errorf("could not read rules file, reason: %w", err)
	}
	rulesFile.Seek(0, io.SeekStart)

	if bytes.Equal(buff, []byte("YARA")) {
		logrus.Debug("Yara rules file contains compiled rules.")

		rules, err := yara.ReadRules(rulesFile)
		if err != nil {
			err = fmt.Errorf("could not read rules file, reason: %w", err)
		}
		return rules, err
	} else {
		logrus.Debug("Yara rules file needs to be compiled.")

		compiler, err := yara.NewCompiler()
		if err != nil {
			return nil, fmt.Errorf("could not create yara compiler, reason: %w", err)
		}
		err = compiler.AddFile(rulesFile, DefaultYaraRulesNamespace)
		if err != nil {
			return nil, fmt.Errorf("could not compile yara rules, reason: %w", err)
		}

		rules, err := compiler.GetRules()
		if err != nil {
			err = fmt.Errorf("could not compile yara rules, reason: %w", err)
		}
		return rules, err
	}
}
