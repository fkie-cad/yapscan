package yapscan

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/yeka/zip"

	"github.com/hillu/go-yara/v4"
	"github.com/sirupsen/logrus"
)

const RulesZIPPassword = "infected"

var DefaultYaraRulesNamespace = ""
var YaraRulesFileExtensions = []string{
	".yar",
	".yara",
}

type YaraScanner struct {
	rules *yara.Rules
}

func NewYaraScanner(rules *yara.Rules) (*YaraScanner, error) {
	return &YaraScanner{rules}, nil
}

func (s *YaraScanner) ScanFile(filename string) ([]yara.MatchRule, error) {
	var matches yara.MatchRules
	err := s.rules.ScanFile(filename, 0, 0, &matches)
	return matches, err
}

func (s *YaraScanner) ScanMem(buf []byte) ([]yara.MatchRule, error) {
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
