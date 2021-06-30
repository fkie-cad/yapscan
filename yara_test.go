package yapscan

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/yeka/zip"

	"github.com/hillu/go-yara/v4"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/mock"
)

func testDataDir(path ...string) string {
	path = append([]string{"testdata", "yara"}, path...)
	return filepath.Join(path...)
}

func TestNewYaraScanner(t *testing.T) {
	Convey("Creating a new yara scanner", t, func() {
		Convey("with a nil argument should fail.", func() {
			ys, err := NewYaraScanner(nil)
			So(ys, ShouldBeNil)
			So(err, ShouldNotBeNil)
		})
		Convey("with a non-nil argument should be successful.", func() {
			ys, err := NewYaraScanner(&yara.Rules{})
			So(ys, ShouldNotBeNil)
			So(err, ShouldBeNil)
		})
	})
}

func TestYaraScannerDelegatedMethods(t *testing.T) {
	mockedRules := new(MockRules)
	defer mockedRules.AssertExpectations(t)

	Convey("A YaraScanner", t, func() {
		ys, _ := NewYaraScanner(mockedRules)

		Convey("should pass a ScanFile call on to the underlying scanner", func() {
			filename := "some filename"
			expextedErr := errors.New("some error")
			mockedRules.
				On("ScanFile", filename, yara.ScanFlags(0), time.Duration(0), mock.Anything).
				Return(expextedErr).
				Once()

			_, err := ys.ScanFile(filename)

			Convey("and return any errors.", func() {
				So(err, ShouldEqual, expextedErr)
			})
		})

		Convey("should pass a ScanMem call on to the underlying scanner", func() {
			buf := []byte("some data")
			expextedErr := errors.New("some error")
			mockedRules.
				On("ScanMem", buf, yara.ScanFlags(0), time.Duration(0), mock.Anything).
				Return(expextedErr).
				Once()

			_, err := ys.ScanMem(buf)

			Convey("and return any errors.", func() {
				So(err, ShouldEqual, expextedErr)
			})
		})
	})
}

func TestIsYaraRulesFile(t *testing.T) {
	Convey("Files with any extension in YaraRulesFileExtensions", t, func() {
		files := make([]string, 0)
		for _, ext := range YaraRulesFileExtensions {
			files = append(files, "someFile"+ext)
		}
		Convey("should be matched.", func() {
			for _, file := range files {
				So(IsYaraRulesFile(file), ShouldBeTrue)
			}
		})
	})

	Convey("Files with any extension in YaraRulesFileExtensions (other case)", t, func() {
		files := make([]string, 0)
		for _, ext := range YaraRulesFileExtensions {
			files = append(files, "someFile"+strings.ToUpper(ext))
			files = append(files, "someFile"+strings.ToUpper(ext[0:1])+ext[1:])
		}
		Convey("should be matched.", func() {
			for _, file := range files {
				So(IsYaraRulesFile(file), ShouldBeTrue)
			}
		})
	})

	Convey("Files with extensions different from those in YaraRulesFileExtensions", t, func() {
		files := []string{
			"someFile.exe",
			"someFile.dll",
			"someFile.notyara",
			"someFileWithNoExt",
			"someFile.a",
			"x",
		}
		for _, ext := range YaraRulesFileExtensions {
			files = append(files, "someFile"+ext+"not")
		}
		Convey("should be matched.", func() {
			for _, file := range files {
				So(IsYaraRulesFile(file), ShouldBeFalse)
			}
		})
	})
}

func TestLoadYaraRules(t *testing.T) {
	Convey("Loading yara rules from a non-existing directory", t, func() {
		rules, err := LoadYaraRules(testDataDir("thisdoesnotexist"), false)
		Convey("should error.", func() {
			So(rules, ShouldBeNil)
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Loading a single uncompiled yara rule", t, func() {
		rules, err := LoadYaraRules(testDataDir("rules_uncompiled", "rule1.yara"), false)
		So(rules, ShouldNotBeNil)
		So(err, ShouldBeNil)

		Convey("should yield the correct rule.", func() {
			yRules := rules.GetRules()
			So(len(yRules), ShouldEqual, 1)
			So(yRules[0].Identifier(), ShouldEqual, "rule1")
		})
	})

	Convey("Loading a single compiled yara rule", t, withCompiledRules1And2(func(rulesPath string) {
		rules, err := LoadYaraRules(rulesPath, false)
		So(rules, ShouldNotBeNil)
		So(err, ShouldBeNil)

		names := make([]string, 0)
		for _, rule := range rules.GetRules() {
			names = append(names, rule.Identifier())
		}
		sort.Strings(names)

		Convey("should yield exactly the rules in this file.", func() {
			So(names, ShouldResemble, []string{
				"rule1", "rule2",
			})
			So(len(names), ShouldEqual, 2)
		})
	}))

	Convey("Loading multiple uncompiled yara rules", t, func() {
		Convey("non-recursively", func() {
			rules, err := LoadYaraRules(testDataDir("rules_uncompiled"), false)
			So(rules, ShouldNotBeNil)
			So(err, ShouldBeNil)

			names := make([]string, 0)
			for _, rule := range rules.GetRules() {
				names = append(names, rule.Identifier())
			}
			sort.Strings(names)

			Convey("should yield exactly the rules in this file.", func() {
				So(names, ShouldResemble, []string{
					"rule1", "rule2",
				})
				So(len(names), ShouldEqual, 2)
			})
		})

		Convey("recursively", func() {
			rules, err := LoadYaraRules(testDataDir("rules_uncompiled"), true)
			So(rules, ShouldNotBeNil)
			So(err, ShouldBeNil)

			names := make([]string, 0)
			for _, rule := range rules.GetRules() {
				names = append(names, rule.Identifier())
			}
			sort.Strings(names)

			Convey("should yield exactly the rules in this file.", func() {
				So(names, ShouldResemble, []string{
					"rule1", "rule2", "rule3",
				})
				So(len(names), ShouldEqual, 3)
			})
		})
	})

	Convey("Loading an encrypted zip", t, func() {
		Convey("with uncompiled yara rules", func() {
			rules, err := LoadYaraRules(testDataDir("rules_zipped", "uncompiled.zip"), true)
			So(rules, ShouldNotBeNil)
			So(err, ShouldBeNil)

			names := make([]string, 0)
			for _, rule := range rules.GetRules() {
				names = append(names, rule.Identifier())
			}
			sort.Strings(names)

			Convey("should yield exactly the rules in this file.", func() {
				So(names, ShouldResemble, []string{
					"rule1", "rule2", "rule3",
				})
				So(len(names), ShouldEqual, 3)
			})
		})

		Convey("with compiled yara rules", withCompiledAndZippedRules1And2And3(func(rulesPath string) {
			rules, err := LoadYaraRules(rulesPath, true)
			So(rules, ShouldNotBeNil)
			So(err, ShouldBeNil)

			names := make([]string, 0)
			for _, rule := range rules.GetRules() {
				names = append(names, rule.Identifier())
			}
			sort.Strings(names)

			Convey("should yield exactly the rules in this file.", func() {
				So(names, ShouldResemble, []string{
					"rule1", "rule2", "rule3",
				})
				So(len(names), ShouldEqual, 3)
			})
		}))
	})
}

func withCompiledRules1And2(inner func(rulesPath string)) func(c C) {
	return func(c C) {
		r1, err := ioutil.ReadFile(testDataDir("rules_uncompiled", "rule1.yara"))
		if err != nil {
			panic(err)
		}
		r2, err := ioutil.ReadFile(testDataDir("rules_uncompiled", "rule2.yara"))
		if err != nil {
			panic(err)
		}

		sb := &strings.Builder{}
		sb.Write(r1)
		sb.WriteString("\n")
		sb.Write(r2)

		rules := yara.MustCompile(sb.String(), nil)

		tmpFile, err := ioutil.TempFile(os.TempDir(), "rule1and2*.yarc")
		if err != nil {
			panic(err)
		}
		rulesPath := tmpFile.Name()
		tmpFile.Close()

		err = rules.Save(rulesPath)
		if err != nil {
			panic(err)
		}

		c.Reset(func() {
			os.Remove(rulesPath)
		})

		inner(rulesPath)
	}
}

func withCompiledAndZippedRules1And2And3(inner func(rulesPath string)) func(c C) {
	return func(c C) {
		r1, err := ioutil.ReadFile(testDataDir("rules_uncompiled", "rule1.yara"))
		if err != nil {
			panic(err)
		}
		r2, err := ioutil.ReadFile(testDataDir("rules_uncompiled", "rule2.yara"))
		if err != nil {
			panic(err)
		}
		r3, err := ioutil.ReadFile(testDataDir("rules_uncompiled", "subdir", "rule3.yara"))
		if err != nil {
			panic(err)
		}

		sb := &strings.Builder{}
		sb.Write(r1)
		sb.WriteString("\n")
		sb.Write(r2)
		sb.WriteString("\n")
		sb.Write(r3)

		rules := yara.MustCompile(sb.String(), nil)

		tmpFile, err := ioutil.TempFile(os.TempDir(), "rule1and2and3*.yarc")
		if err != nil {
			panic(err)
		}
		compiledRulesPath := tmpFile.Name()
		tmpFile.Close()

		err = rules.Save(compiledRulesPath)
		if err != nil {
			panic(err)
		}

		rulesPath := func() string {
			compiled, err := os.Open(compiledRulesPath)
			if err != nil {
				panic(err)
			}
			defer compiled.Close()

			tmpFile, err = ioutil.TempFile(os.TempDir(), "rule1and2and3*.zip")
			if err != nil {
				panic(err)
			}
			defer tmpFile.Close()

			z := zip.NewWriter(tmpFile)
			defer z.Close()

			out, err := z.Encrypt("rules.yarc", RulesZIPPassword, zip.AES256Encryption)
			if err != nil {
				panic(err)
			}
			_, err = io.Copy(out, compiled)
			if err != nil {
				panic(err)
			}
			return tmpFile.Name()
		}()

		c.Reset(func() {
			os.Remove(compiledRulesPath)
			os.Remove(rulesPath)
		})

		inner(rulesPath)
	}
}
