package yapscan

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	Convey("Loading a single compiled yara rule", t, func() {
		rules, err := LoadYaraRules(testDataDir("rules_compiled", "rule1and2.yarc"), false)
		So(rules, ShouldNotBeNil)
		So(err, ShouldBeNil)

		names := make([]string, 0)
		for _, rule := range rules.GetRules() {
			names = append(names, rule.Identifier())
		}

		Convey("should yield exactly the rules in this file.", func() {
			So(names, ShouldResemble, []string{
				"rule1", "rule2",
			})
			So(len(names), ShouldEqual, 2)
		})
	})

	Convey("Loading multiple uncompiled yara rules", t, func() {
		Convey("non-resursively", func() {
			rules, err := LoadYaraRules(testDataDir("rules_uncompiled"), false)
			So(rules, ShouldNotBeNil)
			So(err, ShouldBeNil)

			names := make([]string, 0)
			for _, rule := range rules.GetRules() {
				names = append(names, rule.Identifier())
			}

			Convey("should yield exactly the rules in this file.", func() {
				So(names, ShouldResemble, []string{
					"rule1", "rule2",
				})
				So(len(names), ShouldEqual, 2)
			})
		})

		Convey("resursively", func() {
			rules, err := LoadYaraRules(testDataDir("rules_uncompiled"), true)
			So(rules, ShouldNotBeNil)
			So(err, ShouldBeNil)

			names := make([]string, 0)
			for _, rule := range rules.GetRules() {
				names = append(names, rule.Identifier())
			}

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

			Convey("should yield exactly the rules in this file.", func() {
				So(names, ShouldResemble, []string{
					"rule1", "rule2", "rule3",
				})
				So(len(names), ShouldEqual, 3)
			})
		})

		Convey("with compiled yara rules", func() {
			rules, err := LoadYaraRules(testDataDir("rules_zipped", "compiled.zip"), true)
			So(rules, ShouldNotBeNil)
			So(err, ShouldBeNil)

			names := make([]string, 0)
			for _, rule := range rules.GetRules() {
				names = append(names, rule.Identifier())
			}

			Convey("should yield exactly the rules in this file.", func() {
				So(names, ShouldResemble, []string{
					"rule1", "rule2", "rule3",
				})
				So(len(names), ShouldEqual, 3)
			})
		})
	})
}
