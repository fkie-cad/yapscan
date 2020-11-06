package yapscan

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/hillu/go-yara/v4"

	. "github.com/smartystreets/goconvey/convey"
)

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

func TestYaraScanner(t *testing.T) {
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
	})
}
