package fileIO

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func testDataDir(path ...string) string {
	path = append([]string{"..", "testdata"}, path...)
	return filepath.Join(path...)
}

func TestIterateFail(t *testing.T) {
	Convey("Iterating through a non-existent directory", t, func() {
		it, err := IteratePath(filepath.Join("thispath", "shouldnot", "exist"), context.Background())

		Convey("should error.", func() {
			So(it, ShouldBeNil)
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Opening a file for iteration", t, func() {
		it, err := IteratePath(testDataDir("fsIterator", "f1"), context.Background())

		Convey("should error.", func() {
			So(it, ShouldBeNil)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestIterateSuccess(t *testing.T) {
	Convey("Iterating through a directory with a single goroutine", t, func() {
		it, err := IteratePath(testDataDir("fsIterator"), context.Background())

		Convey("should not error.", func() {
			So(err, ShouldBeNil)
			So(it, ShouldNotBeNil)
		})

		filenames := []string{"f1", "f2", "f3", "f4"}
		Convey("should yield all files.", func() {
			for {
				f, err := it.Next()
				if err == io.EOF {
					break
				}

				So(err, ShouldBeNil)
				So(f, ShouldNotBeNil)
				if f != nil {
					So(f.path, ShouldBeIn, filenames)
				}
			}
		})

		Convey("when closing", func() {
			err := it.Close()
			Convey("should not error.", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}
