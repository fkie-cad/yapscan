package fileio

import (
	"context"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func testDataDir(path ...string) string {
	path = append([]string{"..", "testdata", "fileio"}, path...)
	return filepath.Join(path...)
}

func TestIterateFail(t *testing.T) {
	Convey("Iterating through a non-existent directory", t, func() {
		it, err := IteratePath(context.Background(), filepath.Join("thispath", "shouldnot", "exist"), nil)

		Convey("should error.", func() {
			So(it, ShouldBeNil)
			So(err, ShouldNotBeNil)
		})
	})

	Convey("Opening a file for iteration", t, func() {
		it, err := IteratePath(context.Background(), testDataDir("filesystem", "f1"), nil)

		Convey("should error.", func() {
			So(it, ShouldBeNil)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestIterateSuccess(t *testing.T) {
	Convey("Iterating through a directory with a single goroutine", t, func() {
		it, err := IteratePath(context.Background(), testDataDir("filesystem"), nil)

		Convey("should not error.", func() {
			So(err, ShouldBeNil)
			if it == nil { // Workaround for goconvey bug goconvey/#612
				So(it, ShouldNotBeNil)
			}
		})

		filenames := []string{
			testDataDir("filesystem", "f1"),
			testDataDir("filesystem", "f2"),
			testDataDir("filesystem", "dir1", "dir3", "f3"),
			testDataDir("filesystem", "dir2", "f4"),
		}
		Convey("should yield all files.", func() {
			found := make([]string, 0)
			for {
				f, err := it.Next()
				if err == io.EOF {
					break
				}

				So(err, ShouldBeNil)
				So(f, ShouldNotBeNil)
				found = append(found, f.Path())
			}
			// Sort both because the order does not matter
			sort.Slice(found, func(i, j int) bool {
				return strings.Compare(found[i], found[j]) < 0
			})
			sort.Slice(filenames, func(i, j int) bool {
				return strings.Compare(filenames[i], filenames[j]) < 0
			})
			So(found, ShouldResemble, filenames)
		})

		Convey("when closing", func() {
			err := it.Close()
			Convey("should not error.", func() {
				So(err, ShouldBeNil)
			})
		})
	})
}
