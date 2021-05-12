package output

import (
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAnonymizer_AnonymizePath(t *testing.T) {
	Convey("Anonymizing a windows style path", t, func() {
		anonymizer := &Anonymizer{
			homeDirectoryParent: "users",
			fsIsCaseSensitive:   true,
			Salt:                []byte{},
		}

		anon := filepath.ToSlash(anonymizer.AnonymizePath("/Users/SOME_USERNAME/someRestPath.txt"))
		Convey("should preserve the path.", func() {
			So(anon, ShouldContainSubstring, "/users/")
			So(anon, ShouldContainSubstring, "/somerestpath.txt")
		})
		Convey("should anonymize the username.", func() {
			So(anon, ShouldNotContainSubstring, "some_username")
		})
	})

	Convey("Anonymizing a unix style path", t, func() {
		anonymizer := &Anonymizer{
			homeDirectoryParent: "home",
			fsIsCaseSensitive:   false,
			Salt:                []byte{},
		}

		anon := filepath.ToSlash(anonymizer.AnonymizePath("/home/SOME_USERNAME/someRestPath.txt"))
		Convey("should preserve the path.", func() {
			So(anon, ShouldContainSubstring, "/home/")
			So(anon, ShouldContainSubstring, "/someRestPath.txt")
		})
		Convey("should anonymize the username.", func() {
			So(anon, ShouldNotContainSubstring, "SOME_USERNAME")
		})
	})
}
