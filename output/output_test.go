package output

import (
	"fmt"
	"math/rand"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

const randomChars = "abcd\\"

func randomPath(length int) string {
	ret := ""
	for i := 0; i < length; i++ {
		ind := rand.Int() % len(randomChars)
		ret += randomChars[ind : ind+1]
	}
	return ret
}

func TestFormatPath_NoPanic(t *testing.T) {
	Convey("Formatting paths in a prettyFormatter", t, func() {
		f := prettyFormatter{}
		for pathlen := 0; pathlen < 32; pathlen++ {
			for maxlen := 0; maxlen < 32; maxlen++ {
				Convey(fmt.Sprintf("with a path of length %d and maxlength %d", pathlen, maxlen), func() {
					path := randomPath(pathlen)
					Convey("should not panic.", func() {
						So(func() {
							f.FormatPath(path, maxlen)
						}, ShouldNotPanic)
					})
				})
			}
		}
	})
}
