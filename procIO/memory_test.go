package procIO

import (
	"fmt"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestParsePermissions(t *testing.T) {
	Convey("Given input strings", t, func() {
		strs := []string{
			"r",
			"W",
			"--X",
			"-c-",
			"rw",
			"rWc",
			"rc",
			"r-X",
			"wx",
			"cx",
			"Cwx",
			"Rwx",
			"rwcx",
		}

		perms := []Permissions{
			PermR, // "r"
			{ // "w"
				Read:    false,
				Write:   true,
				COW:     false,
				Execute: false,
			},
			{ // "x"
				Read:    false,
				Write:   false,
				COW:     false,
				Execute: true,
			},
			{ // "c"
				Read:    false,
				Write:   true,
				COW:     true,
				Execute: false,
			},
			PermRW, // "rw"
			{ // "rwc"
				Read:    true,
				Write:   true,
				COW:     true,
				Execute: false,
			},
			PermRC, // "rc"
			PermRX, // "rx"
			{ // "wx"
				Read:    false,
				Write:   true,
				COW:     false,
				Execute: true,
			},
			{ // "cx"
				Read:    false,
				Write:   true,
				COW:     true,
				Execute: true,
			},
			{ // "cwx"
				Read:    false,
				Write:   true,
				COW:     true,
				Execute: true,
			},
			PermRWX, // "rwx"
			PermRCX, // "rwcx"
		}

		for i := range strs {
			Convey(fmt.Sprintf("Parsing should be successful for \"%s\"", strs[i]), func() {
				perm, err := ParsePermissions(strs[i])
				So(err, ShouldBeNil)
				So(perm, ShouldResemble, perms[i])
			})
		}
	})
}
