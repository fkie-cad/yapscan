package system

import (
	"testing"

	"github.com/fkie-cad/yapscan/arch"

	. "github.com/smartystreets/goconvey/convey"
)

func TestGetInfo(t *testing.T) {
	Convey("Retrieving system information should yield plausible results", t, func() {
		info, err := GetInfo()
		So(err, ShouldBeNil)
		So(info.OSArch, ShouldNotEqual, arch.Invalid)
		So(info.OSName, ShouldNotEqual, "UNKNOWN")
		So(info.OSFlavour, ShouldNotEqual, "UNKNOWN")
		So(info.OSVersion, ShouldNotEqual, "UNKNOWN")
		So(info.Hostname, ShouldNotBeEmpty)
		So(info.NumCPUs, ShouldBeGreaterThan, 0)
		So(info.TotalRAM, ShouldBeGreaterThan, 0)
	})
}
