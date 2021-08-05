package system

import (
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestCPULoad(t *testing.T) {
	Convey("Retrieving CPU load should not yield zero", t, func() {
		// wait for two cycles
		time.Sleep(MaxCPULoadResolution * 2)

		avg1, avg5, avg15 := CPULoad()
		So(avg1, ShouldBeGreaterThan, 0.)
		So(avg5, ShouldBeGreaterThan, 0.)
		So(avg15, ShouldBeGreaterThan, 0.)
	})
}
