package procIO

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

const cmdPathTimeout = 1 * time.Second

func TestPIDInEnumeration(t *testing.T) {
	var testExe string
	if runtime.GOOS == "windows" {
		testExe = "cmd.exe"
	} else {
		testExe = "bash"
	}

	path, err := exec.LookPath(testExe)
	if path == "" {
		panic("No " + testExe + " found!")
	}
	if err != nil {
		panic(err)
	}
	Convey("Starting a process", t, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cmd := exec.CommandContext(ctx, path)
		cmdIn, err := cmd.StdinPipe()
		if err != nil {
			panic(err)
		}
		defer cmdIn.Close()
		err = cmd.Start()
		if err != nil {
			panic(err)
		}

		runningPids, err := GetRunningPIDs()
		Convey("enumerating running PIDs", func() {
			Convey("should not error.", func() {
				So(err, ShouldBeNil)
			})
			Convey("should list the executed command.", func() {
				So(runningPids, ShouldContain, cmd.Process.Pid)
			})
		})

		fmt.Fprintln(cmdIn, "exit")
	})
}

func TestProcessInformation(t *testing.T) {
	var testExe string
	var testArgs []string
	if runtime.GOOS == "windows" {
		testExe = "cmd.exe"
		testArgs = []string{"/C", "timeout 6000"}
	} else {
		testExe = "bash"
		testArgs = []string{"-c", "sleep 6000"}
	}

	path, err := exec.LookPath(testExe)
	if path == "" {
		panic("No " + testExe + " found!")
	}
	if err != nil {
		panic(err)
	}
	Convey("With a started process", t, func() {
		ctx, cancel := context.WithTimeout(context.Background(), cmdPathTimeout)
		defer cancel()

		cmd := exec.CommandContext(ctx, path, testArgs...)
		cmdIn, err := cmd.StdinPipe()
		if err != nil {
			panic(err)
		}
		defer cmdIn.Close()
		err = cmd.Start()
		if err != nil {
			panic(err)
		}

		proc, err := OpenProcess(cmd.Process.Pid)
		Convey("opening the process should not error.", func() {
			So(err, ShouldBeNil)
		})
		if err != nil {
			return
		}
		defer proc.Close()

		Convey("the PID should match.", func() {
			So(proc.PID(), ShouldEqual, cmd.Process.Pid)
		})

		Convey("retrieving the process info", func() {
			info, err := proc.Info()

			Convey("should not error.", func() {
				So(err, ShouldBeNil)
			})
			if err != nil {
				return
			}

			Convey("should return the correct PID.", func() {
				So(info.PID, ShouldEqual, cmd.Process.Pid)
			})

			Convey("should return the correct filepath.", func() {
				So(info.ExecutablePath, ShouldEqual, path)
			})
		})
	})
}
