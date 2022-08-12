package acceptanceTests

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/fkie-cad/yapscan/procio"

	"github.com/fkie-cad/yapscan/app"
	. "github.com/smartystreets/goconvey/convey"
)

func TestOptimizedMemoryScanning(t *testing.T) {
	Convey("Scanning a prepared process with a mapped file", t, func(c C) {
		Convey("and a match in live memory", func(c C) {
			fileSize := os.Getpagesize() * 12
			fileData := bytes.Repeat([]byte{0xaa}, fileSize)
			data := []byte{0xbd, 0x62, 0xcd, 0xa4, 0x80, 0x8c, 0x3a, 0x1d, 0x7e, 0x1, 0x21, 0xca, 0xc1, 0x52, 0x87, 0xda, 0xdc, 0x57, 0x61}
			yaraRulesPath, _, pid, addressOfData := withYaraRulesFileAndMatchingMappedMemoryTester(t, c, data, fileData, 0, os.Getpagesize())
			stdout, stderr, cleanupCapture := withCapturedOutput(t)

			args := []string{"yapscan",
				"scan",
				"--verbose",
				"-r", yaraRulesPath,
				"--filter-size-max", fmt.Sprintf("%d", fileSize),
				strconv.Itoa(pid)}
			ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
			err := app.MakeApp().RunContext(ctx, args)
			cancel()

			cleanupCapture()

			conveyMatchWasSuccessful(c, addressOfData+uintptr(os.Getpagesize()), err, stdout, stderr)

			proc, err := procio.OpenProcess(pid)
			So(err, ShouldBeNil)
			segments, err := proc.MemorySegments()
			So(err, ShouldBeNil)
			seg := findMemorySegment(addressOfData, segments)
			c.Convey("should not increase RSS.", func() {
				// Only one page should be in RSS
				c.So(seg.RSS, ShouldEqual, os.Getpagesize())
			})
		})

		Convey("and a match in the file", func(c C) {
			fileSize := os.Getpagesize() * 12
			maldata := []byte{0xbd, 0x62, 0xcd, 0xa4, 0x80, 0x8c, 0x3a, 0x1d, 0x7e, 0x1, 0x21, 0xca, 0xc1, 0x52, 0x87, 0xda, 0xdc, 0x57, 0x61}
			fileData := append(maldata, bytes.Repeat([]byte{0xaa}, fileSize-len(maldata))...)
			memdata := bytes.Repeat([]byte{0xa1}, os.Getpagesize())
			yaraRulesPath, _, pid, addressOfData := withYaraRulesFileAndMappedMemoryTester(t, c, maldata, fileData, 0, os.Getpagesize()*4, memdata)
			stdout, stderr, cleanupCapture := withCapturedOutput(t)

			args := []string{"yapscan",
				"scan",
				"--verbose",
				"-r", yaraRulesPath,
				"--filter-size-max", fmt.Sprintf("%d", fileSize),
				strconv.Itoa(pid)}
			ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
			err := app.MakeApp().RunContext(ctx, args)
			cancel()

			cleanupCapture()

			conveyMatchWasSuccessful(c, addressOfData, err, stdout, stderr)

			proc, err := procio.OpenProcess(pid)
			So(err, ShouldBeNil)
			segments, err := proc.MemorySegments()
			So(err, ShouldBeNil)
			seg := findMemorySegment(addressOfData, segments)
			c.Convey("should not increase RSS.", func() {
				// Only one page should be in RSS
				c.So(seg.RSS, ShouldEqual, os.Getpagesize())
			})
		})

		Convey("and a match in the file but outside the mapped area", func(c C) {
			fileSize := os.Getpagesize() * 12
			maldata := []byte{0xbd, 0x62, 0xcd, 0xa4, 0x80, 0x8c, 0x3a, 0x1d, 0x7e, 0x1, 0x21, 0xca, 0xc1, 0x52, 0x87, 0xda, 0xdc, 0x57, 0x61}
			fileData := append(maldata, bytes.Repeat([]byte{0xaa}, fileSize-len(maldata))...)
			memdata := bytes.Repeat([]byte{0xa1}, os.Getpagesize())
			yaraRulesPath, _, pid, addressOfData := withYaraRulesFileAndMappedMemoryTester(t, c, maldata, fileData, os.Getpagesize(), os.Getpagesize()*4, memdata)
			stdout, stderr, cleanupCapture := withCapturedOutput(t)

			args := []string{"yapscan",
				"scan",
				"--verbose",
				"-r", yaraRulesPath,
				"--filter-size-max", fmt.Sprintf("%d", fileSize),
				strconv.Itoa(pid)}
			ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
			err := app.MakeApp().RunContext(ctx, args)
			cancel()

			cleanupCapture()

			conveyNoMatch(c, err, stdout, stderr)

			proc, err := procio.OpenProcess(pid)
			So(err, ShouldBeNil)
			segments, err := proc.MemorySegments()
			So(err, ShouldBeNil)
			seg := findMemorySegment(addressOfData, segments)
			c.Convey("should not increase RSS.", func() {
				// Only one page should be in RSS
				c.So(seg.RSS, ShouldEqual, os.Getpagesize())
			})
		})
	})
}
