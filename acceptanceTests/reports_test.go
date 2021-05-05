package acceptanceTests

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/fkie-cad/yapscan/app"

	. "github.com/smartystreets/goconvey/convey"
)

const yapscanTimeout = 10 * time.Second

func TestMain(m *testing.M) {
	closer := initializeMemoryTester()
	defer closer.Close()

	m.Run()
}

func TestMatchIsFound_Simple(t *testing.T) {
	yaraRulesPath, pid, addressOfData := withYaraRulesFileAndMatchingMemoryTester(t, []byte("hello world"))

	Convey("Scanning a prepared process with full-report on", t, func(c C) {
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		args := []string{"yapscan",
			"scan",
			"-r", yaraRulesPath,
			strconv.Itoa(pid)}
		ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
		err := app.MakeApp(args).RunContext(ctx, args)
		cancel()

		cleanupCapture()

		conveyMatchWasSuccessful(c, addressOfData, err, stdout, stderr)
	})
}

func TestMatchIsFound_Fuzzy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	f := func(data []byte) bool {
		yaraRulesPath, pid, addressOfData := withYaraRulesFileAndMatchingMemoryTester(t, data)
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		args := []string{"yapscan",
			"scan",
			"-r", yaraRulesPath,
			strconv.Itoa(pid)}
		ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
		err := app.MakeApp(args).RunContext(ctx, args)
		cancel()

		cleanupCapture()

		return err == nil &&
			stderr.String() == "" &&
			strings.Contains(stdout.String(), fmt.Sprintf("Rule-strings matched at 0x%X.", addressOfData))
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

//func TestDoesNotMatchFalsePositive_Fuzzy_FailedInput(t *testing.T) {
//	Convey("With data of a previously observed fuzzy failure", t, func() {
//		data := []byte{0x68, 0xd6, 0x1e, 0x53, 0xf5, 0xe3, 0x62, 0x0, 0x1d, 0xa5, 0x39, 0xf5, 0xe4, 0x95, 0x4b, 0xda, 0xe7, 0x9f, 0xa6, 0x52, 0x64, 0x86, 0xd7, 0x2e, 0xca, 0x98, 0x72, 0xcd, 0x71, 0x2c, 0xc3, 0x7c, 0x5b, 0x4a, 0x82, 0x43, 0x17, 0x74}
//
//		yaraRulesPath, pid, addressOfData := withYaraRulesFileAndNotMatchingMemoryTester(t, data)
//		stdout, stderr, cleanupCapture := withCapturedOutput(t)
//
//		Convey("yapscan should not have this false positive anymore.", func() {
//			args := []string{"yapscan",
//				"scan",
//				"-r", yaraRulesPath,
//				strconv.Itoa(pid)}
//			ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
//			err := app.MakeApp(args).RunContext(ctx, args)
//			cancel()
//
//			cleanupCapture()
//
//			So(err, ShouldBeNil)
//			So(stderr.String(), ShouldBeEmpty)
//			So(stdout.String(), ShouldNotContainSubstring, fmt.Sprintf("Rule-strings matched at 0x%X.", addressOfData))
//		})
//	})
//}

func TestDoesNotMatchFalsePositive_Fuzzy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	f := func(data []byte) bool {
		if len(data) == 0 {
			// Skip empty data as that will always match
			return true
		}
		yaraRulesPath, pid, addressOfData := withYaraRulesFileAndNotMatchingMemoryTester(t, data)
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		args := []string{"yapscan",
			"scan",
			"-r", yaraRulesPath,
			strconv.Itoa(pid)}
		ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
		err := app.MakeApp(args).RunContext(ctx, args)
		cancel()

		cleanupCapture()

		return err == nil &&
			stderr.String() == "" &&
			!strings.Contains(stdout.String(), fmt.Sprintf("Rule-strings matched at 0x%X.", addressOfData))
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestFullReportIsWritten_Unencrypted(t *testing.T) {
	yaraRulesPath, pid, addressOfData := withYaraRulesFileAndMatchingMemoryTester(t, []byte("hello world"))

	Convey("Scanning a prepared process with full-report on", t, func(c C) {
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		reportDir := t.TempDir()
		args := []string{"yapscan",
			"scan",
			"-r", yaraRulesPath,
			"--full-report", "--report-dir", reportDir,
			strconv.Itoa(pid)}
		ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
		err := app.MakeApp(args).RunContext(ctx, args)
		cancel()

		cleanupCapture()

		conveyMatchWasSuccessful(c, addressOfData, err, stdout, stderr)
		conveyReportIsCleartextReadable(c, reportDir)
	})
}

func findReportPath(reportDir string) (string, bool) {
	var reportName string
	dir, _ := os.ReadDir(reportDir)
	for _, entry := range dir {
		if !entry.IsDir() && strings.Contains(entry.Name(), ".tar.zstd") {
			reportName = entry.Name()
			break
		}
	}
	return filepath.Join(reportDir, reportName), reportName != ""
}

func conveyReportIsCleartextReadable(c C, reportDir string) {
	c.Convey("should be a valid zstd compressed file", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		f, _ := os.Open(reportPath)
		defer f.Close()

		reportFiles, err := readReport(c, f)

		c.So(reportFiles, ShouldNotBeEmpty)
		c.So(err, ShouldBeNil)

		filenames := make([]string, len(reportFiles))
		for i, file := range reportFiles {
			filenames[i] = file.Name
		}
		c.Convey("and contain the expected files.", func(c C) {
			c.So(filenames, ShouldContain, "rules.yarc")
			c.So(filenames, ShouldContain, "systeminfo.json")
			c.So(filenames, ShouldContain, "processes.json")
			c.So(filenames, ShouldContain, "memory-scans.json")
			c.So(filenames, ShouldHaveLength, 4)
		})
	})
}

type file struct {
	Name string
	Data []byte
}

func readReport(c C, rdr io.Reader) ([]*file, error) {
	zstdRdr, err := zstd.NewReader(rdr)
	if err != nil {
		return nil, err
	}
	defer zstdRdr.Close()

	result := make([]*file, 0)

	tarRdr := tar.NewReader(zstdRdr)
	for {
		var hdr *tar.Header
		hdr, err = tarRdr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag == tar.TypeReg {
			file := &file{
				Name: filepath.Base(hdr.Name),
			}
			buf := &bytes.Buffer{}
			if _, err = io.Copy(buf, tarRdr); err != nil {
				break
			}
			file.Data = buf.Bytes()

			result = append(result, file)
		}
	}

	if err == io.EOF {
		err = nil
	}

	return result, err
}

func conveyMatchWasSuccessful(c C, addressOfData uintptr, err error, stdout, stderr *bytes.Buffer) {
	c.Convey("should not error.", func() {
		c.So(err, ShouldBeNil)
	})
	c.Convey("should not output anything on stderr.", func() {
		c.So(stderr.String(), ShouldBeEmpty)
	})
	c.Convey("should output a match on the correct address.", func() {
		c.So(stdout.String(), ShouldContainSubstring, fmt.Sprintf("Rule-strings matched at 0x%X.", addressOfData))
	})
}
