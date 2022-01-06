package acceptanceTests

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/quick"

	"github.com/fkie-cad/yapscan/testutil"

	"github.com/fkie-cad/yapscan/report"

	"github.com/fkie-cad/yapscan/procio"
	"github.com/fkie-cad/yapscan/system"

	"golang.org/x/crypto/openpgp"

	"github.com/klauspost/compress/zstd"

	"github.com/fkie-cad/yapscan/app"

	. "github.com/smartystreets/goconvey/convey"
)

const maxRandomDataSize = 4095
const maxSizeFilter = "4K"

func TestMain(m *testing.M) {
	closer := initializeMemoryTester()
	defer closer.Close()

	m.Run()
}

func TestMatchIsFound(t *testing.T) {
	Convey("Scanning a prepared process", t, func(c C) {
		data := []byte{0xbd, 0x62, 0xcd, 0xa4, 0x80, 0x8c, 0x3a, 0x1d, 0x7e, 0x1, 0x21, 0xca, 0xc1, 0x52, 0x87, 0xda, 0xdc, 0x57, 0x61}
		yaraRulesPath, pid, addressOfData := withYaraRulesFileAndMatchingMemoryTester(t, c, data)
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		args := []string{"yapscan",
			"scan",
			"--verbose",
			"-r", yaraRulesPath,
			"--filter-size-max", maxSizeFilter,
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

	i := 0
	fmt.Println()

	f := func(data []byte) bool {
		if len(data) == 0 || len(data) >= maxRandomDataSize {
			return true
		}

		// If there is no output for an extended period of time, travic-ci will just kill the job
		fmt.Printf("\rFuzzy test %4d", i)
		i++
		os.Stdout.Sync()

		yaraRulesPath, pid, addressOfData := withYaraRulesFileAndMatchingMemoryTester(t, nil, data)
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		args := []string{"yapscan",
			"scan",
			"--verbose",
			"-r", yaraRulesPath,
			"--filter-size-max", maxSizeFilter,
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

func TestDoesNotMatchFalsePositive_Fuzzy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	i := 0
	fmt.Println()

	f := func(data []byte) bool {
		if len(data) == 0 || len(data) >= maxRandomDataSize {
			return true
		}

		// If there is no output for an extended period of time, travic-ci will just kill the job
		fmt.Printf("\rFuzzy test %4d", i)
		i++
		os.Stdout.Sync()

		yaraRulesPath, pid, addressOfData := withYaraRulesFileAndNotMatchingMemoryTester(t, nil, data)
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		args := []string{"yapscan",
			"scan",
			"--verbose",
			"-r", yaraRulesPath,
			"--filter-size-max", maxSizeFilter,
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
	fmt.Println()
}

func TestFullReportIsWritten_Unencrypted(t *testing.T) {
	Convey("Scanning a prepared process with full-report", t, func(c C) {
		data := []byte{0xbd, 0x62, 0xcd, 0xa4, 0x80, 0x8c, 0x3a, 0x1d, 0x7e, 0x1, 0x21, 0xca, 0xc1, 0x52, 0x87, 0xda, 0xdc, 0x57, 0x61}
		yaraRulesPath, pid, addressOfData := withYaraRulesFileAndMatchingMemoryTester(t, c, data)
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		reportDir := t.TempDir()
		args := []string{"yapscan",
			"scan",
			"--verbose",
			"-r", yaraRulesPath,
			"--filter-size-max", maxSizeFilter,
			"--full-report", "--report-dir", reportDir,
			strconv.Itoa(pid)}
		ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
		err := app.MakeApp(args).RunContext(ctx, args)
		cancel()

		cleanupCapture()

		conveyMatchWasSuccessful(c, addressOfData, err, stdout, stderr)
		conveyReportIsValidAndHasMatch(c, openReportCleartext(), pid, addressOfData, reportDir)
	})
}

func TestFullReportIsWritten_Unencrypted_WhenScanningTwoProcesses(t *testing.T) {
	Convey("Scanning two prepared processes (first matching, then benign) with full-report", t, func(c C) {
		data := []byte{0xbd, 0x62, 0xcd, 0xa4, 0x80, 0x8c, 0x3a, 0x1d, 0x7e, 0x1, 0x21, 0xca, 0xc1, 0x52, 0x87, 0xda, 0xdc, 0x57, 0x61}
		yaraRulesPath, matchingPID, addressOfMatchingData := withYaraRulesFileAndMatchingMemoryTester(t, c, data)
		_, nonMatchingPID, addressOfNonMatchingData := withYaraRulesFileAndNotMatchingMemoryTester(t, nil, data)
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		reportDir := t.TempDir()
		args := []string{"yapscan",
			"scan",
			"--verbose",
			"-r", yaraRulesPath,
			"--filter-size-max", maxSizeFilter,
			"--full-report", "--report-dir", reportDir,
			strconv.Itoa(matchingPID), strconv.Itoa(nonMatchingPID)}
		ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
		err := app.MakeApp(args).RunContext(ctx, args)
		cancel()

		cleanupCapture()

		conveyMatchWasSuccessful(c, addressOfMatchingData, err, stdout, stderr)
		conveyReportIsValidAndHasMatch(c, openReportCleartext(), matchingPID, addressOfMatchingData, reportDir)
		conveyReportIsValidButDoesNotHaveMatch(c, openReportCleartext(), nonMatchingPID, addressOfNonMatchingData, reportDir)
	})

	Convey("Scanning two prepared processes (first benign, then matching) with full-report", t, func(c C) {
		data := []byte{0xbd, 0x62, 0xcd, 0xa4, 0x80, 0x8c, 0x3a, 0x1d, 0x7e, 0x1, 0x21, 0xca, 0xc1, 0x52, 0x87, 0xda, 0xdc, 0x57, 0x61}
		yaraRulesPath, matchingPID, addressOfMatchingData := withYaraRulesFileAndMatchingMemoryTester(t, c, data)
		_, nonMatchingPID, addressOfNonMatchingData := withYaraRulesFileAndNotMatchingMemoryTester(t, nil, data)
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		reportDir := t.TempDir()
		args := []string{"yapscan",
			"scan",
			"--verbose",
			"-r", yaraRulesPath,
			"--filter-size-max", maxSizeFilter,
			"--full-report", "--report-dir", reportDir,
			strconv.Itoa(nonMatchingPID), strconv.Itoa(matchingPID)}
		ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
		err := app.MakeApp(args).RunContext(ctx, args)
		cancel()

		cleanupCapture()

		conveyMatchWasSuccessful(c, addressOfMatchingData, err, stdout, stderr)
		conveyReportIsValidAndHasMatch(c, openReportCleartext(), matchingPID, addressOfMatchingData, reportDir)
		conveyReportIsValidButDoesNotHaveMatch(c, openReportCleartext(), nonMatchingPID, addressOfNonMatchingData, reportDir)
	})
}

func TestPasswordProtectedFullReport(t *testing.T) {
	Convey("Scanning a prepared process with password protected full-report", t, func(c C) {
		data := []byte{0xbd, 0x62, 0xcd, 0xa4, 0x80, 0x8c, 0x3a, 0x1d, 0x7e, 0x1, 0x21, 0xca, 0xc1, 0x52, 0x87, 0xda, 0xdc, 0x57, 0x61}
		yaraRulesPath, pid, addressOfData := withYaraRulesFileAndMatchingMemoryTester(t, c, data)
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		password := "thisIsNotAStronkPassword"

		reportDir := t.TempDir()
		args := []string{"yapscan",
			"scan",
			"--verbose",
			"-r", yaraRulesPath,
			"--filter-size-max", maxSizeFilter,
			"--password", password,
			"--full-report", "--report-dir", reportDir,
			strconv.Itoa(pid)}
		ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
		err := app.MakeApp(args).RunContext(ctx, args)
		cancel()

		cleanupCapture()

		conveyMatchWasSuccessful(c, addressOfData, err, stdout, stderr)
		conveyReportIsNotReadable(c, openReportCleartext(), reportDir)
		conveyReportIsValidAndHasMatch(c, openReportWithPassword(password), pid, addressOfData, reportDir)
	})
}

func TestPGPProtectedFullReport(t *testing.T) {
	keyringPath, keyring := withPGPKey(t)

	Convey("Scanning a prepared process with password protected full-report", t, func(c C) {
		data := []byte{0xbd, 0x62, 0xcd, 0xa4, 0x80, 0x8c, 0x3a, 0x1d, 0x7e, 0x1, 0x21, 0xca, 0xc1, 0x52, 0x87, 0xda, 0xdc, 0x57, 0x61}
		yaraRulesPath, pid, addressOfData := withYaraRulesFileAndMatchingMemoryTester(t, c, data)
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		reportDir := t.TempDir()
		args := []string{"yapscan",
			"scan",
			"--verbose",
			"-r", yaraRulesPath,
			"--filter-size-max", maxSizeFilter,
			"--pgpkey", keyringPath,
			"--full-report", "--report-dir", reportDir,
			strconv.Itoa(pid)}
		ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
		err := app.MakeApp(args).RunContext(ctx, args)
		cancel()

		cleanupCapture()

		conveyMatchWasSuccessful(c, addressOfData, err, stdout, stderr)
		conveyReportIsNotReadable(c, openReportCleartext(), reportDir)
		conveyReportIsValidAndHasMatch(c, openReportPGP(keyring), pid, addressOfData, reportDir)
	})
}

func TestAnonymizedFullReport(t *testing.T) {
	Convey("Scanning a prepared process with an anonymized full-report", t, func(c C) {
		data := []byte{0xbd, 0x62, 0xcd, 0xa4, 0x80, 0x8c, 0x3a, 0x1d, 0x7e, 0x1, 0x21, 0xca, 0xc1, 0x52, 0x87, 0xda, 0xdc, 0x57, 0x61}
		yaraRulesPath, pid, addressOfData := withYaraRulesFileAndMatchingMemoryTester(t, c, data)
		stdout, stderr, cleanupCapture := withCapturedOutput(t)

		reportDir := t.TempDir()
		args := []string{"yapscan",
			"scan",
			"--verbose",
			"-r", yaraRulesPath,
			"--filter-size-max", maxSizeFilter,
			"--anonymize",
			"--full-report", "--report-dir", reportDir,
			strconv.Itoa(pid)}
		ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
		err := app.MakeApp(args).RunContext(ctx, args)
		cancel()

		cleanupCapture()

		conveyMatchWasSuccessful(c, addressOfData, err, stdout, stderr)
		conveyReportIsAnonymized(c, openReportCleartext(), reportDir)
	})
}

func findReportPath(reportDir string) (string, bool) {
	var reportName string
	dir, _ := ioutil.ReadDir(reportDir)
	for _, entry := range dir {
		if !entry.IsDir() && strings.Contains(entry.Name(), ".tar.zst") {
			reportName = entry.Name()
			break
		}
	}
	return filepath.Join(reportDir, reportName), reportName != ""
}

type readerWithCloser struct {
	rdr    io.Reader
	closer io.Closer
}

func (r *readerWithCloser) Read(p []byte) (n int, err error) {
	return r.rdr.Read(p)
}

func (r *readerWithCloser) Close() error {
	return r.closer.Close()
}

type reportOpenFunc func(reportPath string) (report.Reader, error)

func openReportCleartext() reportOpenFunc {
	return func(reportPath string) (report.Reader, error) {
		return report.NewFileReader(reportPath), nil
	}
}

func openReportWithPassword(password string) reportOpenFunc {
	return func(reportPath string) (report.Reader, error) {
		rdr := report.NewFileReader(reportPath)
		rdr.SetPassword(password)
		return rdr, nil
	}
}

func openReportPGP(keyring openpgp.EntityList) reportOpenFunc {
	return func(reportPath string) (report.Reader, error) {
		rdr := report.NewFileReader(reportPath)
		rdr.SetKeyring(keyring)
		return rdr, nil
	}
}

func conveyReportIsValidAndHasMatch(c C, openReport reportOpenFunc, pid int, addressOfData uintptr, reportDir string) {
	c.Convey("should yield a valid report", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		reportRdr, err := openReport(reportPath)
		So(err, ShouldBeNil)
		defer reportRdr.Close()

		projectRoot, err := testutil.GetProjectRoot()
		So(err, ShouldBeNil)

		validator := report.NewOfflineValidator(projectRoot + "/report")
		err = validator.ValidateReport(reportRdr)
		So(err, ShouldBeNil)

		conveyReportHasMatch(c, pid, addressOfData, reportRdr)
	})
}

func conveyReportIsValidButDoesNotHaveMatch(c C, openReport reportOpenFunc, pid int, addressOfData uintptr, reportDir string) {
	c.Convey("should yield a readable report", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		reportRdr, err := openReport(reportPath)
		So(err, ShouldBeNil)
		defer reportRdr.Close()

		projectRoot, err := testutil.GetProjectRoot()
		So(err, ShouldBeNil)

		validator := report.NewOfflineValidator(projectRoot + "/report")
		err = validator.ValidateReport(reportRdr)
		So(err, ShouldBeNil)

		conveyReportDoesNotHaveMatch(c, pid, addressOfData, reportRdr)
	})
}

func conveyReportIsAnonymized(c C, openReport reportOpenFunc, reportDir string) {
	c.Convey("should yield a valid report", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		reportRdr, err := openReport(reportPath)
		So(err, ShouldBeNil)
		defer reportRdr.Close()

		projectRoot, err := testutil.GetProjectRoot()
		So(err, ShouldBeNil)

		validator := report.NewOfflineValidator(projectRoot + "/report")
		err = validator.ValidateReport(reportRdr)
		So(err, ShouldBeNil)

		c.Convey("which does not contain the hostname, username or any IPs.", func(c C) {
			info, err := system.GetInfo()
			So(err, ShouldBeNil)

			self, err := procio.OpenProcess(os.Getpid())
			So(err, ShouldBeNil)

			selfInfo, err := self.Info()
			So(err, ShouldBeNil)

			buffer := &bytes.Buffer{}

			r, err := reportRdr.OpenMeta()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			r, err = reportRdr.OpenStatistics()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			r, err = reportRdr.OpenSystemInformation()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			r, err = reportRdr.OpenProcesses()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			r, err = reportRdr.OpenMemoryScans()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			r, err = reportRdr.OpenFileScans()
			So(err, ShouldBeNil)
			_, err = io.Copy(buffer, r)
			So(err, ShouldBeNil)
			r.Close()

			allJSON := buffer.String()

			So(allJSON, ShouldNotBeEmpty)
			So(allJSON, ShouldNotContainSubstring, info.Hostname)
			for _, ip := range info.IPs {
				So(allJSON, ShouldNotContainSubstring, ip)
			}
			So(allJSON, ShouldNotContainSubstring, selfInfo.Username)
		})
	})
}

func conveyReportIsNotReadable(c C, openReport reportOpenFunc, reportDir string) {
	c.Convey("should not yield a readable report.", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		reportRdr, err := openReport(reportPath)
		if err != nil {
			So(err, ShouldNotBeNil)
			return
		}
		defer reportRdr.Close()

		_, errMeta := reportRdr.OpenMeta()
		_, errStatistics := reportRdr.OpenStatistics()
		_, errSystemInformation := reportRdr.OpenSystemInformation()
		_, errProcesses := reportRdr.OpenProcesses()
		_, errMemoryScans := reportRdr.OpenMemoryScans()
		_, errFileScans := reportRdr.OpenFileScans()
		So(errMeta, ShouldNotBeNil)
		So(errStatistics, ShouldNotBeNil)
		So(errSystemInformation, ShouldNotBeNil)
		So(errProcesses, ShouldNotBeNil)
		So(errMemoryScans, ShouldNotBeNil)
		So(errFileScans, ShouldNotBeNil)
	})
}

func conveyReportHasMatch(c C, pid int, addressOfData uintptr, reportRdr report.Reader) {
	c.Convey("with the memory-scans.json containing the correct match.", func() {
		parser := report.NewParser()
		rprt, err := parser.Parse(reportRdr)
		So(err, ShouldBeNil)

		foundCorrectMatch := false
		for _, scan := range rprt.MemoryScans {
			if scan.PID == pid && scan.MemorySegment == addressOfData && len(scan.Matches) > 0 {
				foundCorrectMatch = true
				break
			}
		}
		c.So(foundCorrectMatch, ShouldBeTrue)
	})
}

func conveyReportDoesNotHaveMatch(c C, pid int, addressOfData uintptr, reportRdr report.Reader) {
	c.Convey("with the memory-scans.json not containing a false positive.", func() {
		parser := report.NewParser()
		rprt, err := parser.Parse(reportRdr)
		So(err, ShouldBeNil)

		foundMatchForPID := false
		foundMatchForAddressInPID := false
		for _, scan := range rprt.MemoryScans {
			if scan.PID == pid && len(scan.Matches) > 0 {
				foundMatchForPID = true
				if scan.MemorySegment == addressOfData {
					foundMatchForAddressInPID = true
					break
				}
			}
		}
		c.So(foundMatchForPID, ShouldBeFalse)
		c.So(foundMatchForAddressInPID, ShouldBeFalse)
	})
}

type file struct {
	Name string
	Data []byte
}

func readReport(rdr io.Reader) ([]*file, error) {
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
	c.Convey("should not error and find the correct match in stdout.", func() {
		c.So(err, ShouldBeNil)
		c.So(stderr.String(), ShouldBeEmpty)
		c.So(stdout.String(), ShouldContainSubstring, fmt.Sprintf("Rule-strings matched at 0x%X.", addressOfData))
	})
}
