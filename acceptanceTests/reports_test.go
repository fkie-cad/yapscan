package acceptanceTests

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/quick"

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
		conveyReportIsReadable(c, openReportCleartext(), pid, addressOfData, reportDir)
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
		conveyReportIsReadable(c, openReportCleartext(), matchingPID, addressOfMatchingData, reportDir)
		conveyReportIsReadableButDoesNotHaveMatch(c, openReportCleartext(), nonMatchingPID, addressOfNonMatchingData, reportDir)
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
		conveyReportIsReadable(c, openReportCleartext(), matchingPID, addressOfMatchingData, reportDir)
		conveyReportIsReadableButDoesNotHaveMatch(c, openReportCleartext(), nonMatchingPID, addressOfNonMatchingData, reportDir)
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
		conveyReportIsReadable(c, openReportWithPassword(password), pid, addressOfData, reportDir)
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
		conveyReportIsReadable(c, openReportPGP(keyring), pid, addressOfData, reportDir)
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

type reportOpenFunc func(reportPath string) (io.ReadCloser, error)

func openReportCleartext() reportOpenFunc {
	return func(reportPath string) (io.ReadCloser, error) {
		return os.Open(reportPath)
	}
}

func openReportWithPassword(password string) reportOpenFunc {
	return func(reportPath string) (io.ReadCloser, error) {
		f, err := os.Open(reportPath)
		if err != nil {
			return nil, err
		}

		prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			return []byte(password), nil
		}
		msg, err := openpgp.ReadMessage(f, nil, prompt, nil)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &readerWithCloser{
			rdr:    msg.UnverifiedBody,
			closer: f,
		}, nil
	}
}

func openReportPGP(keyring openpgp.EntityList) reportOpenFunc {
	return func(reportPath string) (io.ReadCloser, error) {
		f, err := os.Open(reportPath)
		if err != nil {
			return nil, err
		}

		msg, err := openpgp.ReadMessage(f, keyring, nil, nil)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &readerWithCloser{
			rdr:    msg.UnverifiedBody,
			closer: f,
		}, nil
	}
}

func conveyReportIsReadable(c C, openReport reportOpenFunc, pid int, addressOfData uintptr, reportDir string) {
	c.Convey("should yield a valid report", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		report, err := openReport(reportPath)
		So(err, ShouldBeNil)
		defer report.Close()

		reportFiles, err := readReport(report)

		c.So(reportFiles, ShouldNotBeEmpty)
		c.So(err, ShouldBeNil)

		var memoryScansJSON *file
		filenames := make([]string, len(reportFiles))
		for i, file := range reportFiles {
			filenames[i] = file.Name
			if file.Name == "memory-scans.json" {
				memoryScansJSON = file
			}
		}
		c.Convey("which contains the expected files", func(c C) {
			c.So(filenames, ShouldContain, "systeminfo.json")
			c.So(filenames, ShouldContain, "processes.json")
			c.So(filenames, ShouldContain, "memory-scans.json")
			c.So(filenames, ShouldContain, "stats.json")
			c.So(memoryScansJSON, ShouldNotBeNil)

			conveyReportHasMatch(c, pid, addressOfData, memoryScansJSON)
		})
	})
}

func conveyReportIsReadableButDoesNotHaveMatch(c C, openReport reportOpenFunc, pid int, addressOfData uintptr, reportDir string) {
	c.Convey("should yield a readable report", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		report, err := openReport(reportPath)
		So(err, ShouldBeNil)
		defer report.Close()

		reportFiles, err := readReport(report)

		c.So(reportFiles, ShouldNotBeEmpty)
		c.So(err, ShouldBeNil)

		var memoryScansJSON *file
		filenames := make([]string, len(reportFiles))
		for i, file := range reportFiles {
			filenames[i] = file.Name
			if file.Name == "memory-scans.json" {
				memoryScansJSON = file
			}
		}
		c.Convey("which contains the expected files", func(c C) {
			c.So(filenames, ShouldContain, "systeminfo.json")
			c.So(filenames, ShouldContain, "processes.json")
			c.So(filenames, ShouldContain, "memory-scans.json")
			c.So(filenames, ShouldContain, "stats.json")
			c.So(memoryScansJSON, ShouldNotBeNil)

			conveyReportDoesNotHaveMatch(c, pid, addressOfData, memoryScansJSON)
		})
	})
}

func conveyReportIsAnonymized(c C, openReport reportOpenFunc, reportDir string) {
	c.Convey("should yield a valid report", func(c C) {
		reportPath, exists := findReportPath(reportDir)

		c.So(exists, ShouldBeTrue)
		if !exists {
			return
		}

		report, err := openReport(reportPath)
		So(err, ShouldBeNil)
		defer report.Close()

		reportFiles, err := readReport(report)

		c.So(reportFiles, ShouldNotBeEmpty)
		c.So(err, ShouldBeNil)

		c.Convey("which does not contain the hostname, username or any IPs.", func(c C) {
			info, err := system.GetInfo()
			So(err, ShouldBeNil)

			self, err := procio.OpenProcess(os.Getpid())
			So(err, ShouldBeNil)

			selfInfo, err := self.Info()
			So(err, ShouldBeNil)

			allJSONBuilder := &strings.Builder{}
			for _, file := range reportFiles {
				if strings.Contains(file.Name, ".json") {
					allJSONBuilder.Write(file.Data)
				}
			}
			allJSON := allJSONBuilder.String()

			fmt.Println(info.Hostname)

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

		report, err := openReport(reportPath)
		if err != nil {
			So(err, ShouldNotBeNil)
			return
		}
		defer report.Close()

		_, err = readReport(report)
		c.So(err, ShouldNotBeNil)
	})
}

func conveyReportHasMatch(c C, pid int, addressOfData uintptr, memoryScansJSON *file) {
	c.Convey("with the memory-scans.json containing the correct match.", func() {
		dec := json.NewDecoder(bytes.NewReader(memoryScansJSON.Data))
		foundCorrectMatch := false
		var err error
		for {
			re := new(report.MemoryScan)
			err = dec.Decode(re)
			if err != nil {
				break
			}

			if re.PID == pid && re.MemorySegment == addressOfData && len(re.Matches) > 0 {
				foundCorrectMatch = true
			}
		}
		c.So(err, ShouldResemble, io.EOF)
		c.So(foundCorrectMatch, ShouldBeTrue)
	})
}

func conveyReportDoesNotHaveMatch(c C, pid int, addressOfData uintptr, memoryScansJSON *file) {
	c.Convey("with the memory-scans.json not containing a false positive.", func() {
		dec := json.NewDecoder(bytes.NewReader(memoryScansJSON.Data))
		foundMatchForPID := false
		foundMatchForAddressInPID := false
		var err error
		for {
			re := new(report.MemoryScan)
			err = dec.Decode(re)
			if err != nil {
				break
			}

			if re.PID == pid && len(re.Matches) > 0 {
				foundMatchForPID = true
				if re.MemorySegment == addressOfData {
					foundMatchForAddressInPID = true
				}
			}
		}
		c.So(err, ShouldResemble, io.EOF)
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
