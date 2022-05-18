package acceptanceTests

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/quick"

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
		err := app.MakeApp().RunContext(ctx, args)
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
		err := app.MakeApp().RunContext(ctx, args)
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
		err := app.MakeApp().RunContext(ctx, args)
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
		err := app.MakeApp().RunContext(ctx, args)
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
		err := app.MakeApp().RunContext(ctx, args)
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
		err := app.MakeApp().RunContext(ctx, args)
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
		err := app.MakeApp().RunContext(ctx, args)
		cancel()

		cleanupCapture()

		conveyMatchWasSuccessful(c, addressOfData, err, stdout, stderr)
		conveyReportIsNotReadable(c, openReportCleartext(), reportDir)
		conveyReportIsValidAndHasMatch(c, openReportWithPassword(password), pid, addressOfData, reportDir)
	})
}

func TestPGPProtectedFullReport(t *testing.T) {
	pubkeyPath, _, _, privKey := withPGPKey(t)

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
			"--pgpkey", pubkeyPath,
			"--full-report", "--report-dir", reportDir,
			strconv.Itoa(pid)}
		ctx, cancel := context.WithTimeout(context.Background(), yapscanTimeout)
		err := app.MakeApp().RunContext(ctx, args)
		cancel()

		cleanupCapture()

		conveyMatchWasSuccessful(c, addressOfData, err, stdout, stderr)
		conveyReportIsNotReadable(c, openReportCleartext(), reportDir)
		conveyReportIsValidAndHasMatch(c, openReportPGP(privKey), pid, addressOfData, reportDir)
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
		err := app.MakeApp().RunContext(ctx, args)
		cancel()

		cleanupCapture()

		conveyMatchWasSuccessful(c, addressOfData, err, stdout, stderr)
		conveyReportIsAnonymizedForLocalSystem(c, openReportCleartext(), reportDir)
	})
}

func conveyMatchWasSuccessful(c C, addressOfData uintptr, err error, stdout, stderr *bytes.Buffer) {
	c.Convey("should not error and find the correct match in stdout.", func() {
		c.So(err, ShouldBeNil)
		c.So(stderr.String(), ShouldBeEmpty)
		c.So(stdout.String(), ShouldContainSubstring, fmt.Sprintf("Rule-strings matched at 0x%X.", addressOfData))
	})
}
