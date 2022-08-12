package acceptanceTests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fkie-cad/yapscan/testutil"

	"github.com/fkie-cad/yapscan/procio"
	. "github.com/smartystreets/goconvey/convey"
)

const testCompilerTimeout = 1 * time.Minute
const testerTimeout = 15 * time.Second
const yapscanTimeout = 10 * time.Second

var memoryTesterCompiler *testutil.Compiler

func initializeMemoryTester() io.Closer {
	var err error
	memoryTesterCompiler, err = testutil.NewTesterCompiler()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testCompilerTimeout)
	memoryTesterCompiler.Compile(ctx)
	cancel()

	return memoryTesterCompiler
}

func withMemoryTester(t *testing.T, c C, data []byte) (pid int, addressOfData uintptr) {
	ctx, cancel := context.WithTimeout(context.Background(), testerTimeout)

	tester, err := testutil.NewTester(
		ctx,
		memoryTesterCompiler,
		data,
		procio.Permissions{Read: true}.String())
	if err != nil {
		t.Fatal("could not create memory tester process", err)
	}

	addressOfData, err = tester.WriteDataAndGetAddress()
	if err != nil || addressOfData == 0 {
		t.Fatal("could not write data to memory tester process", err)
	}

	if c != nil {
		c.Reset(func() {
			tester.Close()
			cancel()
		})
	} else {
		t.Cleanup(func() {
			tester.Close()
			cancel()
		})
	}

	return tester.PID(), addressOfData
}

func withMappedMemoryTester(t *testing.T, c C, mappedFile string, mapOffset, writeOffset int, data []byte) (pid int, addressOfData uintptr) {
	ctx, cancel := context.WithTimeout(context.Background(), testerTimeout)

	tester, err := testutil.NewMappedTester(
		ctx,
		memoryTesterCompiler,
		mappedFile, mapOffset, writeOffset,
		data,
		procio.Permissions{Read: true}.String())
	if err != nil {
		t.Fatal("could not create memory tester process", err)
	}

	addressOfData, err = tester.WriteDataAndGetAddress()
	if err != nil || addressOfData == 0 {
		t.Fatal("could not write data to memory tester process", err)
	}

	if c != nil {
		c.Reset(func() {
			tester.Close()
			cancel()
		})
	} else {
		t.Cleanup(func() {
			tester.Close()
			cancel()
		})
	}

	return tester.PID(), addressOfData
}

func withTempFile(t *testing.T, filename string, rules []byte) string {
	tempDir := t.TempDir()
	yaraRulesFile := filepath.Join(tempDir, filename)
	err := os.WriteFile(yaraRulesFile, rules, 0600)
	if err != nil {
		t.Fatal("could not write temporary file", err)
	}

	return yaraRulesFile
}

func withYaraRulesFile(t *testing.T, rules []byte) string {
	return withTempFile(t, "rules.yar", rules)
}

func withYaraRulesFileAndMatchingMemoryTester(t *testing.T, c C, data []byte) (yaraRulesPath string, pid int, addressOfData uintptr) {
	return withYaraRulesFileAndMemoryTester(t, c, data, data)
}

func withYaraRulesFileAndMatchingMappedMemoryTester(t *testing.T, c C, data []byte, fileData []byte, mapOffset, writeOffset int) (yaraRulesPath, mappedFilePath string, pid int, addressOfData uintptr) {
	return withYaraRulesFileAndMappedMemoryTester(t, c, data, fileData, mapOffset, writeOffset, data)
}

func withYaraRulesFileAndNotMatchingMemoryTester(t *testing.T, c C, data []byte) (yaraRulesPath string, pid int, addressOfData uintptr) {
	memoryData := make([]byte, len(data))
	copy(memoryData, data)

	replaceCount := rand.Intn(len(data)) + 1
	for i := 0; i < replaceCount; i++ {
		memoryData[rand.Intn(len(data))] ^= byte(rand.Intn(254) + 1)
	}

	return withYaraRulesFileAndMemoryTester(t, c, data, memoryData)
}

func withYaraRulesFileAndMemoryTester(t *testing.T, c C, ruleData []byte, memoryData []byte) (yaraRulesPath string, pid int, addressOfData uintptr) {
	ruleDataHexString := &strings.Builder{}
	for _, b := range ruleData {
		ruleDataHexString.WriteString(fmt.Sprintf("%02X ", b))
	}

	rule := fmt.Sprintf(`
rule rule1 {
    meta:
        description = "just a dummy rule"
        author = "some dude on the internet"
        date = "2020-01-01"

    strings:
        $str1 = { %s}

    condition:
        $str1
}
`, ruleDataHexString.String())

	yaraRulesPath = withYaraRulesFile(t, []byte(rule))
	pid, addressOfData = withMemoryTester(t, c, memoryData)
	return
}

func withYaraRulesFileAndMappedMemoryTester(t *testing.T, c C, ruleData []byte, fileData []byte, mapOffset, writeOffset int, memoryData []byte) (yaraRulesPath, mappedFilePath string, pid int, addressOfData uintptr) {
	ruleDataHexString := &strings.Builder{}
	for _, b := range ruleData {
		ruleDataHexString.WriteString(fmt.Sprintf("%02X ", b))
	}

	rule := fmt.Sprintf(`
rule rule1 {
    meta:
        description = "just a dummy rule"
        author = "some dude on the internet"
        date = "2020-01-01"

    strings:
        $str1 = { %s}

    condition:
        $str1
}
`, ruleDataHexString.String())

	yaraRulesPath = withYaraRulesFile(t, []byte(rule))
	mappedFilePath = withTempFile(t, "mapped.dat", fileData)
	pid, addressOfData = withMappedMemoryTester(t, c, mappedFilePath, mapOffset, writeOffset, memoryData)
	return
}

func withCapturedOutput(t *testing.T) (stdout, stderr *bytes.Buffer, cleanup func()) {
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal("could not create pipe for output capture", err)
	}
	origOut := os.Stdout
	os.Stdout = stdoutW

	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal("could not create pipe for output capture", err)
	}
	origErr := os.Stderr
	os.Stderr = stderrW

	stdoutB, stderrB := &bytes.Buffer{}, &bytes.Buffer{}

	startWG := &sync.WaitGroup{}
	endWG := &sync.WaitGroup{}

	copyFunc := func(dst io.Writer, src io.Reader) {
		startWG.Done()
		defer endWG.Done()
		io.Copy(dst, src)
	}
	startWG.Add(2)
	endWG.Add(2)
	go copyFunc(stdoutB, stdoutR)
	go copyFunc(stderrB, stderrR)

	startWG.Wait()

	return stdoutB, stderrB, func() {
		os.Stdout = origOut
		os.Stderr = origErr

		stdoutW.Close()
		stdoutR.Close()
		stderrW.Close()
		stderrR.Close()
		endWG.Wait()
	}
}

func findMemorySegment(address uintptr, segs []*procio.MemorySegmentInfo) *procio.MemorySegmentInfo {
	for _, seg := range segs {
		if seg.BaseAddress <= address && address < seg.BaseAddress+seg.Size {
			return seg
		}
	}
	return nil
}
