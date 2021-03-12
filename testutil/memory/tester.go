package memory

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/targodan/go-errors"
)

const (
	OutputErrorPrefix   = "ERROR: "
	OutputReady         = "READY"
	OutputAddressPrefix = "ADDRESS: "
)

func getMemtestPath() (string, error) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("could not determine caller")
	}

	dir := filepath.Dir(filename)
	path := filepath.Join(dir, "..", "..", "cmd", "memtest", "main.go")

	// See if it exists for early exit
	_, err := os.Stat(path)

	return path, err
}

type TesterCompiler struct {
	srcPath  string
	binPath  string
	compiled bool
}

func memtestUtilBinaryName() string {
	name := "yapscan-memtest-util"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

func NewTesterCompiler() (*TesterCompiler, error) {
	srcPath, err := getMemtestPath()
	if err != nil {
		return nil, fmt.Errorf("could not determine path to main.go, reason: %w", err)
	}

	binPath := filepath.Join(os.TempDir(), memtestUtilBinaryName())

	return &TesterCompiler{
		srcPath:  srcPath,
		binPath:  binPath,
		compiled: false,
	}, nil
}

func (c *TesterCompiler) Compile(ctx context.Context) error {
	cmd := exec.CommandContext(ctx,
		"go", "build", "-o", c.binPath, c.srcPath)
	output, err := cmd.Output()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok {
			return fmt.Errorf("could not build test utility\n==== STDOUT ====\n%s\n==== STDERR ====\n%s", output, exitErr.Stderr)
		} else {
			return fmt.Errorf("could not build test utility, reason: %w", err)
		}
	}

	c.compiled = true
	return nil
}

func (c *TesterCompiler) BinaryPath() string {
	if !c.compiled {
		panic("binary path not available, compile first")
	}
	return c.binPath
}

func (c *TesterCompiler) Close() error {
	if c.compiled {
		return os.Remove(c.binPath)
	}
	return nil
}

type Tester struct {
	ctx context.Context

	cmd       *exec.Cmd
	cmdCtx    context.Context
	cmdCancel context.CancelFunc

	cmdIn  io.WriteCloser
	cmdOut io.ReadCloser

	out *bufio.Reader

	data []byte
}

func NewTester(ctx context.Context, c *TesterCompiler, data []byte, nativePermis uintptr) (*Tester, error) {
	cmdCtx, cmdCancel := context.WithCancel(ctx)

	cmd := exec.CommandContext(ctx,
		c.BinaryPath(),
		fmt.Sprintf("%d", len(data)), fmt.Sprintf("%d", nativePermis))

	cmdIn, err := cmd.StdinPipe()
	if err != nil {
		cmdCancel()
		return nil, fmt.Errorf("could not create process pipe, reason: %w", err)
	}
	cmdOut, err := cmd.StdoutPipe()
	if err != nil {
		cmdIn.Close()
		cmdCancel()
		return nil, fmt.Errorf("could not create process pipe, reason: %w", err)
	}

	t := &Tester{
		ctx: ctx,

		cmd:       cmd,
		cmdCtx:    cmdCtx,
		cmdCancel: cmdCancel,

		cmdIn:  cmdIn,
		cmdOut: cmdOut,

		out: bufio.NewReader(cmdOut),

		data: data,
	}

	err = t.cmd.Start()
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("could not start memtester process, reason: %w", err)
	}

	return t, nil
}

func (t *Tester) Close() error {
	t.cmdIn.Close()
	t.cmdOut.Close()

	t.cmd.Wait()
	t.cmdCancel()

	return nil
}

func (t *Tester) PID() int {
	return t.cmd.Process.Pid
}

func (t *Tester) waitForPrefix(prefix string) (string, error) {
	for {
		select {
		case <-t.ctx.Done():
			return "", t.ctx.Err()
		default:
		}

		line, err := t.out.ReadString('\n')
		if err != nil {
			return "", err
		}

		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			// Found it
			return line, nil
		}
		if strings.HasPrefix(line, OutputErrorPrefix) {
			// Found an error
			return "", errors.New(line[len(OutputErrorPrefix):])
		}
	}
}

func (t *Tester) writeData() error {
	_, err := t.waitForPrefix(OutputReady)
	if err != nil {
		return fmt.Errorf("command did not become READY for data input, reason: %w", err)
	}

	_, err = io.Copy(t.cmdIn, bytes.NewBuffer(t.data))
	if err != nil {
		return fmt.Errorf("encountered error during writing data: %w", err)
	}

	return nil
}

func (t *Tester) getMemoryAddress() (uintptr, error) {
	addressLine, err := t.waitForPrefix(OutputAddressPrefix)
	if err != nil {
		return 0, fmt.Errorf("command did not report memory address: %w", err)
	}

	address, err := strconv.ParseUint(addressLine[len(OutputAddressPrefix):], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("could not parse memory address: %w", err)
	}
	return uintptr(address), nil
}

func (t *Tester) WriteDataAndGetAddress() (uintptr, error) {
	err := t.writeData()
	if err != nil {
		return 0, err
	}

	return t.getMemoryAddress()
}
