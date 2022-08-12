package testutil

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	root, err := GetProjectRoot()
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, "cmd", "memtest", "main.go")

	// See if it exists for early exit
	_, err = os.Stat(path)

	return path, err
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

func NewTesterCompiler() (*Compiler, error) {
	srcPath, err := getMemtestPath()
	if err != nil {
		return nil, fmt.Errorf("could not determine path to main.go, reason: %w", err)
	}
	return NewCompiler(srcPath)
}

func NewTester(ctx context.Context, c *Compiler, data []byte, perms string) (*Tester, error) {
	cmdCtx, cmdCancel := context.WithCancel(ctx)
	cmd := makeTesterCommand(cmdCtx, c, data, perms)
	return newTester(ctx, cmdCtx, cmd, cmdCancel, data)
}

func NewMappedTester(ctx context.Context, c *Compiler, mappedFile string, mapOffset, writeOffset int, data []byte, perms string) (*Tester, error) {
	cmdCtx, cmdCancel := context.WithCancel(ctx)
	cmd := makeMappedTesterCommand(cmdCtx, c, data, perms, mappedFile, mapOffset, writeOffset)
	return newTester(ctx, cmdCtx, cmd, cmdCancel, data)
}

func makeTesterCommand(ctx context.Context, c *Compiler, data []byte, perms string) *exec.Cmd {
	return exec.CommandContext(ctx,
		c.BinaryPath(),
		"alloc",
		"--size", fmt.Sprintf("%d", len(data)),
		"--prot", perms)
}

func makeMappedTesterCommand(ctx context.Context, c *Compiler, data []byte, perms string, mapfilePath string, mapOffset, writeOffset int) *exec.Cmd {
	return exec.CommandContext(ctx,
		c.BinaryPath(),
		"map-file",
		"--file", mapfilePath,
		"--size", fmt.Sprintf("%d", len(data)),
		"--map-offset", fmt.Sprintf("%d", mapOffset),
		"--write-offset", fmt.Sprintf("%d", writeOffset),
		"--prot", perms)
}

func newTester(ctx context.Context, cmdCtx context.Context, cmd *exec.Cmd, cmdCancel func(), data []byte) (*Tester, error) {
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
