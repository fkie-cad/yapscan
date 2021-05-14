package testutil

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
)

type Compiler struct {
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

func NewCompiler(srcPath string) (*Compiler, error) {
	pattern := "yapscan_*"
	if runtime.GOOS == "windows" {
		pattern += ".exe"
	}

	tmpFile, err := ioutil.TempFile(os.TempDir(), pattern)
	if err != nil {
		return nil, err
	}
	binPath := tmpFile.Name()
	tmpFile.Close()

	return &Compiler{
		srcPath:  srcPath,
		binPath:  binPath,
		compiled: false,
	}, nil
}

func (c *Compiler) Compile(ctx context.Context) error {
	cmd := exec.CommandContext(ctx,
		"go", "build", "-o", c.binPath, c.srcPath)
	output, err := cmd.Output()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if ok {
			return fmt.Errorf("could not build %s\n==== STDOUT ====\n%s\n==== STDERR ====\n%s", c.srcPath, output, exitErr.Stderr)
		} else {
			return fmt.Errorf("could not build %s, reason: %w", c.srcPath, err)
		}
	}

	c.compiled = true
	return nil
}

func (c *Compiler) BinaryPath() string {
	if !c.compiled {
		panic("binary path not available, compile first")
	}
	return c.binPath
}

func (c *Compiler) Close() error {
	if c.compiled {
		return os.Remove(c.binPath)
	}
	return nil
}
