package app

import (
	"fmt"
	"strconv"

	"github.com/fkie-cad/yapscan/procio"
	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

func crashProcess(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	if c.NArg() != 1 {
		return errors.Newf("expected exactly one arguments, got %d", c.NArg())
	}
	pid_, err := strconv.ParseUint(c.Args().Get(0), 10, 64)
	if err != nil {
		return errors.Newf("\"%s\" is not a pid", c.Args().Get(0))
	}
	pid := int(pid_)

	crashMethod, err := procio.ParseCrashMethod(c.String("method"))
	if err != nil {
		return fmt.Errorf("invalid parameter, %w", err)
	}

	proc, err := procio.OpenProcess(pid)
	if err != nil {
		return errors.Newf("could not open process %d, reason: %w", pid, err)
	}

	return proc.Crash(crashMethod)
}
