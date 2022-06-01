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
	pid, err := strconv.Atoi(c.Args().Get(0))
	if err != nil {
		return errors.Newf("\"%s\" is not a pid", c.Args().Get(0))
	}

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
