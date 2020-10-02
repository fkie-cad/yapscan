package app

import (
	"fmt"
	"fraunhofer/fkie/yapscan/procIO"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

func listProcesses(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	pids, err := procIO.GetRunningPIDs()
	if err != nil {
		return errors.Newf("could not enumerate PIDs, reason: %w", err)
	}

	procInfos := make([]*procIO.ProcessInfo, len(pids))
	maxPidlen := 0
	maxNamelen := 0
	maxUserlen := 0
	errorsOutput := false
	for i, pid := range pids {
		// Default info in case of errors
		info := &procIO.ProcessInfo{
			PID:              pid,
			ExecutablePath:   "ERROR",
			ExecutableMD5:    "ERROR",
			ExecutableSHA256: "ERROR",
			Username:         "ERROR",
			MemorySegments:   nil,
		}

		proc, err := procIO.OpenProcess(pid)
		if err != nil {
			err = errors.Newf("could not open process %d, reason: %w", pid, err)
		} else {
			tmp, err := proc.Info()
			if err != nil {
				err = errors.Newf("could not query info of process %d, reason: %w", pid, err)
			} else {
				info = tmp
			}
			proc.Close()
		}
		if c.Bool("verbose") && err != nil {
			errorsOutput = true
			fmt.Println(err)
		}

		procInfos[i] = info
		pidLen := len(strconv.Itoa(pid))
		if maxPidlen < pidLen {
			maxPidlen = pidLen
		}
		namelen := len(filepath.Base(info.ExecutablePath))
		if maxNamelen < namelen {
			maxNamelen = namelen
		}
		userlen := len(info.Username)
		if maxUserlen < userlen {
			maxUserlen = userlen
		}
	}

	if maxPidlen < 5 {
		maxPidlen = 5
	}

	if errorsOutput {
		// Extra empty line for readability
		fmt.Println()
	}

	headerFmt := fmt.Sprintf("%%%ds %%3v %%-%ds %%-%ds\n", maxPidlen, maxNamelen, maxUserlen)
	rowFmt := fmt.Sprintf("%%%dd %%3v %%-%ds %%-%ds\n", maxPidlen, maxNamelen, maxUserlen)
	fmt.Printf(headerFmt, "PID", "Bit", "Name", "User")
	fmt.Println(strings.Repeat("-", maxPidlen) + "+" + strings.Repeat("-", 3) + "+" + strings.Repeat("-", maxNamelen) + "+" + strings.Repeat("-", maxUserlen))
	for _, info := range procInfos {
		fmt.Printf(rowFmt, info.PID, info.Bitness.Short(), filepath.Base(info.ExecutablePath), info.Username)
	}

	return nil
}
