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
	for i, pid := range pids {
		info := &procIO.ProcessInfo{
			PID:              pid,
			ExecutablePath:   "ERROR",
			ExecutableMD5:    "ERROR",
			ExecutableSHA256: "ERROR",
			Username:         "ERROR",
			MemorySegments:   nil,
		}

		proc, err := procIO.OpenProcess(pid)
		if err == nil {
			tmp, err := proc.Info()
			if err == nil {
				info = tmp
			}
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

	headerFmt := fmt.Sprintf("%%%ds %%-%ds %%-%ds\n", maxPidlen, maxNamelen, maxUserlen)
	rowFmt := fmt.Sprintf("%%%dd %%-%ds %%-%ds\n", maxPidlen, maxNamelen, maxUserlen)
	fmt.Printf(headerFmt, "PID", "Name", "User")
	fmt.Println(strings.Repeat("-", maxPidlen) + "+" + strings.Repeat("-", maxNamelen) + "+" + strings.Repeat("-", maxUserlen))
	for _, info := range procInfos {
		fmt.Printf(rowFmt, info.PID, filepath.Base(info.ExecutablePath), info.Username)
	}

	return nil
}
