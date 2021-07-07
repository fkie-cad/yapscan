package app

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/dustin/go-humanize"

	"github.com/fkie-cad/yapscan/procio"
	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

func listProcesses(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	f, err := filterFromArgs(c)
	if err != nil {
		return err
	}

	fmt.Printf("Filters: %s\n\n", f.Description())

	pids, err := procio.GetRunningPIDs()
	if err != nil {
		return errors.Newf("could not enumerate PIDs, reason: %w", err)
	}

	rowFmt := "%7v %3v %-32s %-32s %7v %7v\n"

	fmt.Printf(rowFmt, "PID", "Bit", "Name", "User", "RSS", "RAM to be Scanned")
	fmt.Println(strings.Repeat("-", 7) + "+" + strings.Repeat("-", 3) + "+" + strings.Repeat("-", 32) + "+" + strings.Repeat("-", 32) + "+" + strings.Repeat("-", 7) + "+" + strings.Repeat("-", 7))

	var estimatedRAMIncrease uintptr
	errorsOutput := false
	for _, pid := range pids {
		// Default info in case of errors
		info := &procio.ProcessInfo{
			PID:              pid,
			ExecutablePath:   "ERROR",
			ExecutableMD5:    "ERROR",
			ExecutableSHA256: "ERROR",
			Username:         "ERROR",
			MemorySegments:   nil,
		}

		proc, err := procio.OpenProcess(pid)
		if err != nil {
			err = errors.Newf("could not open process %d, reason: %w", pid, err)
		} else {
			var tmp *procio.ProcessInfo
			tmp, err = proc.Info()
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

		var rss, toBeScanned uintptr
		for _, seg := range info.MemorySegments {
			rss += seg.RSS

			fRes := f.Filter(seg)
			if !fRes.Result {
				continue
			}

			estimatedRAMIncrease += seg.EstimateRAMIncreaseByScanning()
			toBeScanned += seg.Size
		}

		fmt.Printf(rowFmt, info.PID, info.Bitness.Short(), filepath.Base(info.ExecutablePath), info.Username, humanize.Bytes(uint64(rss)), humanize.Bytes(uint64(toBeScanned)))
	}

	if errorsOutput {
		// Extra empty line for readability
		fmt.Println()
	}

	fmt.Printf("\nEstimated RAM increase by scanning all process: %s\n", humanize.Bytes(uint64(estimatedRAMIncrease)))

	return nil
}
