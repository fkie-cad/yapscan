package app

import (
	"fmt"
	"fraunhofer/fkie/yapscan/procIO"
	"strconv"

	"github.com/dustin/go-humanize"
	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

func listMemory(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	if c.NArg() != 1 {
		return errors.Newf("expected exactly one argument, got %d", c.NArg())
	}
	pid_, err := strconv.ParseUint(c.Args().Get(0), 10, 64)
	if err != nil {
		return errors.Newf("\"%s\" is not a pid", c.Args().Get(0))
	}
	pid := int(pid_)

	f, err := filterFromArgs(c)
	if err != nil {
		return err
	}

	proc, err := procIO.OpenProcess(pid)
	if err != nil {
		return errors.Newf("could not open process with pid %d, reason: %w", pid, err)
	}

	segments, err := proc.MemorySegments()
	if err != nil {
		return errors.Newf("could not enumerate memory segments of process %d, reason: %w", pid, err)
	}
	for _, seg := range segments {
		fRes := f.Filter(seg)
		if !fRes.Result {
			continue
		}

		format := "%19s %8s %3s %7s %7s %s\n"

		fmt.Printf(format, procIO.FormatMemorySegmentAddress(seg), humanize.Bytes(uint64(seg.Size)), seg.CurrentPermissions, seg.Type, seg.State, seg.FilePath)

		if c.Bool("list-subdivided") {
			for i, sseg := range seg.SubSegments {
				addr := procIO.FormatMemorySegmentAddress(sseg)
				if i+1 < len(seg.SubSegments) {
					addr = "├" + addr
				} else {
					addr = "└" + addr
				}

				fmt.Printf(format, addr, humanize.Bytes(uint64(sseg.Size)), sseg.CurrentPermissions, sseg.Type, sseg.State, sseg.FilePath)
			}
		}
	}

	return nil
}
