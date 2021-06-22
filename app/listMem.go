package app

import (
	"fmt"
	"strconv"

	"github.com/dustin/go-humanize"
	"github.com/fkie-cad/yapscan/procio"
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

	fmt.Printf("Filters: %s\n\n", f.Description())

	proc, err := procio.OpenProcess(pid)
	if err != nil {
		return errors.Newf("could not open process with pid %d, reason: %w", pid, err)
	}

	format := "%19s %8s %8s %3s %13s %7s %s\n"
	fmt.Printf(format, "Address", "Size", "RSS", "", "Type", "State", "Path")
	fmt.Printf("-------------------+--------+--------+---+-------------+-------+------\n")

	segments, err := proc.MemorySegments()
	if err != nil {
		return errors.Newf("could not enumerate memory segments of process %d, reason: %w", pid, err)
	}
	for _, seg := range segments {
		fRes := f.Filter(seg)
		if !fRes.Result {
			continue
		}

		filepath := ""
		if seg.MappedFile != nil {
			filepath = seg.MappedFile.Path()
		}

		fmt.Printf(format, procio.FormatMemorySegmentAddress(seg), humanize.Bytes(uint64(seg.Size)), humanize.Bytes(uint64(seg.RSS)), seg.CurrentPermissions, seg.Type, seg.State, filepath)

		if c.Bool("list-subdivided") {
			for i, sseg := range seg.SubSegments {
				addr := procio.FormatMemorySegmentAddress(sseg)
				if i+1 < len(seg.SubSegments) {
					addr = "├" + addr
				} else {
					addr = "└" + addr
				}

				filepath = ""
				if sseg.MappedFile != nil {
					filepath = sseg.MappedFile.Path()
				}

				fmt.Printf(format, addr, humanize.Bytes(uint64(sseg.Size)), sseg.CurrentPermissions, sseg.Type, sseg.State, filepath)
			}
		}
	}

	return nil
}
