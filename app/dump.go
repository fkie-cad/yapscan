package app

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"

	"github.com/fkie-cad/yapscan/procio"
	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

func dumpMemory(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	filter, err := filterFromArgs(c)
	if err != nil {
		return err
	}

	var dumper io.WriteCloser
	if c.Bool("raw") {
		dumper = os.Stdout
	} else {
		dumper = hex.Dumper(os.Stdout)
		defer dumper.Close()
	}

	if c.NArg() != 1 && c.NArg() != 2 {
		return errors.Newf("expected exactly one or two arguments, got %d", c.NArg())
	}
	pid, err := strconv.Atoi(c.Args().Get(0))
	if err != nil {
		return errors.Newf("\"%s\" is not a pid", c.Args().Get(0))
	}

	var addr uintptr
	allSegments := c.NArg() < 2
	if !allSegments {
		_, err = fmt.Sscan(c.Args().Get(1), &addr)
		if err != nil {
			return errors.Newf("\"%s\" is not an address", c.Args().Get(1))
		}
	}

	proc, err := procio.OpenProcess(pid)
	if err != nil {
		return errors.Newf("could not open process %d, reason: %w", pid, err)
	}

	baseSegments, err := proc.MemorySegments()
	if err != nil {
		return errors.Newf("could not retrieve memory segments of process %d, reason: %w", pid, err)
	}
	// Unpack segments
	segments := make([]*procio.MemorySegmentInfo, 0, len(baseSegments))
	for _, seg := range baseSegments {
		if seg.SubSegments == nil || len(seg.SubSegments) == 0 {
			segments = append(segments, seg)
		} else {
			segments = append(segments, seg.SubSegments...)
		}
	}

	readContiguous := c.Int("contiguous")
	found := false
	for i, seg := range segments {
		if seg.BaseAddress == addr || allSegments {
			found = true
		}
		fmt.Printf("0x%08X: ", seg.BaseAddress)
		match := filter.Filter(seg)
		if allSegments && !match.Result {
			fmt.Println("skipping, " + match.Reason)
			continue
		}
		if found {
			rdr, err := procio.NewMemoryReader(proc, seg)
			if err != nil {
				fmt.Println(errors.Newf("could not read memory of process %d at address 0x%016X, reason %w", pid, seg.BaseAddress, err))
				continue
			}

			if c.Bool("store") {
				fname := fmt.Sprintf("%d_%s_0x%X.bin", pid, seg.CurrentPermissions.String(), seg.BaseAddress)
				path := path.Join(c.String("storage-dir"), fname)
				outfile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0666)
				if err != nil {
					fmt.Println(errors.Newf("could not create dump file \"%s\", reason: %w", path, err))
					continue
				}
				_, err = io.Copy(outfile, rdr)
				outfile.Close()
				if err != nil {
					fmt.Println(errors.Newf("could not dump segment to file \"%s\", reason: %w", path, err))
					continue
				}
				fmt.Printf("dumped to \"%s\"\n", path)
			} else {
				_, err = io.Copy(dumper, rdr)
				if err != nil {
					return errors.Newf("could not read memory of process %d at address 0x%016X, reason %w", pid, seg.BaseAddress, err)
				}
			}

			if !allSegments &&
				(readContiguous == 0 || (i+1 < len(segments) && segments[i+1].BaseAddress != seg.BaseAddress+seg.Size)) {
				// Next segment is not contiguous
				break
			}
			readContiguous--
		}
	}
	if !found {
		errors.Newf("process %d has no memory segment starting with address 0x%016X", pid, addr)
	}
	return nil
}
