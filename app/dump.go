package app

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"

	"github.com/fkie-cad/yapscan/procIO"

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
	pid_, err := strconv.ParseUint(c.Args().Get(0), 10, 64)
	if err != nil {
		return errors.Newf("\"%s\" is not a pid", c.Args().Get(0))
	}
	pid := int(pid_)

	var addr uintptr
	allSegments := c.NArg() < 2
	if !allSegments {
		_, err = fmt.Sscan(c.Args().Get(1), &addr)
		if err != nil {
			return errors.Newf("\"%s\" is not an address", c.Args().Get(1))
		}
	}

	proc, err := procIO.OpenProcess(pid)
	if err != nil {
		return errors.Newf("could not open process %d, reason: %w", pid, err)
	}

	baseSegments, err := proc.MemorySegments()
	if err != nil {
		return errors.Newf("could not retrieve memory segments of process %d, reason: %w", pid, err)
	}
	// Unpack segments
	segments := make([]*procIO.MemorySegmentInfo, 0, len(baseSegments))
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
		match := filter.Filter(seg)
		if allSegments && !match.Result {
			continue
		}
		if found {
			rdr, err := procIO.NewMemoryReader(proc, seg)
			if err != nil {
				return errors.Newf("could not read memory of process %d at address 0x%016X, reason %w", pid, seg.BaseAddress, err)
			}

			if c.Bool("store") {
				fname := fmt.Sprintf("%d_%s_0x%X.bin", pid, seg.CurrentPermissions.String(), seg.BaseAddress)
				path := path.Join(c.String("storage-dir"), fname)
				outfile, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0666)
				if err != nil {
					return errors.Newf("could not create dump file \"%s\", reason: %w", path, err)
				}
				_, err = io.Copy(outfile, rdr)
				outfile.Close()
				if err != nil {
					return errors.Newf("could not dump segment to file \"%s\", reason: %w", path, err)
				}
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
