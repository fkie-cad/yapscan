package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"

	"github.com/targodan/go-errors"
	"github.com/urfave/cli/v2"
)

type dumpInput struct {
	Filename string
	Basename string
	File     *os.File
	PID      int
	Address  uintptr
	Size     uintptr
}

type paddingReader struct {
	Padding byte
}

func (r *paddingReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = r.Padding
	}
	return len(p), nil
}

func join(c *cli.Context) error {
	err := initAppAction(c)
	if err != nil {
		return err
	}

	var padding byte
	_, err = fmt.Sscan(c.String("padding"), &padding)
	if err != nil {
		return errors.Newf("invalid padding \"%s\", %w", c.String("padding"), err)
	}

	if c.NArg() == 0 {
		return errors.New("expected at least one dump file")
	}

	nameRex := regexp.MustCompile(`^([0-9]+)_[RWCX-]{3}_(0x[A-F0-9]+).bin$`)

	outFilename := c.String("output")
	customOutFilename := outFilename != ""

	rawFilenames := c.Args().Slice()
	inFilenames := make([]string, 0, len(rawFilenames))
	// Attempt to resolve wildcards for cases where the shell does not.
	for _, fname := range rawFilenames {
		names, err := filepath.Glob(fname)
		if err != nil {
			// Could not glob, use normal name
			inFilenames = append(inFilenames, fname)
		} else {
			inFilenames = append(inFilenames, names...)
		}
	}

	inFiles := make([]*dumpInput, len(inFilenames))
	for i, filename := range inFilenames {
		basename := filepath.Base(filename)
		parts := nameRex.FindStringSubmatch(basename)
		if parts == nil || len(parts) != 3 {
			return errors.Newf("could not parse filename \"%s\", please make sure the input files are named in the same way the dump command uses for its output files", basename)
		}
		pid, err := strconv.Atoi(parts[1])
		if err != nil {
			return errors.Newf("could not parse pid in filename \"%s\", please make sure the input files are named in the same way the dump command uses for its output files", basename)
		}
		var addr uintptr
		_, err = fmt.Sscan(parts[2], &addr)
		if err != nil {
			return errors.Newf("could not parse address in filename \"%s\", please make sure the input files are named in the same way the dump command uses for its output files", basename)
		}

		if !customOutFilename {
			if outFilename == "" {
				outFilename = parts[1]
			} else if outFilename != parts[1] {
				return errors.Newf("not all input files belong to the same process")
			}
		}

		file, err := os.OpenFile(filename, os.O_RDONLY, 0666)
		if err != nil {
			return errors.Newf("could not open file \"%s\", reason: %w", filename, err)
		}
		defer file.Close()

		fStat, err := os.Stat(filename)
		if err != nil {
			return errors.Newf("could not determine size of file \"%s\", reason: %w", filename, err)
		}

		inFiles[i] = &dumpInput{
			Filename: filename,
			Basename: basename,
			File:     file,
			PID:      pid,
			Address:  addr,
			Size:     uintptr(fStat.Size()),
		}
	}

	sort.Slice(inFiles, func(i, j int) bool {
		return inFiles[i].Address < inFiles[j].Address
	})

	if !customOutFilename {
		outFilename += fmt.Sprintf("_0x%X.bin", inFiles[0].Address)
	}

	fmt.Printf("Output file: \"%s\"\n", outFilename)

	out, err := os.OpenFile(outFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return errors.Newf("could not open output file, reason: %w", err)
	}
	defer out.Close()

	padder := &paddingReader{padding}

	for i, file := range inFiles {
		fmt.Printf("Copying \"%s\", size 0x%X.\n", file.Filename, file.Size)

		_, err = io.Copy(out, file.File)
		if err != nil {
			return errors.Newf("could not copy from infile \"%s\" to outfile \"%s\", reason: %w", file.Filename, outFilename, err)
		}

		if i+1 < len(inFiles) {
			padCount := int64(inFiles[i+1].Address) - int64(file.Address+file.Size)
			if padCount < 0 {
				return errors.Newf("input files \"%s\" and \"%s\" are overlapping", file.Filename, inFiles[i+1].Filename)
			}

			if padCount > 0 {
				fmt.Printf("Padding 0x%X * 0x%X.\n", padCount, padding)
			}

			n, err := io.CopyN(out, padder, padCount)
			if n != padCount || err != nil {
				return errors.Newf("could not write padding, reason: %w", err)
			}
		}
	}

	fmt.Println("Done.")

	return nil
}
