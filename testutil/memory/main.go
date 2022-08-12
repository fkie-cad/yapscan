package memory

import (
	"fmt"
	"io"
	"math"
	"os"

	"github.com/fkie-cad/yapscan/testutil"

	"github.com/fkie-cad/yapscan/procio"

	"github.com/urfave/cli/v2"
)

func Main() {
	commonFlags := []cli.Flag{
		&cli.StringFlag{
			Name:  "prot",
			Usage: "memprotect value",
			Value: "RWX",
		},
		&cli.Uint64Flag{
			Name:     "size",
			Usage:    "size in bytes of the expected input data",
			Required: true,
		},
	}

	app := &cli.App{
		Name: "testmem",
		Commands: []*cli.Command{
			{
				Name:      "alloc",
				Flags:     commonFlags,
				ArgsUsage: "[input-file]",
				Action:    allocAction,
			},
			{
				Name: "map-file",
				Flags: append([]cli.Flag{
					&cli.StringFlag{
						Name:  "file",
						Usage: "file to map",
					},
					&cli.Uint64Flag{
						Name:  "map-offset",
						Usage: "the mapping offset in the file",
						Value: 0,
					},
					&cli.Uint64Flag{
						Name:  "write-offset",
						Usage: "the offset where to write the input data",
						Value: 0,
					},
				}, commonFlags...),
				ArgsUsage: "[input-file]",
				Action:    mapFileAction,
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func readData(filename string, size int) ([]byte, error) {
	if filename != "" {
		f, err := os.Open(filename)
		defer f.Close()

		if err != nil {
			fmt.Printf(testutil.OutputErrorPrefix+"Could not open file, reason: %v\n", err)
			return nil, cli.Exit("", 4)
		}
		data, err := io.ReadAll(f)
		if err != nil {
			fmt.Printf(testutil.OutputErrorPrefix+"Could not read from file, reason: %v\n", err)
			return nil, cli.Exit("", 4)
		}

		return data, err
	} else {
		ensureStdinBinary()

		fmt.Println(testutil.OutputReady)
		os.Stdout.Sync()

		data, err := io.ReadAll(io.LimitReader(os.Stdin, int64(size)))
		if err != nil {
			fmt.Printf(testutil.OutputErrorPrefix+"Could not read from stdin, reason: %v\n", err)
			return nil, cli.Exit("", 4)
		}
		if len(data) != size {
			fmt.Printf(testutil.OutputErrorPrefix+"Invalid number of bytes received! Expected %d, got %d!\n", size, len(data))
			return nil, cli.Exit("", 4)
		}
		return data, err
	}
}

func allocAction(c *cli.Context) error {
	filename := ""
	if c.NArg() >= 1 {
		filename = c.Args().First()
	}

	size := c.Uint64("size")
	perms, err := procio.ParsePermissions(c.String("prot"))
	if err != nil {
		return err
	}
	prot := uint64(procio.PermissionsToNative(perms))

	addr, err := alloc(size)
	if err != nil {
		fmt.Printf(testutil.OutputErrorPrefix+"Could not alloc with size %d, reason: %v\n", size, err)
		return cli.Exit("", 5)
	}
	defer func() {
		free(addr, size)
	}()

	pagesize := os.Getpagesize()
	// Round up to next page
	segmentSize := uint64(math.Ceil(float64(size)/float64(pagesize)) * float64(pagesize))

	memset(addr, 0xAA, size)
	memset(addr+uintptr(size), 0xBB, segmentSize-size)

	fmt.Printf("Allocated: 0x%X\n", addr)
	os.Stdout.Sync()

	data, err := readData(filename, int(size))

	memcpy(addr, data)

	// Avoid multiple matches
	for i := range data {
		data[i] = 0xAA
	}

	err = protect(addr, size, prot)
	if err != nil {
		fmt.Printf(testutil.OutputErrorPrefix+"Failed to set protect, reason: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf(testutil.OutputAddressPrefix+"%d\n", addr)
	os.Stdout.Sync()

	if filename != "" {
		fmt.Println("Press Enter to close application...")
		// Wait for user enter
		fmt.Scanln()
	} else {
		// Wait for stdin close
		io.ReadAll(os.Stdin)
	}
	return nil
}
