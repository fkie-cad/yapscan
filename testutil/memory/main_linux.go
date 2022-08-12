package memory

import (
	"fmt"
	"io"
	"os"

	"github.com/fkie-cad/yapscan/procio"
	"github.com/fkie-cad/yapscan/testutil"
	"github.com/urfave/cli/v2"
)

func mapFileAction(c *cli.Context) error {
	filename := ""
	if c.NArg() >= 1 {
		filename = c.Args().First()
	}

	mapFile := c.String("file")
	stat, err := os.Stat(mapFile)
	if err != nil {
		return err
	}
	size := uint64(stat.Size())
	inputSize := c.Uint64("size")
	perms, err := procio.ParsePermissions(c.String("prot"))
	if err != nil {
		return err
	}
	prot := uint64(procio.PermissionsToNative(perms))
	mapOffset := c.Uint64("map-offset")
	writeOffset := c.Uint64("write-offset")

	addr, size, closer, err := mmap(mapFile, mapOffset)
	if err != nil {
		fmt.Printf(testutil.OutputErrorPrefix+"Could not alloc with size %d, reason: %v\n", size, err)
		return cli.Exit("", 5)
	}
	defer closer()

	fmt.Printf("Allocated: 0x%X\n", addr)
	os.Stdout.Sync()

	data, err := readData(filename, int(inputSize))

	memcpy(addr+uintptr(writeOffset), data)

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
