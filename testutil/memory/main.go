package memory

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"strconv"
)

func Main() {
	if len(os.Args) < 3 {
		fmt.Println(OutputErrorPrefix + "Invalid arguments")
		fmt.Printf("Usage: %s <size> <native_memprotect> [file]\n", os.Args[0])
		os.Exit(1)
	}

	filename := ""
	if len(os.Args) >= 4 {
		filename = os.Args[3]
	}

	ensureStdinBinary()

	size, err := strconv.ParseUint(os.Args[1], 10, 64)
	if err != nil {
		fmt.Printf(OutputErrorPrefix+"Invalid size value, %v\n", err)
		os.Exit(1)
	}

	prot, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil {
		fmt.Printf(OutputErrorPrefix+"Invalid protect value, %v\n", err)
		os.Exit(1)
	}

	addr, err := alloc(size)
	if err != nil {
		fmt.Printf(OutputErrorPrefix+"Could not alloc, reason: %v\n", err)
		os.Exit(5)
	}
	defer func() {
		free(addr, size)
	}()

	// Round up to next 4096
	segmentSize := uint64(math.Ceil(float64(size)/4096.) * 4096.)

	memset(addr, 0xAA, size)
	memset(addr+uintptr(size), 0xBB, segmentSize-size)

	fmt.Printf("Allocated: 0x%X\n", addr)

	data := bytes.Repeat([]byte{0xA1}, int(size))

	if filename != "" {
		f, err := os.Open(filename)
		if err != nil {
			fmt.Printf(OutputErrorPrefix+"Could not open file, reason: %v\n", err)
			os.Exit(2)
		}
		data, err = ioutil.ReadAll(f)
		if err != nil {
			fmt.Printf(OutputErrorPrefix+"Could not read from file, reason: %v\n", err)
			os.Exit(3)
		}
		f.Close()

		size = uint64(len(data))
	} else {
		fmt.Println(OutputReady)
		data, err = ioutil.ReadAll(io.LimitReader(os.Stdin, int64(size)))
		if err != nil {
			fmt.Printf(OutputErrorPrefix+"Could not read from stdin, reason: %v\n", err)
			os.Exit(4)
		}
		if uint64(len(data)) != size {
			fmt.Printf(OutputErrorPrefix+"Invalid number of bytes received! Expected %d, got %d!\n", size, len(data))
			os.Exit(4)
		}
	}

	memcpy(addr, data)

	protect(addr, size, prot)
	if err != nil {
		fmt.Printf(OutputErrorPrefix+"Failed to set protect, reason: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf(OutputAddressPrefix+"%d\n", addr)

	if filename != "" {
		fmt.Println("Press Enter to close application...")
		// Wait for user enter
		fmt.Scanln()
	} else {
		// Wait for stdin close
		ioutil.ReadAll(os.Stdin)
	}
}
