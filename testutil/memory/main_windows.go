package memory

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

//#include <memory.h>
//#include <stdio.h>
//#include <stdint.h>
//
// void makeStdinBinary() {
//     freopen(NULL, "rb", stdin);
// }
// void my_memcpy(void* dst, const void* src, const size_t bytes) {
//     uint8_t* dst_bytes = (uint8_t*)dst;
//     const uint8_t* src_bytes = (const uint8_t*)src;
//     for(int i = 0; i < bytes; ++i) {
//	       dst_bytes[i] = src_bytes[i];
//     }
// }
import "C"

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

	C.makeStdinBinary()

	size, err := strconv.ParseUint(os.Args[1], 10, 64)
	if err != nil {
		fmt.Printf(OutputErrorPrefix+"Invalid size value, %v\n", err)
		os.Exit(1)
	}

	protect, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil {
		fmt.Printf(OutputErrorPrefix+"Invalid protect value, %v\n", err)
		os.Exit(1)
	}

	addr, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		fmt.Printf(OutputErrorPrefix+"Could not alloc, reason: %v\n", err)
		os.Exit(5)
	}
	defer func() {
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	}()

	// Round up to next 4096
	segmentSize := uint64(math.Ceil(float64(size)/4096.) * 4096.)

	C.memset(unsafe.Pointer(addr), 0xAA, C.size_t(size))
	C.memset(unsafe.Pointer(addr+uintptr(size)), 0xBB, C.size_t(segmentSize-size))

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

	C.memcpy(unsafe.Pointer(addr), unsafe.Pointer(&data[0]), C.size_t(len(data)))

	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(data)), uint32(protect), &oldProtect)
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
