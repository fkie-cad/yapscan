package main

//#include <memory.h>
import "C"

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <size> <native_memprotect>")
	}

	size, err := strconv.ParseUint(os.Args[1], 10, 64)
	if err != nil {
		log.Fatalf("Invalid size value, %v", err)
	}

	protect, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil {
		log.Fatalf("Invalid protect value, %v", err)
	}

	addr, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		log.Fatalf("Could not alloc, reason: %v", err)
	}
	defer func() {
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	}()

	data, err := ioutil.ReadAll(io.LimitReader(os.Stdin, int64(size)))
	if err != nil {
		log.Fatalf("Could not read from stdin, reason: %v", err)
	}

	C.memcpy(unsafe.Pointer(addr), unsafe.Pointer(&data[0]), C.size_t(size))

	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(data)), uint32(protect), &oldProtect)
	if err != nil {
		log.Fatalf("Failed to set protect, reason: %v", err)
	}

	fmt.Println(addr)

	// Wait for stdin close
	ioutil.ReadAll(os.Stdin)
}
