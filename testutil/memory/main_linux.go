package memory

//#include <sys/mman.h>
//#include <errno.h>
//#include <string.h>
//
// int getErrno() {
//     return errno;
// }
//
// void* negativeOne() {
//     return ((void*)-1);
// }
import "C"

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"unsafe"

	"github.com/targodan/go-errors"
)

func getLastError() error {
	text := C.GoString(C.strerror(C.getErrno()))
	return errors.New(text)
}

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

	addr := C.mmap(
		unsafe.Pointer(uintptr(0)),
		C.size_t(size),
		C.PROT_READ|C.PROT_WRITE,
		C.MAP_PRIVATE|C.MAP_ANONYMOUS|C.MAP_POPULATE,
		-1,
		0)
	if addr == C.negativeOne() {
		fmt.Printf(OutputErrorPrefix+"Could not alloc, reason: %v\n", getLastError())
		os.Exit(5)
	}
	defer func() {
		C.munmap(addr, C.size_t(size))
	}()

	fmt.Printf("Allocated: 0x%X\n", addr)

	var data []byte

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
	}

	C.memcpy(unsafe.Pointer(addr), unsafe.Pointer(&data[0]), C.size_t(size))

	ret := C.mprotect(addr, C.size_t(size), C.int(protect))
	if ret == -1 {
		fmt.Printf(OutputErrorPrefix+"Failed to set protect, reason: %v\n", getLastError())
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
