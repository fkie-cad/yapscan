package memory

//#include <memory.h>
//#include <stdio.h>
//
// void makeStdinBinary() {
//     freopen(NULL, "rb", stdin);
// }
import "C"
import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func ensureStdinBinary() {
	C.makeStdinBinary()
}

func alloc(size uint64) (uintptr, error) {
	return windows.VirtualAlloc(0, uintptr(size), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
}

func free(addr uintptr, size uint64) {
	windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
}

func memset(addr uintptr, value byte, count uint64) {
	C.memset(unsafe.Pointer(addr), 0xAA, C.size_t(count))
}

func memcpy(addr uintptr, data []byte) {
	C.memcpy(unsafe.Pointer(addr), unsafe.Pointer(&data[0]), C.size_t(len(data)))
}

func protect(addr uintptr, size uint64, protect uint64) error {
	var oldProtect uint32
	return windows.VirtualProtect(addr, uintptr(size), uint32(protect), &oldProtect)
}
