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
	"unsafe"

	"github.com/targodan/go-errors"
)

func getLastError() error {
	text := C.GoString(C.strerror(C.getErrno()))
	return errors.New(text)
}

func ensureStdinBinary() {}

func alloc(size uint64) (uintptr, error) {
	addr := C.mmap(
		unsafe.Pointer(uintptr(0)),
		C.size_t(size),
		C.PROT_READ|C.PROT_WRITE,
		C.MAP_PRIVATE|C.MAP_ANONYMOUS|C.MAP_POPULATE,
		-1,
		0)
	if addr == C.negativeOne() {
		return uintptr(addr), getLastError()
	}
	return uintptr(addr), nil
}

func free(addr uintptr, size uint64) {
	C.munmap(unsafe.Pointer(addr), C.size_t(size))
}

func memset(addr uintptr, value byte, count uint64) {
	C.memset(unsafe.Pointer(addr), 0xAA, C.size_t(count))
}

func memcpy(addr uintptr, data []byte) {
	C.memcpy(unsafe.Pointer(addr), unsafe.Pointer(&data[0]), C.size_t(len(data)))
}

func protect(addr uintptr, size uint64, protect uint64) error {
	ret := C.mprotect(unsafe.Pointer(addr), C.size_t(size), C.int(protect))
	if ret == -1 {
		return getLastError()
	}
	return nil
}
