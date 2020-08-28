// Package customWin32 provides a small subset of win32
// bindings. For most win32 purposes, this project uses
// https://github.com/0xrawsec/golang-win32, however some
// wrappers are undesirable without exposing the lower
// level calls, thus these are implemented here.
package customWin32

import (
	"syscall"
	"unsafe"

	"github.com/0xrawsec/golang-win32/win32"
)

var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	readProcessMemory = kernel32.NewProc("ReadProcessMemory")
)

func ReadProcessMemory(hProcess win32.HANDLE, lpBaseAddress win32.LPCVOID, buffer []byte) (int, error) {
	numberOfBytesRead := win32.SIZE_T(0)
	r1, _, lastErr := readProcessMemory.Call(
		uintptr(hProcess),
		uintptr(lpBaseAddress),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&numberOfBytesRead)))

	if r1 == 0 {
		return int(numberOfBytesRead), lastErr
	} else {
		return int(numberOfBytesRead), nil
	}
}
