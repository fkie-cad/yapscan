package system

import (
	"github.com/fkie-cad/yapscan/procio/customWin32"
)

// TotalRAM returns the total amount of installed RAM in bytes.
func TotalRAM() (uintptr, error) {
	status, err := customWin32.GlobalMemoryStatusEx()
	if err != nil {
		return 0, err
	}
	return uintptr(status.TotalPhys), nil
}

// FreeRAM returns the amount of free RAM available for allocation in bytes.
func FreeRAM() (uintptr, error) {
	status, err := customWin32.GlobalMemoryStatusEx()
	if err != nil {
		return 0, err
	}
	return uintptr(status.AvailPhys), nil
}

// TotalSwap returns the amount of free RAM available for allocation in bytes.
func TotalSwap() (uintptr, error) {
	status, err := customWin32.GlobalMemoryStatusEx()
	if err != nil {
		return 0, err
	}
	return uintptr(status.TotalPageFile), nil
}

// FreeSwap returns the amount of free RAM available for allocation in bytes.
func FreeSwap() (uintptr, error) {
	status, err := customWin32.GlobalMemoryStatusEx()
	if err != nil {
		return 0, err
	}
	return uintptr(status.AvailPageFile), nil
}
