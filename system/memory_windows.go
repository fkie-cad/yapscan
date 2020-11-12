package system

import (
	"github.com/fkie-cad/yapscan/procIO/customWin32"
)

func GetTotalRAM() (uintptr, error) {
	status, err := customWin32.GlobalMemoryStatusEx()
	if err != nil {
		return 0, err
	}
	return uintptr(status.TotalPhys), nil
}

func GetFreeRAM() (uintptr, error) {
	status, err := customWin32.GlobalMemoryStatusEx()
	if err != nil {
		return 0, err
	}
	return uintptr(status.AvailPhys), nil
}
