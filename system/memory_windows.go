package system

import (
	"fraunhofer/fkie/yapscan/procIO/customWin32"
)

func GetTotalRAM() (uint64, error) {
	status, err := customWin32.GlobalMemoryStatusEx()
	if err != nil {
		return 0, err
	}
	return uint64(status.TotalPhys), nil
}

func GetFreeRAM() (uint64, error) {
	status, err := customWin32.GlobalMemoryStatusEx()
	if err != nil {
		return 0, err
	}
	return uint64(status.AvailPhys), nil
}
