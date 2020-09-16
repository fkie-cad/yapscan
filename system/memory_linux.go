package system

import (
	"syscall"

	"github.com/targodan/go-errors"
)

func GetTotalRAM() (uintptr, error) {
	si := &syscall.Sysinfo_t{}

	// XXX is a raw syscall thread safe?
	err := syscall.Sysinfo(si)
	if err != nil {
		return 0, errors.Newf("syscall failed: %w", err)
	}

	return uintptr(si.Totalram), nil
}

func GetFreeRAM() (uintptr, error) {
	si := &syscall.Sysinfo_t{}

	// XXX is a raw syscall thread safe?
	err := syscall.Sysinfo(si)
	if err != nil {
		return 0, errors.Newf("syscall failed: %w", err)
	}

	return uintptr(si.Freeram), nil
}
