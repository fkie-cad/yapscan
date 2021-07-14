package system

import (
	"syscall"

	"github.com/targodan/go-errors"
)

// TotalRAM returns the total amount of installed RAM in bytes.
func TotalRAM() (uintptr, error) {
	si := &syscall.Sysinfo_t{}

	err := syscall.Sysinfo(si)
	if err != nil {
		return 0, errors.Newf("syscall failed: %w", err)
	}

	return uintptr(si.Totalram), nil
}

// FreeRAM returns the amount of free RAM available for allocation in bytes.
func FreeRAM() (uintptr, error) {
	si := &syscall.Sysinfo_t{}

	err := syscall.Sysinfo(si)
	if err != nil {
		return 0, errors.Newf("syscall failed: %w", err)
	}

	return uintptr(si.Freeram), nil
}

// TotalSwap returns the amount of free RAM available for allocation in bytes.
func TotalSwap() (uintptr, error) {
	si := &syscall.Sysinfo_t{}

	err := syscall.Sysinfo(si)
	if err != nil {
		return 0, errors.Newf("syscall failed: %w", err)
	}

	return uintptr(si.Totalswap), nil
}

// FreeSwap returns the amount of free RAM available for allocation in bytes.
func FreeSwap() (uintptr, error) {
	si := &syscall.Sysinfo_t{}

	err := syscall.Sysinfo(si)
	if err != nil {
		return 0, errors.Newf("syscall failed: %w", err)
	}

	return uintptr(si.Freeswap), nil
}
