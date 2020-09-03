package system

import (
	"syscall"

	"github.com/targodan/go-errors"
)

func GetTotalRAM() (uint64, error) {
	si := &syscall.Sysinfo_t{}

	// XXX is a raw syscall thread safe?
	err := syscall.Sysinfo(si)
	if err != nil {
		return 0, errors.Newf("syscall failed: %w", err)
	}

	return uint64(si.Totalram), nil
}

func GetFreeRAM() (uint64, error) {
	si := &syscall.Sysinfo_t{}

	// XXX is a raw syscall thread safe?
	err := syscall.Sysinfo(si)
	if err != nil {
		return 0, errors.Newf("syscall failed: %w", err)
	}

	return uint64(si.Freeram), nil
}
