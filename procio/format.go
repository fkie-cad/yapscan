package procio

import (
	"fmt"
)

// FormatMemorySegmentAddress formats the *MemorySegmentInfo.BaseAddress
// to a hex string with prefix '0x' and either 8 or 16 digits (based on
// the address value) with leading zeros.
func FormatMemorySegmentAddress(seg *MemorySegmentInfo) string {
	format := ""
	if seg.BaseAddress < (1 << 32) {
		format = "0x%08X"
	} else {
		format = "0x%016X"
	}
	return fmt.Sprintf(format, seg.BaseAddress)
}

// FormatPID formats the given process ID.
func FormatPID(pid int) string {
	return fmt.Sprint(pid)
}
