package procio

import (
	"fmt"
)

func FormatMemorySegmentAddress(seg *MemorySegmentInfo) string {
	format := ""
	if seg.BaseAddress < (1 << 32) {
		format = "0x%08X"
	} else {
		format = "0x%016X"
	}
	return fmt.Sprintf(format, seg.BaseAddress)
}

func FormatPID(pid int) string {
	return fmt.Sprint(pid)
}
