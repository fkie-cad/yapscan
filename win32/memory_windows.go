package win32

import "golang.org/x/sys/windows"

const (
	MEM_IMAGE   = 0x1000000
	MEM_MAPPED  = 0x40000
	MEM_PRIVATE = 0x20000

	MEM_COMMIT  = windows.MEM_COMMIT
	MEM_FREE    = 0x10000
	MEM_RESERVE = windows.MEM_RESERVE
)
