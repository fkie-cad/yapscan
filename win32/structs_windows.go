package win32

import "golang.org/x/sys/windows"

type MemoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type MemoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	alignment1        uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	alignment2        uint32
}

type TokenOwner struct {
	Owner *windows.SID
}
