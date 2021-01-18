package customWin32

import "github.com/0xrawsec/golang-win32/win32"

type MemoryStatusEx struct {
	Length               win32.DWORD
	MemoryLoad           win32.DWORD
	TotalPhys            win32.DWORDLONG
	AvailPhys            win32.DWORDLONG
	TotalPageFile        win32.DWORDLONG
	AvailPageFile        win32.DWORDLONG
	TotalVirtual         win32.DWORDLONG
	AvailVirtual         win32.DWORDLONG
	AvailExtendedVirtual win32.DWORDLONG
}
