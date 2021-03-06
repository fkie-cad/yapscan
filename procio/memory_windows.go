package procio

import (
	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
)

// SegmentFromMemoryBasicInformation converts the winapi win32.MemoryBasicInformation
// into a *MemorySegmentInfo.
func SegmentFromMemoryBasicInformation(info win32.MemoryBasicInformation) *MemorySegmentInfo {
	return &MemorySegmentInfo{
		ParentBaseAddress:    uintptr(info.AllocationBase),
		BaseAddress:          uintptr(info.BaseAddress),
		AllocatedPermissions: permissionsFromProtectDWORD(info.AllocationProtect),
		CurrentPermissions:   permissionsFromProtectDWORD(info.Protect),
		Size:                 uintptr(info.RegionSize),
		State:                stateFromDWORD(info.State),
		Type:                 typeFromDWORD(info.Type),
		SubSegments:          make([]*MemorySegmentInfo, 0),
	}
}

// LookupFilePathOfSegment attempts to lookup the module filename associated
// with the given *MemorySegmentInfo.
func LookupFilePathOfSegment(procHandle win32.HANDLE, seg *MemorySegmentInfo) (string, error) {
	if seg.BaseAddress != seg.ParentBaseAddress {
		// Only check root segments
		return "", nil
	}
	if seg.Type == TypeImage {
		return kernel32.GetModuleFilenameExW(procHandle, win32.HANDLE(seg.BaseAddress))
	}
	return "", nil
}

// PermissionsToNative converts the given Permissions to the
// native windows representation.
func PermissionsToNative(perms Permissions) win32.DWORD {
	switch perms.String() {
	case "R--":
		return win32.PAGE_READONLY
	case "RW-":
		return win32.PAGE_READWRITE
	case "RC-":
		return win32.PAGE_WRITECOPY
	case "--X":
		return win32.PAGE_EXECUTE
	case "RWX":
		return win32.PAGE_EXECUTE_READWRITE
	case "RCX":
		return win32.PAGE_EXECUTE_WRITECOPY
	default:
		return win32.PAGE_NOACCESS
	}
}

func permissionsFromProtectDWORD(protect win32.DWORD) Permissions {
	mp := Permissions{
		Read:    false,
		Write:   false,
		COW:     false,
		Execute: false,
	}

	protect &= win32.DWORD(0xFF)

	switch protect {
	case win32.PAGE_READONLY:
		mp.Read = true
	case win32.PAGE_READWRITE:
		mp.Read = true
		mp.Write = true
	case win32.PAGE_WRITECOPY:
		mp.Read = true
		mp.Write = true
		mp.COW = true
	case win32.PAGE_EXECUTE:
		mp.Execute = true
	case win32.PAGE_EXECUTE_READ:
		mp.Read = true
		mp.Execute = true
	case win32.PAGE_EXECUTE_READWRITE:
		mp.Read = true
		mp.Write = true
		mp.Execute = true
	case win32.PAGE_EXECUTE_WRITECOPY:
		mp.Read = true
		mp.Write = true
		mp.COW = true
		mp.Execute = true
	}

	return mp
}

func stateFromDWORD(state win32.DWORD) State {
	switch state {
	case win32.MEM_COMMIT:
		return StateCommit
	case win32.MEM_FREE:
		return StateFree
	case win32.MEM_RESERVE:
		return StateReserve
	}
	return State(state)
}

func typeFromDWORD(t win32.DWORD) Type {
	switch t {
	case win32.DWORD(0x1000000):
		return TypeImage
	case win32.MEM_MAPPED:
		return TypeMapped
	case win32.MEM_PRIVATE:
		return TypePrivate
	}
	return Type(t)
}
