package procio

import (
	"github.com/fkie-cad/yapscan/win32"
	"golang.org/x/sys/windows"
)

// SegmentFromMemoryBasicInformation converts the winapi win32.MemoryBasicInformation
// into a *MemorySegmentInfo.
func SegmentFromMemoryBasicInformation(info win32.MemoryBasicInformation) *MemorySegmentInfo {
	return &MemorySegmentInfo{
		ParentBaseAddress:    info.AllocationBase,
		BaseAddress:          info.BaseAddress,
		AllocatedPermissions: permissionsFromNativeProtect(info.AllocationProtect),
		CurrentPermissions:   permissionsFromNativeProtect(info.Protect),
		Size:                 info.RegionSize,
		State:                stateFromNative(info.State),
		Type:                 typeFromNative(info.Type),
		SubSegments:          make([]*MemorySegmentInfo, 0),
	}
}

// LookupFilePathOfSegment attempts to lookup the module filename associated
// with the given *MemorySegmentInfo.
func LookupFilePathOfSegment(procHandle windows.Handle, seg *MemorySegmentInfo) (string, error) {
	if seg.BaseAddress != seg.ParentBaseAddress {
		// Only check root segments
		return "", nil
	}
	if seg.Type == SegmentTypeImage {
		return win32.GetModuleFilenameExW(procHandle, windows.Handle(seg.BaseAddress))
	}
	return "", nil
}

// PermissionsToNative converts the given Permissions to the
// native windows representation.
func PermissionsToNative(perms Permissions) int {
	switch perms.String() {
	case "R--":
		return windows.PAGE_READONLY
	case "RW-":
		return windows.PAGE_READWRITE
	case "RC-":
		return windows.PAGE_WRITECOPY
	case "--X":
		return windows.PAGE_EXECUTE
	case "RWX":
		return windows.PAGE_EXECUTE_READWRITE
	case "RCX":
		return windows.PAGE_EXECUTE_WRITECOPY
	default:
		return windows.PAGE_NOACCESS
	}
}

func permissionsFromNativeProtect(protect uint32) Permissions {
	mp := Permissions{
		Read:    false,
		Write:   false,
		COW:     false,
		Execute: false,
	}

	protect &= 0xFF

	switch protect {
	case windows.PAGE_READONLY:
		mp.Read = true
	case windows.PAGE_READWRITE:
		mp.Read = true
		mp.Write = true
	case windows.PAGE_WRITECOPY:
		mp.Read = true
		mp.Write = true
		mp.COW = true
	case windows.PAGE_EXECUTE:
		mp.Execute = true
	case windows.PAGE_EXECUTE_READ:
		mp.Read = true
		mp.Execute = true
	case windows.PAGE_EXECUTE_READWRITE:
		mp.Read = true
		mp.Write = true
		mp.Execute = true
	case windows.PAGE_EXECUTE_WRITECOPY:
		mp.Read = true
		mp.Write = true
		mp.COW = true
		mp.Execute = true
	}

	return mp
}

func stateFromNative(state uint32) State {
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

func typeFromNative(t uint32) SegmentType {
	switch t {
	case win32.MEM_IMAGE:
		return SegmentTypeImage
	case win32.MEM_MAPPED:
		return SegmentTypeMapped
	case win32.MEM_PRIVATE:
		return SegmentTypePrivate
	}
	return SegmentType(t)
}
