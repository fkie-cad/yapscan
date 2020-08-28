//go:generate go-enum -f=$GOFILE --marshal
package procIO

type MemorySegmentInfo struct {
	// On windows: _MEMORY_BASIC_INFORMATION->AllocationBase
	ParentBaseAddress uint64
	// On windows: _MEMORY_BASIC_INFORMATION->BaseAddress
	BaseAddress uint64
	// On windows: _MEMORY_BASIC_INFORMATION->AllocationProtect
	AllocatedPermissions Permissions
	// On windows: _MEMORY_BASIC_INFORMATION->Protect
	CurrentPermissions Permissions
	// On windows: _MEMORY_BASIC_INFORMATION->RegionSize
	Size uint64
	// On windows: _MEMORY_BASIC_INFORMATION->State
	State State
	// On windows: _MEMORY_BASIC_INFORMATION->Type
	Type Type

	SubSegments []*MemorySegmentInfo
}

func (s *MemorySegmentInfo) CopyWithoutSubSegments() *MemorySegmentInfo {
	return &MemorySegmentInfo{
		ParentBaseAddress:    s.ParentBaseAddress,
		BaseAddress:          s.BaseAddress,
		AllocatedPermissions: s.AllocatedPermissions,
		CurrentPermissions:   s.CurrentPermissions,
		Size:                 s.Size,
		State:                s.State,
		Type:                 s.Type,
		SubSegments:          make([]*MemorySegmentInfo, 0),
	}
}

type Permissions struct {
	// Is read-only access allowed
	Read bool
	// Is write access allowed (also true if COW is enabled)
	Write bool
	// Is copy-on-write access allowed (if this is true, then so is Write)
	COW bool
	// Is execute access allowed
	Execute bool
}

func (p Permissions) EqualTo(other Permissions) bool {
	return p.Read == other.Read && p.Write == other.Write && p.COW == other.COW && p.Execute == other.Execute
}

func (p Permissions) String() string {
	ret := ""
	if p.Read {
		ret += "R"
	} else {
		ret += "-"
	}
	if p.Write {
		if p.COW {
			ret += "C"
		} else {
			ret += "W"
		}
	} else {
		ret += "-"
	}
	if p.Execute {
		ret += "X"
	} else {
		ret += "-"
	}
	return ret
}

/*
ENUM(
Commit
Free
Reserve
)
*/
type State int

/*
ENUM(
Image
Mapped
Private
)
*/
type Type int
