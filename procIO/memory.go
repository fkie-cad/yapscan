//go:generate go-enum -f=$GOFILE --marshal
package procIO

import (
	"errors"
	"fmt"
	"strings"
)

type MemorySegmentInfo struct {
	// On windows: _MEMORY_BASIC_INFORMATION->AllocationBase
	ParentBaseAddress uintptr `json:"parentBaseAddress"`
	// On windows: _MEMORY_BASIC_INFORMATION->BaseAddress
	BaseAddress uintptr `json:"baseAddress"`
	// On windows: _MEMORY_BASIC_INFORMATION->AllocationProtect
	AllocatedPermissions Permissions `json:"allocatedPermissions"`
	// On windows: _MEMORY_BASIC_INFORMATION->Protect
	CurrentPermissions Permissions `json:"currentPermissions"`
	// On windows: _MEMORY_BASIC_INFORMATION->RegionSize
	Size uintptr `json:"size"`
	// On windows: _MEMORY_BASIC_INFORMATION->State
	State State `json:"state"`
	// On windows: _MEMORY_BASIC_INFORMATION->Type
	Type Type `json:"type"`

	FilePath string `json:"filePath"`

	SubSegments []*MemorySegmentInfo `json:"subSegments"`
}

func (s *MemorySegmentInfo) String() string {
	return FormatMemorySegmentAddress(s)
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

var PermR = Permissions{
	Read: true,
}
var PermRW = Permissions{
	Read:  true,
	Write: true,
}
var PermRX = Permissions{
	Read:    true,
	Execute: true,
}
var PermRC = Permissions{
	Read:  true,
	Write: true,
	COW:   true,
}
var PermRWX = Permissions{
	Read:    true,
	Write:   true,
	Execute: true,
}
var PermRCX = Permissions{
	Read:    true,
	Write:   true,
	COW:     true,
	Execute: true,
}

func ParsePermissions(s string) (Permissions, error) {
	perm := Permissions{
		Read:    false,
		Write:   false,
		COW:     false,
		Execute: false,
	}
	for _, c := range strings.ToLower(s) {
		switch c {
		case 'r':
			perm.Read = true
		case 'w':
			perm.Write = true
		case 'c':
			perm.Write = true
			perm.COW = true
		case 'e':
			fallthrough
		case 'x':
			perm.Execute = true
		case '-':
			continue
		default:
			return perm, errors.New(fmt.Sprintf("character '%c' is not a valid permission character", c))
		}
	}
	return perm, nil
}

func (p Permissions) EqualTo(other Permissions) bool {
	return p.Read == other.Read && p.Write == other.Write && p.COW == other.COW && p.Execute == other.Execute
}

func (p Permissions) IsMoreOrEquallyPermissiveThan(other Permissions) bool {
	if other.Read && !p.Read {
		return false
	}
	if other.Write && !p.Write {
		return false
	}
	if other.Execute && !p.Execute {
		return false
	}
	return true
}

func (p Permissions) IsMorePermissiveThan(other Permissions) bool {
	if other.Read && !p.Read {
		return false
	}
	if other.Write && !p.Write {
		return false
	}
	if other.Execute && !p.Execute {
		return false
	}
	return !p.EqualTo(other)
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

// TODO: Consider additional type "Shared"
/*
ENUM(
Image
Mapped
Private
)
*/
type Type int
