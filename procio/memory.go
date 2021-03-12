//go:generate go-enum -f=$GOFILE --marshal --lower --names
package procio

import (
	"fmt"
	"strings"
)

// MemorySegmentInfo contains information about a memory segment.
type MemorySegmentInfo struct {
	// ParentBaseAddress is the base address of the parent segment.
	// If no parent segment exists, this is equal to the BaseAddress.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->AllocationBase
	ParentBaseAddress uintptr `json:"parentBaseAddress"`

	// BaseAddress is the base address of the current memory segment.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->BaseAddress
	BaseAddress uintptr `json:"baseAddress"`

	// AllocatedPermissions is the Permissions that were used to initially
	// allocate this segment.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->AllocationProtect
	AllocatedPermissions Permissions `json:"allocatedPermissions"`

	// CurrentPermissions is the Permissions that the segment currently has.
	// This may differ from AllocatedPermissions if the permissions where changed
	// at some point (e.g. via VirtualProtect).
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->Protect
	CurrentPermissions Permissions `json:"currentPermissions"`

	// Size contains the size of the segment in bytes.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->RegionSize
	Size uintptr `json:"size"`

	// State contains the current State of the segment.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->State
	State State `json:"state"`

	// Type contains the Type of the segment.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->Type
	Type Type `json:"type"`

	// FilePath contains the path to the mapped file, or empty string if
	// no file mapping is associated with this memory segment.
	FilePath string `json:"filePath"`

	// SubSegments contains sub-segments, i.e. segment where their ParentBaseAddress
	// is equal to this segments BaseAddress.
	// If no such segments exist, this will be a slice of length 0.
	SubSegments []*MemorySegmentInfo `json:"subSegments"`
}

// String returns a human readable representation of the BaseAddress.
func (s *MemorySegmentInfo) String() string {
	return FormatMemorySegmentAddress(s)
}

// CopyWithoutSubSegments creates a copy of this *MemorySegmentInfo, but
// the SubSegments of the returned *MemorySegmentInfo will be of length 0.
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

// Permissions describes the permissions of a memory segment.
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

// PermR is readonly Permissions.
var PermR = Permissions{
	Read: true,
}

// PermRW is the read-write Permissions.
var PermRW = Permissions{
	Read:  true,
	Write: true,
}

// PermRX is the read-execute Permissions.
var PermRX = Permissions{
	Read:    true,
	Execute: true,
}

// PermRC is the read and copy-on-write Permissions.
var PermRC = Permissions{
	Read:  true,
	Write: true,
	COW:   true,
}

// PermRWX is the read-write-execute Permissions.
var PermRWX = Permissions{
	Read:    true,
	Write:   true,
	Execute: true,
}

// PermRCX is the read-execute and copy-on-write Permissions.
var PermRCX = Permissions{
	Read:    true,
	Write:   true,
	COW:     true,
	Execute: true,
}

// ParsePermissions parses the string representation of a Permissions,
// as output by Permissions.String and returns the resulting Permissions.
//
// Each character of the string is interpreted individually and case insensitive.
// A '-' is ignored, 'r' stands for read, 'w' for write, 'c' for copy-on-write,
// and 'e' or 'x' for execute. Any other character results in an error.
// The resulting Permissions is the combination of all character interpretations.
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
			return perm, fmt.Errorf("character '%c' is not a valid permission character", c)
		}
	}
	return perm, nil
}

// EqualTo returns true if the other Permissions is exactly equal to this one.
func (p Permissions) EqualTo(other Permissions) bool {
	return p.Read == other.Read && p.Write == other.Write && p.COW == other.COW && p.Execute == other.Execute
}

// IsMoreOrEquallyPermissiveThan returns true if the other Permissions is equally or
// more permissive than this one.
// See IsMorePermissiveThan for more information
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

// IsMorePermissiveThan returns true if the other Permissions is more permissive than
// this one.
// E.g. "rx" is more permissive than "r".
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

// String returns the string representation of this Permissions.
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

// State represents the state of a memory segment.
/*
ENUM(
Commit
Free
Reserve
)
*/
type State int

// Type represents the type of a memory segment.
/*
ENUM(
Image
Mapped
Private
)
*/
type Type int
