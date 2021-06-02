package procio

//#include <sys/mman.h>
import "C"

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fkie-cad/yapscan/fileio"

	"github.com/targodan/go-errors"
)

const (
	fieldAddr = iota
	fieldPerm
	fieldOffset
	fieldDev
	fieldInode
	fieldPath
)

func memorySegmentFromLine(line string) (*MemorySegmentInfo, error) {
	ret := &MemorySegmentInfo{
		State:       StateCommit,
		SubSegments: make([]*MemorySegmentInfo, 0, 0),
	}

	parts := strings.Fields(line)

	addrS := strings.Split(parts[fieldAddr], "-")
	if len(addrS) != 2 {
		return nil, errors.New("addr is not of format \"<hex>-<hex>\"")
	}
	addrStart, err := strconv.ParseUint(addrS[0], 16, 64)
	if err != nil {
		return nil, fmt.Errorf("addr is not of format \"<hex>-<hex>\", %w", err)
	}
	addrEnd, err := strconv.ParseUint(addrS[1], 16, 64)
	if err != nil {
		return nil, fmt.Errorf("addr is not of format \"<hex>-<hex>\", %w", err)
	}
	ret.BaseAddress = uintptr(addrStart)
	ret.ParentBaseAddress = uintptr(addrStart)
	ret.Size = uintptr(addrEnd - addrStart)

	if len(parts[fieldPerm]) != 4 {
		return nil, errors.New("permissions have invalid format")
	}
	perms, err := ParsePermissions(parts[fieldPerm][0:3])
	if err != nil {
		return nil, errors.Newf("permissions have invalid format, %w", err)
	}
	ret.AllocatedPermissions = perms
	ret.CurrentPermissions = perms

	var t Type
	switch parts[fieldPerm][3] {
	case 's':
		// TODO: New type "Shared" maybe
		t = TypePrivate
	case 'p':
		t = TypePrivate
	default:
		return nil, errors.Newf("invalid memory type \"%c\"", parts[fieldPerm][3])
	}
	ret.Type = t

	if fieldPath < len(parts) && parts[fieldPath] != "" {
		ret.MappedFile = fileio.NewFile(parts[fieldPath])
	}

	return ret, nil
}

// PermissionsToNative converts the given Permissions to the
// native linux representation.
func PermissionsToNative(perms Permissions) int {
	switch perms.String() {
	case "R--":
		return C.PROT_READ
	case "RW-":
		return C.PROT_READ | C.PROT_WRITE
	case "RC-":
		// Isn't actually COW, but RW is close enough
		return C.PROT_READ | C.PROT_WRITE
	case "--X":
		return C.PROT_EXEC
	case "RWX":
		return C.PROT_READ | C.PROT_WRITE | C.PROT_EXEC
	case "RCX":
		return C.PROT_READ | C.PROT_WRITE | C.PROT_EXEC
	default:
		return C.PROT_NONE
	}
}
