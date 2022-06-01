package procio

//#include <sys/mman.h>
import "C"

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/fkie-cad/yapscan/fileio"

	"github.com/targodan/go-errors"
)

const (
	fieldZero = iota
	fieldAddrStart
	fieldAddrEnd
	fieldPerms
	fieldOffset
	fieldDev
	fieldInode
	fieldPathname
	expectedFieldCount
)

const (
	nativeProtNone  = C.PROT_NONE
	nativeProtRead  = C.PROT_READ
	nativeProtWrite = C.PROT_WRITE
	nativeProtExec  = C.PROT_EXEC
)

const (
	keyRSS            = "Rss"
	keyLastDetailLine = "VmFlags"
)

const (
	detailExpectedUnit   = "kB"
	detailUnitMultiplier = uintptr(1024)
)

func parseSMEMFile(f io.Reader) ([]*MemorySegmentInfo, error) {
	segments := make([]*MemorySegmentInfo, 0)

	var cumErr error
	var err error
	state := stateSegmentHead
	cSeg := make(chan *MemorySegmentInfo, 1)
	var lastSeg *MemorySegmentInfo

	rdr := bufio.NewReader(f)
	for {
		state, err = state(rdr, cSeg, lastSeg)
		if err == io.EOF {
			break
		}
		if err != nil {
			lastSeg = nil
			cumErr = errors.NewMultiError(cumErr, err)
			continue
		}

		select {
		case lastSeg = <-cSeg:
			segments = append(segments, lastSeg)
		default:
		}
	}

	err = nil
	if cumErr != nil {
		err = fmt.Errorf("could not parse memory segment info, reason: %w", cumErr)
	}

	return segments, err
}

type state func(in *bufio.Reader, out chan<- *MemorySegmentInfo, lastSeg *MemorySegmentInfo) (state, error)

// Example:
//     00400000-00452000     r-xp  00000000 08:02  173521      /usr/bin/dbus-daemon
// (start addr)-(end addr) (perms) (offset) (dev) (inode)      (pathname)
var segmentHeadRegex = regexp.MustCompile(`^([a-f0-9]+)-([a-f0-9]+)\s+([rwxsp-]{4})\s+([a-f0-9]+)\s+([a-f0-9]{2}:[a-f0-9]{2})\s+([a-f0-9]+)\s*(.*)$`)

var keyValueRegex = regexp.MustCompile(`^([a-zA-Z_]+):\s+(.*)$`)

func stateSegmentHead(in *bufio.Reader, out chan<- *MemorySegmentInfo, lastSeg *MemorySegmentInfo) (state, error) {
	line, err := in.ReadString('\n')
	if err != nil {
		return stateSegmentDetail, err
	}

	seg, err := parseSegmentHead(line)
	if err != nil {
		return stateSegmentDetail, fmt.Errorf("invalid segment head, %w", err)
	}
	out <- seg

	return stateSegmentDetail, nil
}

func parseSegmentHead(line string) (*MemorySegmentInfo, error) {
	line = strings.TrimRight(line, "\n")
	matches := segmentHeadRegex.FindStringSubmatch(line)
	if len(matches) != expectedFieldCount {
		return nil, fmt.Errorf("invalid format \"%s\"", line)
	}

	seg := &MemorySegmentInfo{
		State:       StateCommit,
		SubSegments: make([]*MemorySegmentInfo, 0, 0),
	}

	addrStart, err := strconv.ParseUint(matches[fieldAddrStart], 16, 64)
	if err != nil {
		return nil, fmt.Errorf("start address is not a valid hex number, %w", err)
	}
	seg.BaseAddress = uintptr(addrStart)
	seg.ParentBaseAddress = uintptr(addrStart)

	endStart, err := strconv.ParseUint(matches[fieldAddrEnd], 16, 64)
	if err != nil {
		return nil, fmt.Errorf("end address is not a valid hex number, %w", err)
	}
	seg.Size = uintptr(endStart - addrStart)

	perms, err := ParsePermissions(matches[fieldPerms][0:3])
	if err != nil {
		return seg, fmt.Errorf("permissions have invalid format, %w", err)
	}

	var t SegmentType
	switch matches[fieldPerms][3] {
	case 's':
		t = SegmentTypeMapped
	case 'p':
		t = SegmentTypePrivate
		if perms.Write {
			perms.COW = true
		}
	default:
		return seg, errors.Newf("invalid memory type \"%c\"", matches[fieldPerms][3])
	}
	seg.AllocatedPermissions = perms
	seg.CurrentPermissions = perms
	seg.Type = t

	fpath := matches[fieldPathname]
	if fpath != "" && fpath[0] != '[' {
		deleted := " (deleted)"
		idxDeleted := strings.LastIndex(fpath, deleted)
		if idxDeleted >= 0 && idxDeleted == len(fpath)-len(deleted) /* ends with deleted */ {
			fpath = strings.TrimSpace(fpath[:idxDeleted])
		}

		seg.MappedFile = fileio.NewFile(fpath)
		if seg.Type == SegmentTypePrivate {
			seg.Type = SegmentTypePrivateMapped
		}
	}

	return seg, nil
}

func stateSegmentDetail(in *bufio.Reader, out chan<- *MemorySegmentInfo, lastSeg *MemorySegmentInfo) (state, error) {
	line, err := in.ReadString('\n')
	if err != nil {
		return stateSegmentDetail, err
	}
	line = strings.TrimSpace(line)

	key, value, err := parseKeyValue(line)
	if err != nil {
		return stateSegmentDetail, fmt.Errorf("invalid segment detail line, %w", err)
	}

	if key == keyLastDetailLine {
		return stateSegmentHead, nil
	}

	if lastSeg == nil {
		// Look for the next head
		return stateSegmentDetail, nil
	}

	if key == keyRSS {
		b, err := parseBytes(value)
		if err != nil {
			return stateSegmentDetail, fmt.Errorf("invalid Rss value \"%s\", %w", value, err)
		}
		lastSeg.RSS = b
		if lastSeg.RSS == 0 {
			lastSeg.State = StateReserve
		}
	}

	return stateSegmentDetail, nil
}

func parseKeyValue(line string) (key, value string, err error) {
	matches := keyValueRegex.FindStringSubmatch(line)
	if len(matches) != 3 {
		return "", "", fmt.Errorf("invalid format \"%s\"", strings.TrimSpace(line))
	}

	return matches[1], matches[2], nil
}

func parseBytes(value string) (uintptr, error) {
	parts := strings.Split(value, " ")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid format")
	}
	amount, unit := parts[0], parts[1]
	if unit != detailExpectedUnit {
		return 0, fmt.Errorf("unexpected unit \"%s\"", unit)
	}
	amountUint, err := strconv.ParseUint(amount, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("amount \"%s\" is not integer", amount)
	}
	return uintptr(amountUint) * detailUnitMultiplier, nil
}

func sanitizeMappedFile(proc Process, seg *MemorySegmentInfo) {
	if seg.MappedFile == nil {
		return
	}
	originalPath := seg.MappedFile.Path()
	if strings.Contains(originalPath, "\\012") {
		// newline characters are encoded as '\012', but we cannot distinguish between an actual
		// literal '\012' or it representing the newline character => lookup the link
		linkPath := fmt.Sprintf("%s/%d/map_files/%x-%x", procPath, proc.PID(), seg.BaseAddress, seg.BaseAddress+seg.Size)
		actualPath, err := os.Readlink(linkPath)
		if err != nil {
			// Could not read the link => leave it as-is
			return
		}
		if originalPath != actualPath {
			seg.MappedFile = fileio.NewFile(actualPath)
		}
	}
}

// PermissionsToNative converts the given Permissions to the
// native linux representation.
func PermissionsToNative(perms Permissions) int {
	if !perms.Read && !perms.Write && !perms.Execute {
		return nativeProtNone
	}

	// COW does not translate to native permissions, so its ignored

	native := 0
	if perms.Read {
		native |= nativeProtRead
	}
	if perms.Write {
		native |= nativeProtWrite
	}
	if perms.Execute {
		native |= nativeProtExec
	}
	return native
}
