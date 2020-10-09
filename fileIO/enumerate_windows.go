package fileIO

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func nativeToGoDriveType(t uint32) DriveType {
	switch t {
	case windows.DRIVE_UNKNOWN:
		return DriveTypeUnknown
	case windows.DRIVE_REMOVABLE:
		return DriveTypeRemovable
	case windows.DRIVE_FIXED:
		return DriveTypeFixed
	case windows.DRIVE_REMOTE:
		return DriveTypeRemote
	case windows.DRIVE_CDROM:
		return DriveTypeCDRom
	case windows.DRIVE_RAMDISK:
		return DriveTypeRAM
	}
	// Might be windows.DRIVE_NO_ROOT_DIR, but this
	// should never happen! (This function is only used internally)
	panic("invalid parameter to GetDriveTypeW")
}

type drive struct {
	Root string
	Type DriveType
}

var allDrives []*drive

func loadAllDrives() []*drive {
	drives := make([]*drive, 0)

	for d := 'A'; d <= 'Z'; d++ {
		root := fmt.Sprintf("%c:\\", d)
		rootU16, _ := windows.UTF16FromString(root)

		t := windows.GetDriveType(&rootU16[0])
		if t == windows.DRIVE_NO_ROOT_DIR {
			continue
		}

		drives = append(drives, &drive{
			Root: root,
			Type: nativeToGoDriveType(t),
		})
	}

	return drives
}

func enumerateImpl(typeMask DriveType) ([]string, error) {
	if allDrives == nil {
		allDrives = loadAllDrives()
	}

	ret := make([]string, 0)
	for _, d := range allDrives {
		if d.Type&typeMask != 0 {
			ret = append(ret, d.Root)
		}
	}

	return ret, nil
}
