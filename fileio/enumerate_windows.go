package fileio

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/targodan/go-errors"

	"github.com/sirupsen/logrus"

	"golang.org/x/sys/windows"
)

var (
	netShareInitialTimeout = 1 * time.Second
	netShareMountTimeout   = 1 * time.Second
)

func makeSharesAvailableAsAdmin() error {
	netUseOutput, err := func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), netShareInitialTimeout)
		defer cancel()

		netUse := exec.CommandContext(ctx, "net", "use")
		output, err := netUse.Output()
		return string(output), err
	}()
	if err != nil {
		return err
	}

	// Example output (tested on windows 7 ultimate x64):
	//PS C:\users\user\Desktop> net use
	//New connections will be remembered.
	//
	//
	//Status       Local     Remote                    Network
	//
	//-------------------------------------------------------------------------------
	//Unavailable  Z:        \\192.168.xxx.xxx\share   Microsoft Windows Network
	//The command completed successfully.
	lineRe := regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+.+$`)

	unavailable := make(map[string]string, 0)

	lines := strings.Split(netUseOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		matches := lineRe.FindAllStringSubmatch(line, -1)
		if len(matches) == 1 && len(matches[0]) == 4 {
			status, local, remote := matches[0][1], matches[0][2], matches[0][3]
			if status == "Unavailable" {
				unavailable[local] = remote
			}
		}
	}

	err = nil
	for drive, remote := range unavailable {
		logrus.Infof("Attempting to make drive \"%s\" available to current user.", drive)

		tmpErr := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), netShareMountTimeout)
			defer cancel()

			netUse := exec.CommandContext(ctx, "net", "use", drive, remote)
			return netUse.Run()
		}()
		if tmpErr != nil {
			logrus.WithError(err).Errorf("Could not make drive \"%s\" available to current user.", drive)

			err = errors.NewMultiError(err, tmpErr)
		} else {
			logrus.Errorf("Successfully made drive \"%s\" available to current user.", drive)
		}
	}
	return err
}

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
	err := makeSharesAvailableAsAdmin()

	if allDrives == nil {
		allDrives = loadAllDrives()
	}

	ret := make([]string, 0)
	for _, d := range allDrives {
		if d.Type&typeMask != 0 {
			ret = append(ret, d.Root)
		}
	}

	return ret, err
}
