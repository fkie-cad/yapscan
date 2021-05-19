package system

import (
	"fmt"
	"net"
	"os"

	"github.com/targodan/go-errors"

	"github.com/fkie-cad/yapscan/arch"
)

// Info contains information about the running system.
type Info struct {
	OSName    string   `json:"osName"`
	OSVersion string   `json:"osVersion"`
	OSFlavour string   `json:"osFlavour"`
	OSArch    arch.T   `json:"osArch"`
	Hostname  string   `json:"hostname"`
	IPs       []string `json:"ips"`
	TotalRAM  uintptr  `json:"totalRAM"`
}

var info *Info

// GetInfo retrieves the Info about the currently running system.
func GetInfo() (*Info, error) {
	if info == nil {
		var err error
		var tmpErr error

		info = new(Info)
		info.OSArch = arch.Native()
		info.OSName, info.OSVersion, info.OSFlavour, tmpErr = getOSInfo()
		if tmpErr != nil {
			info.OSName, info.OSVersion, info.OSFlavour = "UNKNOWN", "UNKNOWN", "UNKNOWN"
			err = errors.NewMultiError(err, fmt.Errorf("could not determine OS info, reason: %w", tmpErr))
		}
		info.Hostname, tmpErr = os.Hostname()
		if tmpErr != nil {
			err = errors.NewMultiError(err, fmt.Errorf("could not determine hostname, reason: %w", tmpErr))
		}
		addrs, tmpErr := net.InterfaceAddrs()
		if tmpErr != nil {
			err = errors.NewMultiError(err, fmt.Errorf("could not determine IPs, reason: %w", tmpErr))
			info.IPs = []string{"UNKNOWN"}
		} else {
			info.IPs = make([]string, len(addrs))
			for i := range addrs {
				info.IPs[i] = addrs[i].String()
			}
		}
		info.TotalRAM, tmpErr = TotalRAM()
		if tmpErr != nil {
			err = errors.NewMultiError(err, fmt.Errorf("could not determine total RAM, reason: %w", tmpErr))
		}
	}
	return copyInfo(info), nil
}

func copyInfo(info *Info) *Info {
	ips := make([]string, len(info.IPs))
	for i, ip := range info.IPs {
		ips[i] = ip
	}
	return &Info{
		OSName:    info.OSName,
		OSVersion: info.OSVersion,
		OSFlavour: info.OSFlavour,
		OSArch:    info.OSArch,
		Hostname:  info.Hostname,
		IPs:       ips,
		TotalRAM:  info.TotalRAM,
	}
}
