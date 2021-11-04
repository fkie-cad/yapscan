package system

import (
	"fmt"
	"net"
	"os"
	"runtime"

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
	NumCPUs   int      `json:"numCPUs"`
	TotalRAM  uintptr  `json:"totalRAM"`
	TotalSwap uintptr  `json:"totalSwap"`
}

// UnknownOSInfo is returned as OSName, OSVersion or OSFlavour if the OS information
// could not be retrieved.
const UnknownOSInfo = "UNKNOWN"

var info *Info

// GetInfo retrieves the Info about the currently running system.
func GetInfo() (*Info, error) {
	if info == nil {
		var err error
		var tmpErr error

		tmpInfo := new(Info)
		// TODO: #16 This causes false detection if yapscan was compiled for 32-bit but run on a 64-bit
		// 		 system.
		tmpInfo.OSArch = arch.Native()
		tmpInfo.OSName, tmpInfo.OSVersion, tmpInfo.OSFlavour, tmpErr = getOSInfo()
		if tmpErr != nil {
			tmpInfo.OSName, tmpInfo.OSVersion, tmpInfo.OSFlavour = UnknownOSInfo, UnknownOSInfo, UnknownOSInfo
			err = errors.NewMultiError(err, fmt.Errorf("could not determine OS info, reason: %w", tmpErr))
		}
		tmpInfo.Hostname, tmpErr = os.Hostname()
		if tmpErr != nil {
			err = errors.NewMultiError(err, fmt.Errorf("could not determine hostname, reason: %w", tmpErr))
		}
		addrs, tmpErr := net.InterfaceAddrs()
		if tmpErr != nil {
			err = errors.NewMultiError(err, fmt.Errorf("could not determine IPs, reason: %w", tmpErr))
			tmpInfo.IPs = []string{"UNKNOWN"}
		} else {
			tmpInfo.IPs = make([]string, len(addrs))
			for i := range addrs {
				tmpInfo.IPs[i] = addrs[i].String()
			}
		}
		tmpInfo.TotalRAM, tmpErr = TotalRAM()
		if tmpErr != nil {
			err = errors.NewMultiError(err, fmt.Errorf("could not determine total RAM, reason: %w", tmpErr))
		}
		tmpInfo.TotalSwap, tmpErr = TotalSwap()
		if tmpErr != nil {
			err = errors.NewMultiError(err, fmt.Errorf("could not determine total Swap, reason: %w", tmpErr))
		}
		tmpInfo.NumCPUs = runtime.NumCPU()

		if err != nil {
			return tmpInfo, err
		}
		info = tmpInfo
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
		NumCPUs:   info.NumCPUs,
		TotalRAM:  info.TotalRAM,
		TotalSwap: info.TotalSwap,
	}
}
