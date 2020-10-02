package system

import (
	"fraunhofer/fkie/yapscan/arch"
	"net"
	"os"

	"github.com/targodan/go-errors"
)

type Info struct {
	OSName    string   `json:"osName"`
	OSVersion string   `json:"osVersion"`
	OSFlavour string   `json:"osFlavour"`
	OSArch    arch.T   `json:"osArch"`
	Hostname  string   `json:"hostname"`
	IPs       []string `json:"ips"`
}

var info *Info

func GetInfo() (*Info, error) {
	if info == nil {
		var err error

		info = new(Info)
		info.OSArch = arch.Native()
		info.OSName, info.OSVersion, info.OSFlavour, err = getOSInfo()
		if err != nil {
			err = errors.Errorf("could not determine OS info, reason: %w", err)
			return info, err
		}
		info.Hostname, err = os.Hostname()
		if err != nil {
			err = errors.Errorf("could not determine hostname, reason: %w", err)
			return info, err
		}
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			err = errors.Errorf("could not determine IPs, reason: %w", err)
			return info, err
		}
		info.IPs = make([]string, len(addrs))
		for i := range addrs {
			info.IPs[i] = addrs[i].String()
		}
	}
	return info, nil
}
