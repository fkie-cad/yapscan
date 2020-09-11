//go:generate go-enum -f=$GOFILE --marshal
package system

import (
	"net"
	"os"

	"github.com/targodan/go-errors"
)

/*
ENUM(
32Bit
64Bit
)
*/
type Bitness int

type Info struct {
	OSName    string   `json:"osName"`
	OSVersion string   `json:"osVersion"`
	OSFlavour string   `json:"osFlavour"`
	OSBitness Bitness  `json:"osBitness"`
	Hostname  string   `json:"hostname"`
	IPs       []string `json:"ips"`
}

var info *Info

func GetInfo() (*Info, error) {
	if info == nil {
		var err error

		info = new(Info)
		info.OSName, info.OSVersion, info.OSFlavour, info.OSBitness, err = getOSInfo()
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
