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
	OSName    string
	OSVersion string
	OSFlavour string
	Bitness   Bitness
	Hostname  string
	IPs       []string
}

func GetInfo() (info *Info, err error) {
	info = new(Info)
	info.OSName, info.OSVersion, info.OSFlavour, info.Bitness, err = getOSInfo()
	if err != nil {
		err = errors.Errorf("could not determine OS info", err)
		return
	}
	info.Hostname, err = os.Hostname()
	if err != nil {
		err = errors.Errorf("could not determine hostname", err)
		return
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		err = errors.Errorf("could not determine IPs", err)
		return
	}
	info.IPs = make([]string, len(addrs))
	for i := range addrs {
		info.IPs[i] = addrs[i].String()
	}
	return
}
