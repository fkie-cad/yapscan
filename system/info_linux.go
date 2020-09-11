package system

import (
	"os/exec"
	"strings"

	"github.com/targodan/go-errors"
)

func getOSInfo() (name, version, flavour string, bitness Bitness, err error) {
	var buf []byte

	cmd := exec.Command("uname", "-s")
	buf, err = cmd.Output()
	if err != nil {
		return
	}
	name = strings.TrimSpace(string(buf))

	cmd = exec.Command("uname", "-r")
	buf, err = cmd.Output()
	if err != nil {
		return
	}
	version = strings.TrimSpace(string(buf))

	cmd = exec.Command("uname", "-m")
	buf, err = cmd.Output()
	if err != nil {
		return
	}
	arch := strings.TrimSpace(string(buf))

	switch arch {
	case "amd64":
		fallthrough
	case "x86_64":
		info.Bitness = Bitness64Bit

	case "i686":
		fallthrough
	case "x86":
		info.Bitness = Bitness32Bit

	default:
		err = errors.Errorf("unknown architecture \"%s\"", arch)
		return
	}

	cmd = exec.Command("uname", "-o")
	buf, err = cmd.Output()
	if err != nil {
		return
	}
	flavour = strings.TrimSpace(string(buf))

	return
}
