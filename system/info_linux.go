package system

import (
	"os/exec"
	"strings"
)

func getOSInfo() (name, version, flavour string, err error) {
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

	cmd = exec.Command("uname", "-o")
	buf, err = cmd.Output()
	if err != nil {
		return
	}
	flavour = strings.TrimSpace(string(buf))

	return
}
