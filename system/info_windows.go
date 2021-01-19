package system

import (
	"encoding/csv"
	"fmt"
	"os/exec"
	"strings"
)

func getOSInfo() (name, version, flavour string, err error) {
	cmd := exec.Command("systeminfo", "/FO", "CSV")
	buf, err := cmd.Output()
	if err != nil {
		err = fmt.Errorf("could not execute systeminfo, reason: %s", err)
		return
	}

	info := csv.NewReader(strings.NewReader(string(buf)))
	headings, err := info.Read()
	if err != nil {
		err = fmt.Errorf("could not parse systeminfo output, reason: %s", err)
		return
	}
	data, err := info.Read()
	if err != nil {
		err = fmt.Errorf("could not parse systeminfo output, reason: %s", err)
		return
	}

	var iOSName, iOSVersion int
	for i, heading := range headings {
		if strings.ToLower(heading) == "os name" {
			iOSName = i
		}
		if strings.ToLower(heading) == "os version" {
			iOSVersion = i
		}
		if iOSName != 0 && iOSVersion != 0 {
			break
		}
	}

	parts := strings.Split(strings.TrimSpace(data[iOSName]), " ")
	if len(parts) < 3 {
		err = fmt.Errorf("invalid OS name \"%s\"", data[iOSName])
		return
	}
	// Examples:
	// Microsoft Windows 7 Professional
	// Microsoft Windows XP Professional
	// Microsoft Windows 10 Pro
	name = strings.Join(parts[:3], " ")
	flavour = strings.Join(parts[3:], " ")
	version = strings.TrimSpace(data[iOSVersion])

	return
}
