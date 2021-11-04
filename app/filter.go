package app

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/fkie-cad/yapscan"
	"github.com/fkie-cad/yapscan/procio"
	"github.com/fkie-cad/yapscan/system"

	"github.com/sirupsen/logrus"

	"github.com/dustin/go-humanize"

	"github.com/targodan/go-errors"
)

func BuildFilterPermissions(fStr string) (yapscan.MemorySegmentFilter, error) {
	if len(fStr) == 0 {
		return nil, nil
	}

	perm, err := procio.ParsePermissions(fStr)
	if err != nil {
		return nil, fmt.Errorf("could not parse permissions \"%s\", reason: %w", fStr, err)
	}

	return yapscan.NewPermissionsFilter(perm), nil
}

func BuildFilterPermissionsExact(fStr []string) (yapscan.MemorySegmentFilter, error) {
	var err error

	if len(fStr) == 0 {
		return nil, nil
	}

	perms := make([]procio.Permissions, len(fStr))
	for i, s := range fStr {
		perms[i], err = procio.ParsePermissions(s)
		if err != nil {
			return nil, fmt.Errorf("could not parse permissions \"%s\", reason: %w", s, err)
		}
	}

	return yapscan.NewPermissionsFilterExact(perms), nil
}

func BuildFilterType(fStr []string) (yapscan.MemorySegmentFilter, error) {
	var err error

	if len(fStr) == 0 {
		return nil, nil
	}

	types := make([]procio.Type, len(fStr))
	for i, s := range fStr {
		if s == "" {
			continue
		}
		types[i], err = procio.ParseType(strings.ToUpper(s[0:1]) + strings.ToLower(s[1:]))
		if err != nil {
			return nil, fmt.Errorf("could not parse type \"%s\", reason: %w", s, err)
		}
	}

	return yapscan.NewTypeFilter(types), nil
}

func BuildFilterState(fStr []string) (yapscan.MemorySegmentFilter, error) {
	var err error

	if len(fStr) == 0 {
		return nil, nil
	}

	states := make([]procio.State, len(fStr))
	for i, s := range fStr {
		if s == "" {
			continue
		}
		states[i], err = procio.ParseState(strings.ToUpper(s[0:1]) + strings.ToLower(s[1:]))
		if err != nil {
			return nil, fmt.Errorf("could not parse state \"%s\", reason: %w", s, err)
		}
	}

	return yapscan.NewStateFilter(states), nil
}

func BuildFilterSizeMin(fStr string) (yapscan.MemorySegmentFilter, error) {
	if len(fStr) == 0 {
		return nil, nil
	}

	size, err := ParseSizeArgument(fStr)
	if err != nil {
		return nil, fmt.Errorf("could not parse size \"%s\", reason: %w", fStr, err)
	}

	logrus.Infof("Filtering for minimum size %s", humanize.Bytes(uint64(size)))

	return yapscan.NewMinSizeFilter(size), nil
}

func BuildRSSRatioMin(fStr string) (yapscan.MemorySegmentFilter, error) {
	if len(fStr) == 0 {
		return nil, nil
	}

	ratio, err := ParseRatioArgument(fStr)
	if err != nil {
		return nil, fmt.Errorf("could not parse ratio \"%s\", reason: %w", fStr, err)
	}

	logrus.Infof("Filtering for minimum RSS/Size ratio %v", ratio)

	return yapscan.NewRSSRatioFilter(ratio), nil
}

func BuildFilterSizeMax(fStr string) (yapscan.MemorySegmentFilter, error) {
	if len(fStr) == 0 {
		return nil, nil
	}

	size, err := ParseSizeArgument(fStr)
	if err != nil {
		return nil, fmt.Errorf("could not parse size \"%s\", reason: %w", fStr, err)
	}

	logrus.Infof("Filtering for maximum size %s", humanize.Bytes(uint64(size)))

	return yapscan.NewMaxSizeFilter(size), nil
}

func ParseRatioArgument(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return 0, fmt.Errorf("empty string is not a ratio")
	}
	mul := 1.
	if s[len(s)-1] == '%' {
		mul = 1 / 100.
		s = strings.TrimSpace(s[:len(s)-1])
	}

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, err
	}

	return f * mul, nil
}

func ParseSizeArgument(s string) (uintptr, error) {
	if strings.Contains(s, "%") {
		return ParseRelativeSize(s)
	} else {
		return ParseAbsoluteSize(s)
	}
}

func ParseRelativeSize(s string) (uintptr, error) {
	var err error

	parts := strings.Split(s, "%")
	if len(parts) != 2 {
		return 0, errors.New("could not parse relative size, expected exactly one '%'")
	}

	num := parts[0]
	relToWhat := parts[1]

	value, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, err
	}

	max := uintptr(0)

	switch strings.ToLower(relToWhat) {
	case "t":
		fallthrough
	case "total":
		max, err = system.TotalRAM()
		if err != nil {
			err = fmt.Errorf("could not get total RAM, reason: %w", err)
		}
	case "f":
		fallthrough
	case "free":
		max, err = system.FreeRAM()
		if err != nil {
			err = fmt.Errorf("could not get free RAM, reason: %w", err)
		}
	default:
		err = errors.Newf("unknown relative definition \"%s\", must be \"[t]otal\" or \"[f]ree\"", relToWhat)
	}

	if err != nil {
		return 0, err
	}

	return uintptr(value*float64(max)/100. + 0.5), nil
}

func ParseByteUnit(s string) (uint64, error) {
	switch s {
	case "":
		fallthrough
	case "B":
		return 1, nil

	case "K":
		fallthrough
	case "KiB":
		return humanize.KiByte, nil

	case "M":
		fallthrough
	case "MiB":
		return humanize.MiByte, nil

	case "G":
		fallthrough
	case "GiB":
		return humanize.GiByte, nil

	case "T":
		fallthrough
	case "TiB":
		return humanize.TiByte, nil

	case "KB":
		return humanize.KByte, nil

	case "MB":
		return humanize.MByte, nil

	case "GB":
		return humanize.GByte, nil

	case "TB":
		return humanize.TByte, nil
	}
	return 0, errors.Newf("unknown size unit \"%s\"", s)
}

func ParseAbsoluteSize(s string) (uintptr, error) {
	s = strings.Trim(s, " \t")

	numReg := regexp.MustCompile(`[0-9]*\.?[0-9]+`)
	numReg.Longest()

	num := numReg.FindString(s)
	value, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, err
	}

	unit := strings.Trim(s[len(num):], " \t")
	mult, err := ParseByteUnit(unit)
	if err != nil {
		return 0, err
	}

	return uintptr(float64(mult)*value + 0.5), nil
}
