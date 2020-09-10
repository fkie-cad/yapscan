package app

import (
	"fraunhofer/fkie/yapscan"
	"fraunhofer/fkie/yapscan/procIO"
	"fraunhofer/fkie/yapscan/system"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/dustin/go-humanize"

	"github.com/targodan/go-errors"
)

func BuildFilterPermissions(fStr string) (yapscan.MemorySegmentFilter, error) {
	if len(fStr) == 0 {
		return nil, nil
	}

	perm, err := procIO.ParsePermissions(fStr)
	if err != nil {
		return nil, errors.Errorf("could not parse permissions \"%s\", reason: %w", fStr, err)
	}

	return yapscan.NewPermissionsFilter(perm), nil
}

func BuildFilterPermissionsExact(fStr []string) (yapscan.MemorySegmentFilter, error) {
	var err error

	if fStr == nil || len(fStr) == 0 {
		return nil, nil
	}

	perms := make([]procIO.Permissions, len(fStr))
	for i, s := range fStr {
		perms[i], err = procIO.ParsePermissions(s)
		if err != nil {
			return nil, errors.Errorf("could not parse permissions \"%s\", reason: %w", s, err)
		}
	}

	return yapscan.NewPermissionsFilterExact(perms), nil
}

func BuildFilterType(fStr []string) (yapscan.MemorySegmentFilter, error) {
	var err error

	if fStr == nil || len(fStr) == 0 {
		return nil, nil
	}

	types := make([]procIO.Type, len(fStr))
	for i, s := range fStr {
		if s == "" {
			continue
		}
		types[i], err = procIO.ParseType(strings.ToUpper(s[0:1]) + strings.ToLower(s[1:]))
		if err != nil {
			return nil, errors.Errorf("could not parse type \"%s\", reason: %w", s, err)
		}
	}

	return yapscan.NewTypeFilter(types), nil
}

func BuildFilterState(fStr []string) (yapscan.MemorySegmentFilter, error) {
	var err error

	if fStr == nil || len(fStr) == 0 {
		return nil, nil
	}

	states := make([]procIO.State, len(fStr))
	for i, s := range fStr {
		if s == "" {
			continue
		}
		states[i], err = procIO.ParseState(strings.ToUpper(s[0:1]) + strings.ToLower(s[1:]))
		if err != nil {
			return nil, errors.Errorf("could not parse state \"%s\", reason: %w", s, err)
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
		return nil, errors.Errorf("could not parse size \"%s\", reason: %w", fStr, err)
	}

	logrus.Info("Filtering for minimum size %s", humanize.Bytes(size))

	return yapscan.NewMinSizeFilter(size), nil
}

func BuildFilterSizeMax(fStr string) (yapscan.MemorySegmentFilter, error) {
	if len(fStr) == 0 {
		return nil, nil
	}

	size, err := ParseSizeArgument(fStr)
	if err != nil {
		return nil, errors.Errorf("could not parse size \"%s\", reason: %w", fStr, err)
	}

	logrus.Info("Filtering for maximum size %s", humanize.Bytes(size))

	return yapscan.NewMaxSizeFilter(size), nil
}

func ParseSizeArgument(s string) (uint64, error) {
	if strings.Contains(s, "%") {
		return ParseRelativeSize(s)
	} else {
		return ParseAbsoluteSize(s)
	}
}

func ParseRelativeSize(s string) (uint64, error) {
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

	max := uint64(0)

	switch strings.ToLower(relToWhat) {
	case "t":
		fallthrough
	case "total":
		max, err = system.GetTotalRAM()
		if err != nil {
			err = errors.Errorf("could not get total RAM, reason: %w", err)
		}
	case "f":
		fallthrough
	case "free":
		max, err = system.GetFreeRAM()
		if err != nil {
			err = errors.Errorf("could not get free RAM, reason: %w", err)
		}
	default:
		err = errors.Newf("unknown relative definition \"%s\", must be \"[t]otal\" or \"[f]ree\"", relToWhat)
	}

	if err != nil {
		return 0, err
	}

	return uint64(value*float64(max)/100. + 0.5), nil
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

func ParseAbsoluteSize(s string) (uint64, error) {
	s = strings.Trim(s, " \t")

	numReg := regexp.MustCompile(`[0-9]*\.?[0-9]+`)
	numReg.Longest()

	num := numReg.FindString(s)
	value, err := strconv.ParseFloat(num, 64)

	unit := strings.Trim(s[len(num):], " \t")
	mult, err := ParseByteUnit(unit)
	if err != nil {
		return 0, err
	}

	return uint64(float64(mult)*value + 0.5), nil
}
