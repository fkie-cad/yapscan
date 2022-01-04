package version

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

var YapscanVersion = Version{
	Major:  0,
	Minor:  12,
	Bugfix: 0,
}

type Version struct {
	Major  int
	Minor  int
	Bugfix int
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Bugfix)
}

func (v Version) MarshalJSON() ([]byte, error) {
	s := v.String()
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	b = append(b, s...)
	b = append(b, '"')
	return b, nil
}

func (v *Version) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return fmt.Errorf("expected a JSON-string as Version, %w", err)
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return fmt.Errorf("expected exactly 3 dot-separated parts as version string, got %d", len(parts))
	}

	v.Major, err = strconv.Atoi(parts[0])
	v.Minor, err = strconv.Atoi(parts[1])
	v.Bugfix, err = strconv.Atoi(parts[2])

	return nil
}
