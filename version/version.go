package version

import "fmt"

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
	return []byte(v.String()), nil
}
