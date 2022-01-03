package report

import (
	"time"
)

const Format = "2006-01-02T15:04:05.000000Z07:00"

type Time struct {
	time.Time
}

func Now() Time {
	return Time{time.Now()}
}

func (t Time) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, len(Format)+2)
	b = append(b, '"')
	b = t.AppendFormat(b, Format)
	b = append(b, '"')
	return b, nil
}

func (t *Time) UnmarshalJSON(b []byte) error {
	tmp, err := time.Parse(`"`+Format+`"`, string(b))
	t.Time = tmp
	return err
}
