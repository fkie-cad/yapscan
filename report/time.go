package report

import (
	"encoding/json"
	"fmt"
	"time"
)

const TimeFormat = "2006-01-02T15:04:05.000000-07:00"

type Time struct {
	time.Time
}

func Now() Time {
	return Time{time.Now()}
}

func NewTime(t time.Time) Time {
	return Time{t}
}

func (t Time) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, len(TimeFormat)+2)
	b = append(b, '"')
	b = t.AppendFormat(b, TimeFormat)
	b = append(b, '"')
	return b, nil
}

func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return fmt.Errorf("expected a JSON-string as Time, %w", err)
	}

	tmp, err := time.Parse(TimeFormat, s)
	t.Time = tmp
	return err
}
