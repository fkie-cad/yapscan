package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rjNemo/underscore"
)

const TimeFormatV100 = "2006-01-02T15:04:05.000000Z-07:00"

type TimeV100 struct {
	time.Time
}

func (t *TimeV100) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return fmt.Errorf("expected a JSON-string as Time, %w", err)
	}

	tmp, err := time.Parse(TimeFormatV100, s)
	t.Time = tmp
	return err
}

type ProfilingInformationV100 struct {
	Time                  TimeV100 `json:"time"`
	FreeRAM               uintptr  `json:"freeRAM"`
	FreeSwap              uintptr  `json:"freeSwap"`
	LoadAvgOneMinute      float64  `json:"loadAvgOneMinute"`
	LoadAvgFiveMinutes    float64  `json:"loadAvgFiveMinutes"`
	LoadAvgFifteenMinutes float64  `json:"loadAvgFifteenMinutes"`
}

// ScanningStatisticsV100 holds statistic information about a scan.
type ScanningStatisticsV100 struct {
	Start                      TimeV100                    `json:"start"`
	End                        TimeV100                    `json:"end"`
	NumberOfProcessesScanned   uint64                      `json:"numberOfProcessesScanned"`
	NumberOfSegmentsScanned    uint64                      `json:"numberOfSegmentsScanned"`
	NumberOfMemoryBytesScanned uint64                      `json:"numberOfMemoryBytesScanned"`
	NumberOfFileBytesScanned   uint64                      `json:"numberOfFileBytesScanned"`
	NumberOfFilesScanned       uint64                      `json:"numberOfFilesScanned"`
	ProfilingInformation       []*ProfilingInformationV100 `json:"profilingInformation"`
}

func buildPartsParser100() partsParser {
	parser, _ := buildPartsParser("1.1.0")
	return &partsParserV100{
		v101: parser,
	}
}

type partsParserV100 struct {
	v101 partsParser
}

func (p *partsParserV100) ParseStatistics(rdr Reader) (*ScanningStatistics, error) {
	r, err := rdr.OpenStatistics()
	if err != nil {
		return nil, err
	}
	var data ScanningStatisticsV100
	err = json.NewDecoder(r).Decode(&data)

	profilingInformation := underscore.Map(data.ProfilingInformation, func(i *ProfilingInformationV100) *ProfilingInformation {
		return &ProfilingInformation{
			Time:                  Time(i.Time),
			FreeRAM:               i.FreeRAM,
			FreeSwap:              i.FreeSwap,
			LoadAvgOneMinute:      i.LoadAvgOneMinute,
			LoadAvgFiveMinutes:    i.LoadAvgFiveMinutes,
			LoadAvgFifteenMinutes: i.LoadAvgFifteenMinutes,
		}
	})

	return &ScanningStatistics{
		Start:                      Time(data.Start),
		End:                        Time(data.End),
		NumberOfProcessesScanned:   data.NumberOfProcessesScanned,
		NumberOfSegmentsScanned:    data.NumberOfSegmentsScanned,
		NumberOfMemoryBytesScanned: data.NumberOfMemoryBytesScanned,
		NumberOfFileBytesScanned:   data.NumberOfFileBytesScanned,
		NumberOfFilesScanned:       data.NumberOfFilesScanned,
		ProfilingInformation:       profilingInformation,
	}, err
}

func (p *partsParserV100) ParseSystemInformation(rdr Reader) (*SystemInfo, error) {
	return p.v101.ParseSystemInformation(rdr)
}

func (p *partsParserV100) ParseProcesses(rdr Reader) ([]*ProcessInfo, error) {
	return p.v101.ParseProcesses(rdr)
}

func (p *partsParserV100) ParseMemoryScans(rdr Reader) ([]*MemoryScan, error) {
	return p.v101.ParseMemoryScans(rdr)
}

func (p *partsParserV100) ParseFileScans(rdr Reader) ([]*FileScan, error) {
	return p.v101.ParseFileScans(rdr)
}
