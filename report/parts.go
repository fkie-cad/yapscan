package report

import "fmt"

type partsParser interface {
	ParseStatistics(rdr Reader) (*ScanningStatistics, error)
	ParseSystemInformation(rdr Reader) (*SystemInfo, error)
	ParseProcesses(rdr Reader) ([]*ProcessInfo, error)
	ParseMemoryScans(rdr Reader) ([]*MemoryScan, error)
	ParseFileScans(rdr Reader) ([]*FileScan, error)
}

type partsParserBuilder func() partsParser

var partsParserBuilders map[string]partsParserBuilder

func init() {
	partsParserBuilders = map[string]partsParserBuilder{
		"1.0.0": buildPartsParser100,
		"1.1.0": buildPartsParserLatest,
	}
}

func buildPartsParser(version string) (partsParser, error) {
	builder, ok := partsParserBuilders[version]
	if !ok {
		return nil, fmt.Errorf("unsupported report version \"%v\"", version)
	}
	return builder(), nil
}
