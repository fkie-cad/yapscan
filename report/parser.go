package report

import (
	"encoding/json"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(rdr Reader) (*Report, error) {
	meta, err := p.parseMeta(rdr)
	if err != nil {
		return nil, err
	}

	parser, err := buildPartsParser(meta.FormatVersion.String())
	if err != nil {
		return nil, err
	}

	stats, err := parser.ParseStatistics(rdr)
	if err != nil {
		return nil, err
	}

	sysInfo, err := parser.ParseSystemInformation(rdr)
	if err != nil {
		return nil, err
	}

	processes, err := parser.ParseProcesses(rdr)
	if err != nil {
		return nil, err
	}

	memScans, err := parser.ParseMemoryScans(rdr)
	if err != nil {
		return nil, err
	}

	fileScans, err := parser.ParseFileScans(rdr)
	if err != nil {
		return nil, err
	}

	return &Report{
		Meta:        meta,
		Stats:       stats,
		SystemInfo:  sysInfo,
		Processes:   processes,
		MemoryScans: memScans,
		FileScans:   fileScans,
	}, nil
}

func (p *Parser) parseMeta(rdr Reader) (*MetaInformation, error) {
	r, err := rdr.OpenMeta()
	if err != nil {
		return nil, err
	}
	var data MetaInformation
	err = json.NewDecoder(r).Decode(&data)
	return &data, err
}
