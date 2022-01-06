package report

import (
	"encoding/json"
	"fmt"
	"io"
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

	if meta.FormatVersion.String() != "1.0.0" {
		return nil, fmt.Errorf("unsupported report version \"%v\", expected \"1.0.0\"", meta.FormatVersion)
	}

	stats, err := p.parseStatistics(rdr)
	if err != nil {
		return nil, err
	}

	sysInfo, err := p.parseSystemInformation(rdr)
	if err != nil {
		return nil, err
	}

	processes, err := p.parseProcesses(rdr)
	if err != nil {
		return nil, err
	}

	memScans, err := p.parseMemoryScans(rdr)
	if err != nil {
		return nil, err
	}

	fileScans, err := p.parseFileScans(rdr)
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

func (p *Parser) parseStatistics(rdr Reader) (*ScanningStatistics, error) {
	r, err := rdr.OpenStatistics()
	if err != nil {
		return nil, err
	}
	var data ScanningStatistics
	err = json.NewDecoder(r).Decode(&data)
	return &data, err
}

func (p *Parser) parseSystemInformation(rdr Reader) (*SystemInfo, error) {
	r, err := rdr.OpenSystemInformation()
	if err != nil {
		return nil, err
	}
	var data SystemInfo
	err = json.NewDecoder(r).Decode(&data)
	return &data, err
}

func (p *Parser) parseProcesses(rdr Reader) ([]*ProcessInfo, error) {
	r, err := rdr.OpenProcesses()
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(r)

	data := make([]*ProcessInfo, 0)
	for {
		var obj ProcessInfo
		err = decoder.Decode(&obj)
		if err != nil {
			break
		}
		data = append(data, &obj)
	}
	if err != io.EOF {
		return nil, err
	}

	return data, nil
}

func (p *Parser) parseMemoryScans(rdr Reader) ([]*MemoryScan, error) {
	r, err := rdr.OpenMemoryScans()
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(r)

	data := make([]*MemoryScan, 0)
	for {
		var obj MemoryScan
		err = decoder.Decode(&obj)
		if err != nil {
			break
		}
		data = append(data, &obj)
	}
	if err != io.EOF {
		return nil, err
	}

	return data, nil
}

func (p *Parser) parseFileScans(rdr Reader) ([]*FileScan, error) {
	r, err := rdr.OpenFileScans()
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(r)

	data := make([]*FileScan, 0)
	for {
		var obj FileScan
		err = decoder.Decode(&obj)
		if err != nil {
			break
		}
		data = append(data, &obj)
	}
	if err != io.EOF {
		return nil, err
	}

	return data, nil
}
