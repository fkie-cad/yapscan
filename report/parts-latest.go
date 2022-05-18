package report

import (
	"encoding/json"
	"io"
)

func buildPartsParserLatest() partsParser {
	return &partsParserLatest{}
}

type partsParserLatest struct{}

func (p *partsParserLatest) ParseStatistics(rdr Reader) (*ScanningStatistics, error) {
	r, err := rdr.OpenStatistics()
	if err != nil {
		return nil, err
	}
	var data ScanningStatistics
	err = json.NewDecoder(r).Decode(&data)
	return &data, err
}

func (p *partsParserLatest) ParseSystemInformation(rdr Reader) (*SystemInfo, error) {
	r, err := rdr.OpenSystemInformation()
	if err != nil {
		return nil, err
	}
	var data SystemInfo
	err = json.NewDecoder(r).Decode(&data)
	return &data, err
}

func (p *partsParserLatest) ParseProcesses(rdr Reader) ([]*ProcessInfo, error) {
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

func (p *partsParserLatest) ParseMemoryScans(rdr Reader) ([]*MemoryScan, error) {
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

func (p *partsParserLatest) ParseFileScans(rdr Reader) ([]*FileScan, error) {
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
