package report

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/fkie-cad/yapscan/archiver"
)

type ReportWriter struct {
	archiver archiver.Archiver
}

func NewReportWriter(archiver archiver.Archiver) *ReportWriter {
	return &ReportWriter{
		archiver: archiver,
	}
}

func (w *ReportWriter) WriteReport(rprt *Report) (err error) {
	dir := rprt.SystemInfo.Hostname

	err = w.writeJson(fmt.Sprintf("%s/%s", dir, MetaFileName), rprt.Meta)
	if err != nil {
		return err
	}

	err = w.writeJson(fmt.Sprintf("%s/%s", dir, SystemInfoFileName), rprt.SystemInfo)
	if err != nil {
		return err
	}

	err = w.writeJson(fmt.Sprintf("%s/%s", dir, ScanningStatisticsFileName), rprt.Stats)
	if err != nil {
		return err
	}

	err = w.writeJsonLines(fmt.Sprintf("%s/%s", dir, ProcessesFileName), rprt.Processes)
	if err != nil {
		return err
	}

	err = w.writeJsonLines(fmt.Sprintf("%s/%s", dir, MemoryScansFileName), rprt.MemoryScans)
	if err != nil {
		return err
	}

	err = w.writeJsonLines(fmt.Sprintf("%s/%s", dir, FileScansFileName), rprt.FileScans)
	return err
}

func (w *ReportWriter) writeJson(path string, data interface{}) error {
	file, err := w.archiver.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	return enc.Encode(data)
}

func (w *ReportWriter) writeJsonLines(path string, data interface{}) error {
	file, err := w.archiver.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	dataValue := reflect.ValueOf(data)

	enc := json.NewEncoder(file)
	for i := 0; i < dataValue.Len(); i++ {
		err := enc.Encode(dataValue.Index(i).Interface())
		if err != nil {
			return err
		}
	}

	return nil
}
