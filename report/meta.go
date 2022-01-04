package report

import (
	"fmt"
	"strings"

	"github.com/fkie-cad/yapscan/version"
)

// SystemInfoFileName is the name of the file, where system info is stored.
const SystemInfoFileName = "systeminfo.json"

// RulesFileName is the name of the file, where the used rules will be stored.
const RulesFileName = "rules.yarc"

// ProcessFileName is the name of the file used to report information about processes.
const ProcessFileName = "processes.json"

// MemoryProgressFileName is the name of the file used to report information about memory scans.
const MemoryProgressFileName = "memory-scans.json"

// FSProgressFileName is the name of the file used to report information about file scans.
const FSProgressFileName = "file-scans.json"

// ScanningStatisticsFileName is the name of the file used to report scanning.
const ScanningStatisticsFileName = "stats.json"

// MetaFileName is the name of the file containing meta information about the report format.
const MetaFileName = "meta.json"

var FormatVersion = version.Version{
	Major:  1,
	Minor:  0,
	Bugfix: 0,
}
var schemaURLBase = "https://yapscan.targodan.de/reportFormat/%s/%s"

type MetaInformation struct {
	YapscanVersion version.Version   `json:"yapscanVersion"`
	FormatVersion  version.Version   `json:"formatVersion"`
	SchemaURLs     map[string]string `json:"schemaURLs"`
}

func generateSchemaURLs(files []string) map[string]string {
	ret := make(map[string]string)
	for _, file := range files {
		fileParts := strings.Split(file, ".")
		schemaFile := strings.Join(fileParts[0:len(fileParts)-1], ".") + ".schema." + fileParts[len(fileParts)-1]
		ret[file] = fmt.Sprintf(schemaURLBase, FormatVersion, schemaFile)
	}
	return ret
}

func GetMetaInformation() *MetaInformation {
	return &MetaInformation{
		YapscanVersion: version.YapscanVersion,
		FormatVersion:  FormatVersion,
		SchemaURLs: generateSchemaURLs([]string{
			SystemInfoFileName,
			ProcessFileName,
			MemoryProgressFileName,
			FSProgressFileName,
			ScanningStatisticsFileName,
			MetaFileName,
		}),
	}
}
