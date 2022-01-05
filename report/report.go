package report

import (
	"github.com/fkie-cad/yapscan/arch"
	"github.com/fkie-cad/yapscan/fileio"
	"github.com/fkie-cad/yapscan/procio"
)

type Report struct {
	Meta        *MetaInformation
	Stats       *ScanningStatistics
	SystemInfo  *SystemInfo
	Processes   []*ProcessInfo
	MemoryScans []*MemoryScan
	FileScans   []*FileScan
}

type ProfilingInformation struct {
	Time                  Time    `json:"time"`
	FreeRAM               uintptr `json:"freeRAM"`
	FreeSwap              uintptr `json:"freeSwap"`
	LoadAvgOneMinute      float64 `json:"loadAvgOneMinute"`
	LoadAvgFiveMinutes    float64 `json:"loadAvgFiveMinutes"`
	LoadAvgFifteenMinutes float64 `json:"loadAvgFifteenMinutes"`
}

// ScanningStatistics holds statistic information about a scan.
type ScanningStatistics struct {
	Start                      Time                    `json:"start"`
	End                        Time                    `json:"end"`
	NumberOfProcessesScanned   uint64                  `json:"numberOfProcessesScanned"`
	NumberOfSegmentsScanned    uint64                  `json:"numberOfSegmentsScanned"`
	NumberOfMemoryBytesScanned uint64                  `json:"numberOfMemoryBytesScanned"`
	NumberOfFileBytesScanned   uint64                  `json:"numberOfFileBytesScanned"`
	NumberOfFilesScanned       uint64                  `json:"numberOfFilesScanned"`
	ProfilingInformation       []*ProfilingInformation `json:"profilingInformation"`
}

// ProcessInfo represents information about a Process.
type ProcessInfo struct {
	PID              int                  `json:"pid"`
	Bitness          arch.Bitness         `json:"bitness"`
	ExecutablePath   string               `json:"executablePath"`
	ExecutableMD5    string               `json:"executableMD5"`
	ExecutableSHA256 string               `json:"executableSHA256"`
	Username         string               `json:"username"`
	MemorySegments   []*MemorySegmentInfo `json:"memorySegments"`
}

// MemorySegmentInfo contains information about a memory segment.
type MemorySegmentInfo struct {
	// ParentBaseAddress is the base address of the parent segment.
	// If no parent segment exists, this is equal to the BaseAddress.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->AllocationBase
	ParentBaseAddress uintptr `json:"parentBaseAddress"`

	// BaseAddress is the base address of the current memory segment.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->BaseAddress
	BaseAddress uintptr `json:"baseAddress"`

	// AllocatedPermissions is the Permissions that were used to initially
	// allocate this segment.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->AllocationProtect
	AllocatedPermissions procio.Permissions `json:"allocatedPermissions"`

	// CurrentPermissions is the Permissions that the segment currently has.
	// This may differ from AllocatedPermissions if the permissions where changed
	// at some point (e.g. via VirtualProtect).
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->Protect
	CurrentPermissions procio.Permissions `json:"currentPermissions"`

	// Size contains the size of the segment in bytes.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->RegionSize
	Size uintptr `json:"size"`

	// RSS contains the ResidentSetSize as reported on linux, i.e.
	// the amount of RAM this segment actually uses right now.
	// Equivalence on windows: No equivalence, this is currently always equal to Size.
	RSS uintptr `json:"rss"`

	// State contains the current State of the segment.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->State
	State procio.State `json:"state"`

	// Type contains the Type of the segment.
	// Equivalence on windows: _MEMORY_BASIC_INFORMATION->SegmentType
	Type procio.SegmentType `json:"type"`

	// File contains the path to the mapped file, or empty string if
	// no file mapping is associated with this memory segment.
	MappedFile fileio.File `json:"mappedFile"`
}

// SystemInfo contains information about the running system.
type SystemInfo struct {
	OSName    string   `json:"osName"`
	OSVersion string   `json:"osVersion"`
	OSFlavour string   `json:"osFlavour"`
	OSArch    arch.T   `json:"osArch"`
	Hostname  string   `json:"hostname"`
	IPs       []string `json:"ips"`
	NumCPUs   int      `json:"numCPUs"`
	TotalRAM  uintptr  `json:"totalRAM"`
	TotalSwap uintptr  `json:"totalSwap"`
}

// MemoryScan represents all matches on a single memory
// segment of a process.
type MemoryScan struct {
	PID           int         `json:"pid"`
	MemorySegment uintptr     `json:"memorySegment"`
	Matches       []*Match    `json:"match"`
	Error         interface{} `json:"error"`
}

// FileScan represents all matches on a file.
type FileScan struct {
	File    fileio.File `json:"file"`
	Matches []*Match    `json:"match"`
	Error   interface{} `json:"error"`
}

// Match represents the match of a yara Rule.
type Match struct {
	Rule      string         `json:"rule"`
	Namespace string         `json:"namespace"`
	Strings   []*MatchString `json:"strings"`
}

// A MatchString represents a string declared and matched in a rule.
type MatchString struct {
	Name   string `json:"name"`
	Base   uint64 `json:"base"`
	Offset uint64 `json:"offset"`
}
