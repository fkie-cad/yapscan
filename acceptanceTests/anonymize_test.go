package acceptanceTests

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/fkie-cad/yapscan/app"

	"github.com/fkie-cad/yapscan/arch"
	"github.com/fkie-cad/yapscan/archiver"
	"github.com/fkie-cad/yapscan/pgp"
	"github.com/fkie-cad/yapscan/procio"
	"github.com/fkie-cad/yapscan/report"
	"golang.org/x/crypto/openpgp"

	. "github.com/smartystreets/goconvey/convey"
)

const yapscanAnonymizeTimeout = 1 * time.Second
const symmetricEncryptionPassword = "thisIsOnlyForTesting"
const timestampFormat = "2006-01-02_15-04-05"
const mockHostname = "hal2000"
const mockUsername = "rohnJambo"

var mockStartTimestamp time.Time
var mockStopTimestamp time.Time

func init() {
	var err error
	mockStartTimestamp, err = time.Parse(timestampFormat, "2022-01-01_12-30-00")
	if err != nil {
		panic(err)
	}
	mockStopTimestamp = mockStartTimestamp.Add(5 * time.Minute)
}

func TestLinuxReportIsAnonymized(t *testing.T) {
	Convey("Anonymizing a linux report should not error", t, func(c C) {
		rprt := generateReportLinux()
		filename := writeMockReportNotEncrypted(t, rprt)

		outputDir := t.TempDir()

		args := []string{"yapscan", "anonymize", "--output-dir", outputDir, filename}

		ctx, cancel := context.WithTimeout(context.Background(), yapscanAnonymizeTimeout)
		err := app.MakeApp().RunContext(ctx, args)
		cancel()

		So(err, ShouldBeNil)
		conveyReportIsAnonymized(c, openReportCleartext(), outputDir, mockHostname, mockUsername, rprt.SystemInfo.IPs)
	})
}

func TestWindowsReportIsAnonymized(t *testing.T) {
	Convey("Anonymizing a linux report should not error", t, func(c C) {
		rprt := generateReportWindows()
		filename := writeMockReportNotEncrypted(t, rprt)

		outputDir := t.TempDir()

		args := []string{"yapscan", "anonymize", "--output-dir", outputDir, filename}

		ctx, cancel := context.WithTimeout(context.Background(), yapscanAnonymizeTimeout)
		err := app.MakeApp().RunContext(ctx, args)
		cancel()

		So(err, ShouldBeNil)
		conveyReportIsAnonymized(c, openReportCleartext(), outputDir, mockHostname, mockUsername, rprt.SystemInfo.IPs)
	})
}

func writeMockReport(t *testing.T, rprt *report.Report, arc archiver.Archiver) {
	writer := report.NewReportWriter(arc)
	err := writer.WriteReport(rprt)
	if err != nil {
		t.Fatal("could not write mock report", err)
	}
}

func createMockReportFile(t *testing.T, rprt *report.Report) (string, *os.File) {
	filename := fmt.Sprintf(
		"%s/%s_%s.tar.zst",
		t.TempDir(),
		rprt.SystemInfo.Hostname,
		rprt.Stats.Start.Format(timestampFormat))

	file, err := os.Create(filename)
	if err != nil {
		t.Fatal("could not create mock report", err)
	}
	return filename, file
}

func writeMockReportNotEncrypted(t *testing.T, rprt *report.Report) string {
	filename, file := createMockReportFile(t, rprt)
	defer file.Close()

	compressor, err := zstd.NewWriter(file)
	if err != nil {
		t.Fatal("could not compress mock report", err)
	}

	arc := archiver.NewTarArchiver(compressor)
	defer arc.Close()

	writeMockReport(t, rprt, arc)

	return filename
}

func writeMockReportSymmetricallyEncrypted(t *testing.T, rprt *report.Report) string {
	filename, file := createMockReportFile(t, rprt)
	defer file.Close()

	encryptor, err := pgp.NewPGPSymmetricEncryptor(symmetricEncryptionPassword, true, file)
	if err != nil {
		t.Fatal("could not create mock report encryptor", err)
	}

	compressor, err := zstd.NewWriter(encryptor)
	if err != nil {
		t.Fatal("could not compress mock report", err)
	}

	arc := archiver.NewTarArchiver(compressor)
	defer arc.Close()

	writeMockReport(t, rprt, arc)

	return filename
}

func writeMockReportAsymmetricallyEncrypted(t *testing.T, pubkey openpgp.EntityList, rprt *report.Report) string {
	filename, file := createMockReportFile(t, rprt)
	defer file.Close()

	encryptor, err := pgp.NewPGPEncryptor(pubkey, true, file)
	if err != nil {
		t.Fatal("could not create mock report encryptor", err)
	}

	compressor, err := zstd.NewWriter(encryptor)
	if err != nil {
		t.Fatal("could not compress mock report", err)
	}

	arc := archiver.NewTarArchiver(compressor)
	defer arc.Close()

	writeMockReport(t, rprt, arc)

	return filename
}

func generateReportLinux() *report.Report {
	rprt := report.NewReport()
	rprt.SystemInfo = &report.SystemInfo{
		OSName:    "Linux",
		OSVersion: "5.16.7-zen1-1-zen",
		OSFlavour: "GNU/Linux",
		OSArch:    arch.AMD64,
		Hostname:  mockHostname,
		IPs: []string{
			"127.0.0.1",
			"::1",
			"192.168.0.42",
		},
		NumCPUs:   4,
		TotalRAM:  4 * 1024 * 1024 * 1024,
		TotalSwap: 2 * 1024 * 1024 * 1024,
	}
	rprt.Processes = []*report.ProcessInfo{
		{
			PID:              42,
			Bitness:          arch.Bitness64Bit,
			ExecutablePath:   "/some/path/somewhere",
			ExecutableMD5:    "d41d8cd98f00b204e9800998ecf8427e",
			ExecutableSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Username:         mockUsername,
			MemorySegments: []*report.MemorySegmentInfo{
				{
					ParentBaseAddress:    0,
					BaseAddress:          0,
					AllocatedPermissions: procio.PermRWX,
					CurrentPermissions:   procio.PermRWX,
					Size:                 42,
					RSS:                  0,
					State:                procio.StateCommit,
					Type:                 procio.SegmentTypeMapped,
					MappedFile: &report.File{
						FilePath:  "/some/path/somewhere",
						MD5Sum:    "d41d8cd98f00b204e9800998ecf8427e",
						SHA256Sum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
				{
					ParentBaseAddress:    42,
					BaseAddress:          42,
					AllocatedPermissions: procio.PermRWX,
					CurrentPermissions:   procio.PermRWX,
					Size:                 42,
					RSS:                  0,
					State:                procio.StateCommit,
					Type:                 procio.SegmentTypeMapped,
					MappedFile: &report.File{
						FilePath:  "/home/" + mockUsername + "/somefile.so",
						MD5Sum:    "d41d8cd98f00b204e9800998ecf8427e",
						SHA256Sum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
			},
		},
		{
			PID:              43,
			Bitness:          arch.Bitness64Bit,
			ExecutablePath:   "/home/" + mockUsername + "/anotherfile.so",
			ExecutableMD5:    "d41d8cd98f00b204e9800998ecf8427e",
			ExecutableSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Username:         mockUsername,
			MemorySegments:   []*report.MemorySegmentInfo{},
		},
	}
	rprt.Stats = &report.ScanningStatistics{
		Start:                      report.NewTime(mockStartTimestamp),
		End:                        report.NewTime(mockStopTimestamp),
		NumberOfProcessesScanned:   2,
		NumberOfSegmentsScanned:    3,
		NumberOfMemoryBytesScanned: 42 * 3,
		NumberOfFileBytesScanned:   42 * 3,
		NumberOfFilesScanned:       3,
		ProfilingInformation:       []*report.ProfilingInformation{},
	}
	rprt.MemoryScans = []*report.MemoryScan{
		{
			PID:           42,
			MemorySegment: 0,
			Matches:       []*report.Match{},
			Error:         nil,
		},
		{
			PID:           42,
			MemorySegment: 42,
			Matches: []*report.Match{
				{
					Rule:      "someRule",
					Namespace: "",
					Strings: []*report.MatchString{
						{
							Name:   "somestring",
							Base:   0,
							Offset: 0,
						},
					},
				},
			},
			Error: nil,
		},
	}
	rprt.FileScans = []*report.FileScan{
		{
			File: &report.File{
				FilePath:  "/some/file.txt",
				MD5Sum:    "d41d8cd98f00b204e9800998ecf8427e",
				SHA256Sum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			Matches: []*report.Match{},
			Error:   nil,
		},
		{
			File: &report.File{
				FilePath:  "/home/" + mockUsername + "/anotherFile.txt",
				MD5Sum:    "d41d8cd98f00b204e9800998ecf8427e",
				SHA256Sum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			Matches: []*report.Match{},
			Error:   nil,
		},
	}

	return rprt
}

func generateReportWindows() *report.Report {
	rprt := report.NewReport()
	rprt.SystemInfo = &report.SystemInfo{
		OSName:    "Microsoft Windows 10",
		OSVersion: "10.0.19042 N/A Build 19042",
		OSFlavour: "Education",
		OSArch:    arch.AMD64,
		Hostname:  mockHostname,
		IPs: []string{
			"127.0.0.1",
			"::1",
			"192.168.0.42",
		},
		NumCPUs:   4,
		TotalRAM:  4 * 1024 * 1024 * 1024,
		TotalSwap: 2 * 1024 * 1024 * 1024,
	}
	rprt.Processes = []*report.ProcessInfo{
		{
			PID:              42,
			Bitness:          arch.Bitness64Bit,
			ExecutablePath:   "D:\\some\\path\\somewhere",
			ExecutableMD5:    "d41d8cd98f00b204e9800998ecf8427e",
			ExecutableSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Username:         mockUsername,
			MemorySegments: []*report.MemorySegmentInfo{
				{
					ParentBaseAddress:    0,
					BaseAddress:          0,
					AllocatedPermissions: procio.PermRWX,
					CurrentPermissions:   procio.PermRWX,
					Size:                 42,
					RSS:                  0,
					State:                procio.StateCommit,
					Type:                 procio.SegmentTypeMapped,
					MappedFile: &report.File{
						FilePath:  "D:\\some\\path\\somewhere",
						MD5Sum:    "d41d8cd98f00b204e9800998ecf8427e",
						SHA256Sum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
				{
					ParentBaseAddress:    42,
					BaseAddress:          42,
					AllocatedPermissions: procio.PermRWX,
					CurrentPermissions:   procio.PermRWX,
					Size:                 42,
					RSS:                  0,
					State:                procio.StateCommit,
					Type:                 procio.SegmentTypeMapped,
					MappedFile: &report.File{
						FilePath:  "C:\\users\\" + mockUsername + "\\somefile.so",
						MD5Sum:    "d41d8cd98f00b204e9800998ecf8427e",
						SHA256Sum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
			},
		},
		{
			PID:              43,
			Bitness:          arch.Bitness64Bit,
			ExecutablePath:   "C:\\home\\" + mockUsername + "\\anotherfile.so",
			ExecutableMD5:    "d41d8cd98f00b204e9800998ecf8427e",
			ExecutableSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			Username:         mockUsername,
			MemorySegments:   []*report.MemorySegmentInfo{},
		},
	}
	rprt.Stats = &report.ScanningStatistics{
		Start:                      report.NewTime(mockStartTimestamp),
		End:                        report.NewTime(mockStopTimestamp),
		NumberOfProcessesScanned:   2,
		NumberOfSegmentsScanned:    3,
		NumberOfMemoryBytesScanned: 42 * 3,
		NumberOfFileBytesScanned:   42 * 3,
		NumberOfFilesScanned:       3,
		ProfilingInformation:       []*report.ProfilingInformation{},
	}
	rprt.MemoryScans = []*report.MemoryScan{
		{
			PID:           42,
			MemorySegment: 0,
			Matches:       []*report.Match{},
			Error:         nil,
		},
		{
			PID:           42,
			MemorySegment: 42,
			Matches: []*report.Match{
				{
					Rule:      "someRule",
					Namespace: "",
					Strings: []*report.MatchString{
						{
							Name:   "somestring",
							Base:   0,
							Offset: 0,
						},
					},
				},
			},
			Error: nil,
		},
	}
	rprt.FileScans = []*report.FileScan{
		{
			File: &report.File{
				FilePath:  "D:\\some\\file.txt",
				MD5Sum:    "d41d8cd98f00b204e9800998ecf8427e",
				SHA256Sum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			Matches: []*report.Match{},
			Error:   nil,
		},
		{
			File: &report.File{
				FilePath:  "D:\\users\\" + mockUsername + "\\anotherFile.txt",
				MD5Sum:    "d41d8cd98f00b204e9800998ecf8427e",
				SHA256Sum: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
			Matches: []*report.Match{},
			Error:   nil,
		},
	}

	return rprt
}
