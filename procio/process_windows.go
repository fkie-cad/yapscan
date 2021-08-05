package procio

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/fkie-cad/yapscan/arch"
	"github.com/fkie-cad/yapscan/fileio"

	"github.com/fkie-cad/yapscan/win32"
	"golang.org/x/sys/windows"

	"github.com/targodan/go-errors"
)

var specialPIDs = map[uint32]*ProcessInfo{
	0: &ProcessInfo{
		PID:              0,
		Bitness:          arch.Native().Bitness(),
		ExecutablePath:   "IdleProcess",
		ExecutableMD5:    "",
		ExecutableSHA256: "",
		Username:         "System",
		MemorySegments:   []*MemorySegmentInfo{},
	},
	4: &ProcessInfo{
		PID:              4,
		Bitness:          arch.Native().Bitness(),
		ExecutablePath:   "PsInitialSystemProcess",
		ExecutableMD5:    "",
		ExecutableSHA256: "",
		Username:         "System",
		MemorySegments:   []*MemorySegmentInfo{},
	},
}

// GetRunningPIDs returns the PIDs of all running processes.
func GetRunningPIDs() ([]int, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	pids := make([]int, 0)

	procEntry := windows.ProcessEntry32{
		Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{})),
	}

	err = windows.Process32First(snap, &procEntry)
	if err != nil && err != windows.ERROR_NO_MORE_FILES {
		return nil, err
	}
	pids = append(pids, int(procEntry.ProcessID))
	for {
		err = windows.Process32Next(snap, &procEntry)
		if err != nil {
			break
		}
		pids = append(pids, int(procEntry.ProcessID))
	}
	if err != windows.ERROR_NO_MORE_FILES {
		return nil, err
	}
	return pids, nil
}

type processWindows struct {
	pid        uint32
	procHandle windows.Handle
	suspended  bool
}

func open(pid int) (Process, error) {
	if pid <= 4 {
		// We'll create special processes without handle, so the info can at least be retreived
		return &processWindows{pid: uint32(pid), procHandle: 0}, nil
	}
	handle, err := windows.OpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_SUSPEND_RESUME|
			// Specifically needed for CreateRemoteThread:
			windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE,
		false,
		uint32(pid),
	)
	if err != nil {
		return nil, err
	}

	return &processWindows{pid: uint32(pid), procHandle: handle}, nil
}

func (p *processWindows) PID() int {
	return int(p.pid)
}

func (p *processWindows) Info() (*ProcessInfo, error) {
	special, ok := specialPIDs[p.pid]
	if ok {
		return special, nil
	}

	var tmpErr, err error
	info := &ProcessInfo{
		PID: int(p.pid),
	}

	info.MemorySegments, tmpErr = p.MemorySegments()
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not retrieve memory segments info, reason: %w", tmpErr))
	}

	var isWow64 bool
	err = windows.IsWow64Process(p.procHandle, &isWow64)
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not determine process bitness, reason: %w", tmpErr))
	}
	// Note: This is good for windows on x86 and x86_64.
	// Docs: https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process?redirectedfrom=MSDN
	if isWow64 {
		info.Bitness = arch.Bitness32Bit
	} else {
		info.Bitness = arch.Bitness64Bit
	}

	info.ExecutablePath, tmpErr = win32.QueryFullProcessImageName(p.procHandle)
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not retrieve executable path, reason: %w", tmpErr))
	} else {
		info.ExecutableMD5, info.ExecutableSHA256, tmpErr = fileio.ComputeHashes(info.ExecutablePath)
		if tmpErr != nil {
			err = errors.NewMultiError(err, fmt.Errorf("could not compute hashes of executable, reason: %w", tmpErr))
		}
	}

	var tokenHandle windows.Token
	tmpErr = windows.OpenProcessToken(p.procHandle, windows.TOKEN_QUERY, &tokenHandle)
	if tmpErr != nil {
		err = errors.NewMultiError(err, fmt.Errorf("could not retrieve process token, reason: %w", tmpErr))
	} else {
		sid, tmpErr := win32.GetTokenOwner(tokenHandle)
		if tmpErr != nil {
			err = errors.NewMultiError(err, fmt.Errorf("could not get process token owner, reason: %w", tmpErr))
		} else {
			accout, domain, _, tmpErr := sid.LookupAccount("")
			if tmpErr == nil {
				info.Username = domain + "\\" + accout
			} else {
				err = errors.NewMultiError(err, fmt.Errorf("could not lookup username from SID, reason: %w", tmpErr))

				info.Username, tmpErr = win32.ConvertSidToStringSid(sid)
				if tmpErr != nil {
					err = errors.NewMultiError(err, fmt.Errorf("could not convert SID to string, reason: %w", tmpErr))
				}
			}
		}
	}

	return info, err
}

func (p *processWindows) String() string {
	return FormatPID(int(p.pid))
}

func (p *processWindows) Suspend() error {
	if int(p.pid) == os.Getpid() {
		return ErrProcIsSelf
	}
	if int(p.pid) == os.Getppid() {
		return ErrProcIsParent
	}
	err := win32.SuspendProcess(p.pid)
	if err == nil {
		p.suspended = true
	}
	return err
}

func (p *processWindows) Resume() error {
	var err error
	if p.suspended {
		err = win32.ResumeProcess(p.pid)
	}
	if err == nil {
		p.suspended = false
	}
	return err
}

func (p *processWindows) Close() error {
	return windows.CloseHandle(p.procHandle)
}

func (p *processWindows) Handle() interface{} {
	return p.procHandle
}

func (p *processWindows) MemorySegments() ([]*MemorySegmentInfo, error) {
	segments := make(chan *MemorySegmentInfo)
	errors := make(chan error, 1)

	go func() {
		defer close(segments)
		defer close(errors)

		var currentParent *MemorySegmentInfo

		var lpAddress uintptr
		for {
			mbi, err := win32.VirtualQueryEx(p.procHandle, lpAddress)
			if err != nil {
				if err == windows.ERROR_INVALID_PARAMETER {
					// ERROR_INVALID_PARAMETER is emitted at end of iteration
					err = nil
				}
				errors <- err
				break
			}
			lpAddress += mbi.RegionSize
			seg := SegmentFromMemoryBasicInformation(mbi)
			mappedFilePath, _ := LookupFilePathOfSegment(p.procHandle, seg)
			if mappedFilePath != "" {
				seg.MappedFile = fileio.NewFile(mappedFilePath)
			}

			if seg.State == StateFree {
				continue
			}

			if currentParent == nil {
				currentParent = seg
				currentParent.SubSegments = append(currentParent.SubSegments, currentParent.CopyWithoutSubSegments())
			} else {
				if currentParent.ParentBaseAddress == seg.ParentBaseAddress {
					currentParent.SubSegments = append(currentParent.SubSegments, seg)
					currentParent.Size += seg.Size
				} else {
					segments <- currentParent

					currentParent = seg
					currentParent.SubSegments = append(currentParent.SubSegments, currentParent.CopyWithoutSubSegments())
				}
			}
		}
		if currentParent != nil {
			segments <- currentParent
		}
	}()

	segmentsSlice := make([]*MemorySegmentInfo, 0)
	for seg := range segments {
		segmentsSlice = append(segmentsSlice, seg)
	}
	err := <-errors

	return segmentsSlice, err
}

func (p *processWindows) Crash(m CrashMethod) error {
	if m == CrashMethodCreateThreadOnNull {
		err := win32.CreateRemoteThreadMinimal(p.procHandle, 0)
		if err != nil {
			if err == windows.ERROR_NOT_ENOUGH_MEMORY {
				return fmt.Errorf("could not crash process, \"%w\", this may be due to service/non-service mode, note that only services can inject into services and services cannot inject into non-service processes", err)
			}
			return fmt.Errorf("could not crash process, %w", err)
		}
		return nil
	}
	return &arch.ErrNotImplemented{fmt.Sprintf("crash method \"%s\" is not implemented on windows", m.String())}
}
