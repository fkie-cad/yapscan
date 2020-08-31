package procIO

import (
	"syscall"

	"github.com/0xrawsec/golang-win32/win32"
	"github.com/0xrawsec/golang-win32/win32/kernel32"
)

type processWindows struct {
	pid        int
	procHandle win32.HANDLE
}

func open(pid int) (Process, error) {
	handle, err := kernel32.OpenProcess(
		kernel32.PROCESS_VM_READ|kernel32.PROCESS_QUERY_INFORMATION,
		win32.FALSE,
		win32.DWORD(pid),
	)
	if err != nil {
		return nil, err
	}

	return &processWindows{pid: pid, procHandle: handle}, nil
}

func (p *processWindows) String() string {
	return FormatPID(p.pid)
}

func (p *processWindows) Close() error {
	return kernel32.CloseHandle(p.procHandle)
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

		lpAddress := win32.LPCVOID(0)
		for {
			var mbi win32.MemoryBasicInformation
			mbi, err := kernel32.VirtualQueryEx(p.procHandle, lpAddress)
			if err != nil {
				if err == syscall.Errno(87) {
					// 87 = ERROR_INVALID_PARAMETER is emitted at end of iteration
					err = nil
				}
				errors <- err
				break
			}
			lpAddress += win32.LPCVOID(mbi.RegionSize)
			seg := SegmentFromMemoryBasicInformation(mbi)

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
