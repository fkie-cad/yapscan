package win32

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32             = windows.NewLazyDLL("kernel32.dll")
	readProcessMemory    = kernel32.NewProc("ReadProcessMemory")
	globalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	suspendThread        = kernel32.NewProc("SuspendThread")
	createRemoteThread   = kernel32.NewProc("CreateRemoteThread")
	virtualQueryEx       = kernel32.NewProc("VirtualQueryEx")
	getSystemTimes       = kernel32.NewProc("GetSystemTimes")
	getModuleFilenameExW = kernel32.NewProc("K32GetModuleFileNameExW")
)

func ReadProcessMemory(process windows.Handle, address uintptr, buffer []byte) (int, error) {
	numberOfBytesRead := uintptr(0)
	r0, _, lastErr := readProcessMemory.Call(
		uintptr(process),
		address,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&numberOfBytesRead)))

	if r0 == 0 {
		return int(numberOfBytesRead), lastErr
	}
	return int(numberOfBytesRead), nil
}

func GlobalMemoryStatusEx() (*MemoryStatusEx, error) {
	var memStat MemoryStatusEx
	memStat.Length = uint32(unsafe.Sizeof(memStat))
	r0, _, err := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStat)))
	if r0 == 0 {
		return nil, err
	}
	return &memStat, nil
}

func SuspendThread(thread windows.Handle) (uint32, error) {
	r0, _, lastErr := suspendThread.Call(uintptr(thread))
	if r0 == DwordNegativeOne {
		return 0, lastErr
	}
	return uint32(r0), nil
}

func CreateRemoteThreadMinimal(process windows.Handle, startAddress uintptr) error {
	r0, _, lastErr := createRemoteThread.Call(
		uintptr(process),
		uintptr(0),
		uintptr(0),
		startAddress,
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)
	if r0 == Null {
		return lastErr
	}
	return nil
}

func VirtualQueryEx(process windows.Handle, address uintptr) (MemoryBasicInformation, error) {
	mbi := MemoryBasicInformation{}
	r0, _, lastErr := virtualQueryEx.Call(
		uintptr(process),
		address,
		uintptr(unsafe.Pointer(&mbi)),
		unsafe.Sizeof(mbi))
	if r0 == 0 {
		return mbi, lastErr
	}
	return mbi, nil
}

func GetSystemTimes() (idleTicks int64, kernelTicks int64, userTicks int64, err error) {
	var fIdleTicks, fKernelTicks, fUserTicks windows.Filetime

	r0, _, lastErr := getSystemTimes.Call(
		uintptr(unsafe.Pointer(&fIdleTicks)),
		uintptr(unsafe.Pointer(&fKernelTicks)),
		uintptr(unsafe.Pointer(&fUserTicks)),
	)
	if r0 == 0 {
		err = lastErr
	}

	idleTicks = int64(fIdleTicks.HighDateTime)<<32 + int64(fIdleTicks.LowDateTime)
	kernelTicks = int64(fKernelTicks.HighDateTime)<<32 + int64(fKernelTicks.LowDateTime)
	userTicks = int64(fUserTicks.HighDateTime)<<32 + int64(fUserTicks.LowDateTime)

	return
}

func GetModuleFilenameExW(process windows.Handle, module windows.Handle) (string, error) {
	var buf [windows.MAX_PATH]uint16
	n := len(buf)
	r0, _, lastErr := getModuleFilenameExW.Call(
		uintptr(process),
		uintptr(module),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(n))
	if r0 == 0 {
		return "", lastErr
	}
	return windows.UTF16ToString(buf[:]), nil
}
