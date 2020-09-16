// Package customWin32 provides a small subset of win32
// bindings. For most win32 purposes, this project uses
// https://github.com/0xrawsec/golang-win32, however some
// wrappers are undesirable without exposing the lower
// level calls, thus these are implemented here.
package customWin32

import (
	"syscall"
	"unsafe"

	"github.com/targodan/go-errors"

	"github.com/0xrawsec/golang-win32/win32"
	k32 "github.com/0xrawsec/golang-win32/win32/kernel32"
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	readProcessMemory    = kernel32.NewProc("ReadProcessMemory")
	globalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	process32NextW       = kernel32.NewProc("Process32NextW")
	thread32First        = kernel32.NewProc("Thread32First")
	thread32Next         = kernel32.NewProc("Thread32Next")
)

func ReadProcessMemory(hProcess win32.HANDLE, lpBaseAddress win32.LPCVOID, buffer []byte) (int, error) {
	numberOfBytesRead := win32.SIZE_T(0)
	r1, _, lastErr := readProcessMemory.Call(
		uintptr(hProcess),
		uintptr(lpBaseAddress),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&numberOfBytesRead)))

	if r1 == 0 {
		return int(numberOfBytesRead), lastErr
	} else {
		return int(numberOfBytesRead), nil
	}
}

func GlobalMemoryStatusEx() (*MemoryStatusEx, error) {
	memStat := new(MemoryStatusEx)
	memStat.Length = win32.DWORD(unsafe.Sizeof(*memStat))
	r1, _, err := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(memStat)))
	if r1 == 0 {
		return nil, err
	}
	return memStat, nil
}

func Process32NextW(hSnapshot win32.HANDLE, lpte k32.LPPROCESSENTRY32W) error {
	_, _, lastErr := process32NextW.Call(
		uintptr(hSnapshot),
		uintptr(unsafe.Pointer(lpte)))
	if lastErr.(syscall.Errno) == 0 {
		return nil
	}
	return lastErr
}

func Thread32First(hSnapshot win32.HANDLE, lpte k32.LPTHREADENTRY32) error {
	_, _, lastErr := thread32First.Call(
		uintptr(hSnapshot),
		uintptr(unsafe.Pointer(lpte)))
	if lastErr.(syscall.Errno) == 0 {
		return nil
	}
	return lastErr
}

// Thread32Next Win32 API wrapper
func Thread32Next(hSnapshot win32.HANDLE, lpte k32.LPTHREADENTRY32) error {
	_, _, lastErr := thread32Next.Call(
		uintptr(hSnapshot),
		uintptr(unsafe.Pointer(lpte)))
	if lastErr.(syscall.Errno) == 0 {
		return nil
	}
	return lastErr
}

func ListThreads(pid int) ([]int, error) {
	snap, err := k32.CreateToolhelp32Snapshot(k32.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}

	threadIDs := make([]int, 0)

	threadEntry := k32.NewThreadEntry32()

	err = Thread32First(snap, &threadEntry)
	if err != nil {
		if err.(syscall.Errno) != win32.ERROR_NO_MORE_FILES {
			return nil, err
		} else {
			return nil, nil
		}
	}
	if int(threadEntry.Th32OwnerProcessID) == pid {
		threadIDs = append(threadIDs, int(threadEntry.Th32ThreadID))
	}
	for {
		err = Thread32Next(snap, &threadEntry)
		if err != nil {
			break
		}
		if int(threadEntry.Th32OwnerProcessID) == pid {
			threadIDs = append(threadIDs, int(threadEntry.Th32ThreadID))
		}
	}
	if err.(syscall.Errno) != win32.ERROR_NO_MORE_FILES {
		return nil, err
	}
	return threadIDs, nil
}

func SuspendProcess(pid int) error {
	threads, err := ListThreads(pid)
	if err != nil {
		return errors.Errorf("could not list process threads, reason: %w", err)
	}
	for _, tid := range threads {
		hThread, err := k32.OpenThread(k32.THREAD_SUSPEND_RESUME, win32.FALSE, win32.DWORD(tid))
		if err != nil {
			return errors.Errorf("could not open thread %d, reason: %w", tid, err)
		}
		_, err = k32.SuspendThread(hThread)
		k32.CloseHandle(hThread)

		if err != nil {
			return errors.Errorf("could not open suspend thread %d, reason: %w", tid, err)
		}
	}
	return nil
}

func ResumeProcess(pid int) error {
	threads, err := ListThreads(pid)
	if err != nil {
		return errors.Errorf("could not list process threads, reason: %w", err)
	}
	for _, tid := range threads {
		hThread, err := k32.OpenThread(k32.THREAD_SUSPEND_RESUME, win32.FALSE, win32.DWORD(tid))
		if err != nil {
			return errors.Errorf("could not open thread %d, reason: %w", tid, err)
		}
		_, err = k32.ResumeThread(hThread)
		k32.CloseHandle(hThread)

		if err != nil {
			return errors.Errorf("could not open resume thread %d, reason: %w", tid, err)
		}
	}
	return nil
}
