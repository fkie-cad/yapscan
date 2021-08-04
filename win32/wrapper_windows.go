package win32

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ListThreads(pid uint32) ([]uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}

	threadIDs := make([]uint32, 0)

	var threadEntry windows.ThreadEntry32
	threadEntry.Size = uint32(unsafe.Sizeof(threadEntry))

	err = windows.Thread32First(snap, &threadEntry)
	if err != nil {
		if err != windows.ERROR_NO_MORE_FILES {
			return nil, err
		} else {
			return nil, nil
		}
	}
	if threadEntry.OwnerProcessID == pid {
		threadIDs = append(threadIDs, threadEntry.ThreadID)
	}
	for {
		err = windows.Thread32Next(snap, &threadEntry)
		if err != nil {
			break
		}
		if threadEntry.OwnerProcessID == pid {
			threadIDs = append(threadIDs, threadEntry.ThreadID)
		}
	}
	if err != windows.ERROR_NO_MORE_FILES {
		return nil, err
	}
	return threadIDs, nil
}

func SuspendProcess(pid uint32) error {
	threads, err := ListThreads(pid)
	if err != nil {
		return fmt.Errorf("could not list process threads, reason: %w", err)
	}
	for _, tid := range threads {
		hThread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, tid)
		if err != nil {
			return fmt.Errorf("could not open thread %d, reason: %w", tid, err)
		}
		_, err = SuspendThread(hThread)
		windows.CloseHandle(hThread)

		if err != nil {
			return fmt.Errorf("could not open suspend thread %d, reason: %w", tid, err)
		}
	}
	return nil
}

func ResumeProcess(pid uint32) error {
	threads, err := ListThreads(pid)
	if err != nil {
		return fmt.Errorf("could not list process threads, reason: %w", err)
	}
	for _, tid := range threads {
		hThread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, tid)
		if err != nil {
			return fmt.Errorf("could not open thread %d, reason: %w", tid, err)
		}
		_, err = windows.ResumeThread(hThread)
		windows.CloseHandle(hThread)

		if err != nil {
			return fmt.Errorf("could not open resume thread %d, reason: %w", tid, err)
		}
	}
	return nil
}

func GetTokenOwner(token windows.Token) (*windows.SID, error) {
	size := uint32(64) // Experimental value that works. unsafe.Sizeof(TokenOwner{}) is insufficient
	buffer := make([]byte, size)

	err := windows.GetTokenInformation(
		token,
		windows.TokenOwner,
		&buffer[0],
		size,
		&size,
	)
	if err != nil {
		return nil, err
	}

	owner := (*TokenOwner)(unsafe.Pointer(&buffer[0]))

	return owner.Owner, err
}

func ConvertSidToStringSid(sid *windows.SID) (string, error) {
	var ptr *uint16
	err := windows.ConvertSidToStringSid(sid, &ptr)
	if err != nil {
		return "", err
	}

	str := windows.UTF16PtrToString(ptr)

	windows.LocalFree(windows.Handle(unsafe.Pointer(ptr)))

	return str, nil
}
