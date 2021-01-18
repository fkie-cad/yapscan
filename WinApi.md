# Demystifying Win32 API

In this document, an overview of the win32 APIs is given regarding process and memory scanning. If the scanner is a 64-bit application, these calls result in an executable which can scan memory of both 64- and 32-bit processes.

The shown code samples are not valid C code. They are supposed to be more akin to pseudo-code to give you a starting point for researching how to access another processes memory. You can find the shown API calls in the context of Go in these files: [procio/process_windows.go](procio/process_windows.go), [procio/memory_windows.go](procio/memory_windows.go) and [procio/reader_windows.go](procio/reader_windows.go).

## Listing Processes

```
snapHandle = kernel32.dll::CreateToolhelp32Snapshot(TH32CS_SCNAPPROCESS, 0);

PROCESSENTRY32W procEntry;
procEntry.DwSize = sizeof(procEntry);

kernel32.dll::Process32FirstW(snapHandle, &procEntry);
error = kernel32.dll::GetLastError();
if(error == ERROR_NO_MORE_FILES) {
	// No processes running, return success
} else if(error != 0) {
	// Handle error
}
// Handle procEntry
while(true) {
	kernel32.dll::Process32NextW(snapHandle, &procEntry);
	error = kernel32.dll::GetLastError();
	if(error == ERROR_NO_MORE_FILES) {
        break
    } else if(error != 0) {
        // Handle error
    }
   	// Handle procEntry
}
kernel32.dll::CloseHandle(snapHandle);
```

## Open Process Handle for later Use

Note that the permissions requested here are the permissions needed for all actions, yapscan may perform on a process. You can omit `PROCESS_SUSPEND_RESUME` if you do not plan on suspending or resuming the process.

```
procHandle = kernel32.dll::OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION|PROCESS_SUSPEND_RESUME, FALSE, pidOfProcess);
// Handle kernel32.dll::GetLastError()

// Do something with handle, then remember to cleanup

kernel32.dll::CloseHandle(procHandle);
```

## Listing Virtual Memory Segments

```
procHandle = // see above
address = 0;
while(true) {
	MemoryBasicInformation mbi;
	kernel32.dll::VirtualQueryEx(procHandle, address, &mbi, sizeof(mbi));
	error = kernel32.dll::GetLastError();
	if(error == ERROR_INVALID_PARAMETER) {
		// Ran out of bounds for memory address
		break;
	} else if(error != 0) {
		// Handle error
	}
	
	// handle mbi
	
	address += mbi.RegionSize;
}
```

## Reading Virtual Memory

```
byte buffer[512];
size_t bytesRead;
void* address = ...;
while(true) {
	kernel32.dll::ReadProcessMemory(procHandle, address, buffer, sizeof(buffer), &bytesRead);
	// Handle error
	// Note: Frequently ERROR_PARTIAL_COPY is emitted and I don't really know how to handle that one properly.
	
	for(int i = 0; i < bytesRead; i++) {
		// use the data in buffer[i]
	}
	address += bytesRead;
}
```

