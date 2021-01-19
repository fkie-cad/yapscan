package customWin32

import (
	"fmt"
	"syscall"
	"unsafe"
)

// #include<windows.h>
// #include<winnt.h>
//
// int wstrlen(WCHAR* str) {
//     int i = 0;
//     while(str[i] != 0) {
//         ++i;
//     }
//     return i+1;
// }
//
// void copy(WCHAR* dst, WCHAR* src, int count) {
//     memcpy(dst, src, count);
// }
import "C"

type TokenOwner C.TOKEN_OWNER

// BOOL OpenProcessToken(
//  HANDLE  ProcessHandle,
//  DWORD   DesiredAccess,
//  PHANDLE TokenHandle
//);
func OpenProcessToken(process syscall.Handle, desiredAccess uint32) (syscall.Token, error) {
	var t syscall.Token
	err := syscall.OpenProcessToken(
		process,
		desiredAccess,
		&t,
	)
	return t, err
}

//BOOL GetTokenInformation(
//  HANDLE                  TokenHandle,
//  TOKEN_INFORMATION_CLASS TokenInformationClass,
//  LPVOID                  TokenInformation,
//  DWORD                   TokenInformationLength,
//  PDWORD                  ReturnLength
//);
func GetTokenOwner(token syscall.Token) (*syscall.SID, error) {
	size := uint32(64) // Don't actually know what we need. In theory there should just be a pointer in there.
	buffer := make([]byte, size)

	err := syscall.GetTokenInformation(
		token,
		syscall.TokenOwner,
		&buffer[0],
		size,
		&size,
	)
	if err != nil {
		return nil, err
	}

	owner := (*TokenOwner)(unsafe.Pointer(&buffer[0]))

	return (*syscall.SID)(owner.Owner), err
}

//BOOL LookupAccountSidW(
//  LPCWSTR       lpSystemName,
//  PSID          Sid,
//  LPWSTR        Name,
//  LPDWORD       cchName,
//  LPWSTR        ReferencedDomainName,
//  LPDWORD       cchReferencedDomainName,
//  PSID_NAME_USE peUse
//);
func UsernameFromSID(sid *syscall.SID) (string, error) {
	var nameLength uint32
	var domainLength uint32

	err := syscall.LookupAccountSid(
		nil,
		sid,
		nil,
		&nameLength,
		nil,
		&domainLength,
		nil,
	)
	if err != syscall.ERROR_INSUFFICIENT_BUFFER || nameLength == 0 || domainLength == 0 {
		return "", fmt.Errorf("could not determine username length, reason: %w", err)
	}

	accountName := make([]uint16, nameLength/2+1)
	domainName := make([]uint16, domainLength/2+1)

	err = syscall.LookupAccountSid(
		nil,
		sid,
		&accountName[0],
		&nameLength,
		&domainName[0],
		&domainLength,
		nil,
	)
	if err != nil {
		return "", err
	}

	return syscall.UTF16ToString(domainName) + "\\" + syscall.UTF16ToString(accountName), nil
}

//BOOL ConvertSidToStringSidW(
//  PSID   Sid,
//  LPWSTR *StringSid
//);
func ConvertSidToStringSid(sid *syscall.SID) (string, error) {
	var ptr *uint16
	err := syscall.ConvertSidToStringSid(sid, &ptr)
	if err != nil {
		return "", err
	}

	l := C.wstrlen((*C.WCHAR)(ptr))
	buff := make([]uint16, l)
	C.copy((*C.WCHAR)(&buff[0]), (*C.WCHAR)(ptr), l)

	syscall.LocalFree(syscall.Handle(unsafe.Pointer(ptr)))

	return syscall.UTF16ToString(buff), nil
}
