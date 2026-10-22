//go:build windows

package privilege

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modshell32  = syscall.NewLazyDLL("shell32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procOpenProcessToken      = modadvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation   = modadvapi32.NewProc("GetTokenInformation")
	procLookupPrivilegeValueW = modadvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = modadvapi32.NewProc("AdjustTokenPrivileges")
	procShellExecuteW         = modshell32.NewProc("ShellExecuteW")
	procGetCurrentProcess     = modkernel32.NewProc("GetCurrentProcess")
)

const (
	tokenQuery            = 0x0008
	tokenAdjustPrivileges = 0x0020
	tokenElevationType    = 20 // TokenElevation
	sePrivilegeEnabled    = 0x00000002
)

type tokenElevation struct {
	TokenIsElevated uint32
}

type luid struct {
	LowPart  uint32
	HighPart int32
}

type luidAndAttributes struct {
	Luid       luid
	Attributes uint32
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

// IsAdmin reports whether the current process is running with administrative
// privileges (elevated token on Windows Vista+).
func IsAdmin() bool {
	var token syscall.Handle
	proc, _, _ := procGetCurrentProcess.Call()
	r, _, _ := procOpenProcessToken.Call(proc, tokenQuery, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer syscall.CloseHandle(token)

	var elevation tokenElevation
	var returnedLen uint32
	r, _, _ = procGetTokenInformation.Call(
		uintptr(token),
		tokenElevationType,
		uintptr(unsafe.Pointer(&elevation)),
		uintptr(unsafe.Sizeof(elevation)),
		uintptr(unsafe.Pointer(&returnedLen)),
	)
	if r == 0 {
		return false
	}
	return elevation.TokenIsElevated != 0
}

// EnableBackupPrivilege enables SeBackupPrivilege, SeRestorePrivilege and
// SeSecurityPrivilege on the process token. This grants forensic bypass of
// NTFS DACL restrictions when opening files with FILE_FLAG_BACKUP_SEMANTICS.
func EnableBackupPrivilege() error {
	var token syscall.Handle
	proc, _, _ := procGetCurrentProcess.Call()
	r, _, err := procOpenProcessToken.Call(proc, tokenAdjustPrivileges|tokenQuery, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return fmt.Errorf("privilege: OpenProcessToken failed: %w", err)
	}
	defer syscall.CloseHandle(token)

	privs := []string{
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeSecurityPrivilege",
		"SeDebugPrivilege",
	}

	for _, privName := range privs {
		if err := setPrivilege(token, privName, true); err != nil {
			// Some privileges might not be available; continue with the others
			continue
		}
	}
	return nil
}

func setPrivilege(token syscall.Handle, name string, enable bool) error {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}

	var l luid
	r, _, err := procLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&l)),
	)
	if r == 0 {
		return err
	}

	tp := tokenPrivileges{
		PrivilegeCount: 1,
		Privileges: [1]luidAndAttributes{
			{
				Luid:       l,
				Attributes: 0,
			},
		},
	}
	if enable {
		tp.Privileges[0].Attributes = sePrivilegeEnabled
	}

	r, _, err = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		uintptr(unsafe.Sizeof(tp)),
		0,
		0,
	)
	if r == 0 {
		return err
	}
	return nil
}

// RelaunchElevated relaunches the current executable requesting UAC elevation
// via ShellExecuteW with verb "runas".
func RelaunchElevated(args []string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("privilege: cannot get executable path: %w", err)
	}

	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	filePtr, _ := syscall.UTF16PtrFromString(exePath)

	var argStr string
	if len(args) > 0 {
		argStr = strings.Join(args, " ")
	}
	argsPtr, _ := syscall.UTF16PtrFromString(argStr)

	cwd, _ := os.Getwd()
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)

	// SW_SHOWNORMAL = 1
	r, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(filePtr)),
		uintptr(unsafe.Pointer(argsPtr)),
		uintptr(unsafe.Pointer(cwdPtr)),
		1,
	)

	// ShellExecute returns an HINSTANCE > 32 on success
	if r <= 32 {
		return errors.New("privilege: user canceled or failed UAC elevation")
	}
	return nil
}
