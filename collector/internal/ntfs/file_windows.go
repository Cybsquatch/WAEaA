//go:build windows

package ntfs

import (
	"fmt"
	"os"
	"syscall"
)

const (
	fileFlagBackupSemantics = 0x02000000
	fileShareAll            = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE
)

// OpenForensic attempts to open a file with forensic bypass semantics:
//   - GENERIC_READ
//   - FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
//   - FILE_FLAG_BACKUP_SEMANTICS (bypasses DACLs via SeBackupPrivilege)
//
// This allows acquiring many files actively held open or locked by system
// processes (e.g. active event logs, hives or user profiles).
func OpenForensic(path string) (*os.File, error) {
	ptr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	h, err := syscall.CreateFile(
		ptr,
		syscall.GENERIC_READ,
		fileShareAll,
		nil,
		syscall.OPEN_EXISTING,
		fileFlagBackupSemantics,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("ntfs: CreateFile forensic open failed: %w", err)
	}

	return os.NewFile(uintptr(h), path), nil
}

// StatForensic returns file info using forensic bypass semantics (FILE_FLAG_BACKUP_SEMANTICS).
func StatForensic(path string) (os.FileInfo, error) {
	f, err := OpenForensic(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}
