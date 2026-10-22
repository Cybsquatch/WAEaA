//go:build !windows

package privilege

import (
	"errors"
	"os"
)

// IsAdmin reports whether the process has root privileges on Unix-like systems.
func IsAdmin() bool {
	return os.Geteuid() == 0
}

// EnableBackupPrivilege is a no-op on Unix-like systems.
func EnableBackupPrivilege() error {
	return nil
}

// RelaunchElevated returns an error indicating sudo is required on Unix-like systems.
func RelaunchElevated(args []string) error {
	return errors.New("privilege: administrative privileges required; please run with sudo")
}
