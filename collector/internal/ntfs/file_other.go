//go:build !windows

package ntfs

import (
	"os"
)

// OpenForensic opens the file normally on non-Windows platforms.
func OpenForensic(path string) (*os.File, error) {
	return os.Open(path)
}

// StatForensic returns file info normally on non-Windows platforms.
func StatForensic(path string) (os.FileInfo, error) {
	return os.Stat(path)
}
