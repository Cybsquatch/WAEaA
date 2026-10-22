//go:build !windows

package ntfs

import (
	"os"
)

// OpenForensic opens the file normally on non-Windows platforms.
func OpenForensic(path string) (*os.File, error) {
	return os.Open(path)
}
