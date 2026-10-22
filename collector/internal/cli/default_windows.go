//go:build windows

package cli

import "os"

// defaultSource returns the system drive (e.g. "C:"), the standard default
// volume used for forensic triage on Windows.
func defaultSource() string {
	if d := os.Getenv("SystemDrive"); d != "" {
		return d
	}
	return "C:"
}
