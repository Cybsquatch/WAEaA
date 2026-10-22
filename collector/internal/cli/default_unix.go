//go:build !windows

package cli

// defaultSource returns the root filesystem on Unix-like systems.
func defaultSource() string { return "/" }
