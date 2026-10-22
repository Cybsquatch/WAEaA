//go:build !windows

package gui

// Run is a stub on non-Windows platforms (Linux uses TUI).
func Run() int {
	return 0
}
