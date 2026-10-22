//go:build windows

package app

import (
	"fmt"
	"io"
	"syscall"
	"unsafe"

	"github.com/Cybsquatch/WAEaA/collector/internal/i18n"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procFreeConsole           = kernel32.NewProc("FreeConsole")
)

// ownsConsole reports whether this process is the only one attached to its
// console, which happens when the executable is started by double-click from
// Explorer: Windows creates a fresh console just for us. When started from
// cmd.exe or PowerShell, the shell is attached too and the count is >= 2.
func ownsConsole() bool {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// detachConsole hides the console window created for a double-click launch,
// leaving only the GUI on screen.
func detachConsole() {
	_, _, _ = procFreeConsole.Call()
}

// runInteractive starts the graphical interface. If the program owns its
// console (double-click), the console is released first.
// The GUI itself is implemented in milestone M4.
func runInteractive(stdout, stderr io.Writer, prog string) int {
	tr := i18n.MustNew(i18n.Detect())
	if ownsConsole() {
		// Until the GUI exists, keep the console so the message is readable.
		fmt.Fprintln(stdout, tr.T("interactive.not_implemented"))
		fmt.Fprint(stdout, "\n[Enter]")
		_, _ = fmt.Scanln()
		return ExitOK
	}
	fmt.Fprintln(stderr, tr.T("interactive.not_implemented"))
	return ExitUsage
}

// Ensure detachConsole is referenced until the GUI uses it (M4).
var _ = detachConsole
