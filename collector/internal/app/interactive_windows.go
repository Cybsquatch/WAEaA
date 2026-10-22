//go:build windows

package app

import (
	"fmt"
	"io"
	"syscall"
	"unsafe"

	"github.com/Cybsquatch/WAEaA/collector/internal/gui"
	"github.com/Cybsquatch/WAEaA/collector/internal/privilege"
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

// runInteractive starts the graphical interface. If the program is not
// elevated, it requests UAC elevation. If the program owns its console
// (double-click launch), the console is released first.
func runInteractive(stdout, stderr io.Writer, prog string) int {
	// Ensure administrator rights for GUI mode so locked files ($MFT, registry) can be acquired
	if !privilege.IsAdmin() {
		if err := privilege.RelaunchElevated(nil); err == nil {
			// Successfully launched elevated instance
			return ExitOK
		}
		// If UAC was rejected or failed, notify user
		fmt.Fprintln(stderr, "Administrator privileges are required to run WAEaA.")
		if ownsConsole() {
			fmt.Fprint(stdout, "\n[Enter]")
			_, _ = fmt.Scanln()
		}
		return ExitFailure
	}

	// Enable forensic token privileges (SeBackupPrivilege, etc.)
	_ = privilege.EnableBackupPrivilege()

	// If started by double-click from Explorer, detach the console window
	if ownsConsole() {
		detachConsole()
	}

	// Launch native Windows GUI
	return gui.Run()
}
