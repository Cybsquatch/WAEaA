//go:build !windows

package app

import (
	"fmt"
	"io"
	"os"

	"github.com/Cybsquatch/WAEaA/collector/internal/i18n"
	"github.com/Cybsquatch/WAEaA/collector/internal/tui"
)

// isTerminal reports whether f is attached to a character device (a TTY).
// It relies only on os.Stat, so no cgo or extra dependency is required.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// runInteractive starts the terminal user interface when both stdin and
// stdout are TTYs; otherwise (cron, pipes, remote exec) it prints a hint.
func runInteractive(stdout, stderr io.Writer, prog string) int {
	tr := i18n.MustNew(i18n.Detect())
	if !isTerminal(os.Stdin) || !isTerminal(os.Stdout) {
		fmt.Fprintln(stderr, tr.T("interactive.no_terminal"))
		return ExitUsage
	}
	return tui.Run(os.Stdin, stdout)
}
