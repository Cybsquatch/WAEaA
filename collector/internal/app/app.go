// Package app wires the collector together and decides, at start-up, which
// user interface to run:
//
//   - arguments present          -> command-line mode;
//   - no arguments, Windows      -> graphical interface (GUI);
//   - no arguments, Linux + TTY  -> interactive terminal menu (TUI);
//   - no arguments, no TTY       -> usage text.
//
// This allows a single executable to serve both automated (scripted, remote)
// and interactive acquisitions.
package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Cybsquatch/WAEaA/collector/internal/cli"
	"github.com/Cybsquatch/WAEaA/collector/internal/i18n"
	"github.com/Cybsquatch/WAEaA/collector/internal/version"
)

// Exit codes returned by Main.
const (
	ExitOK      = 0 // success
	ExitFailure = 1 // acquisition or runtime error
	ExitUsage   = 2 // invalid command line
)

// Main is the real entry point; main.main only forwards os.Args and exits
// with the returned code. Keeping the logic here makes it testable.
func Main(args []string, stdout, stderr io.Writer) int {
	prog := filepath.Base(os.Args[0])
	if len(args) == 0 {
		return runInteractive(stdout, stderr, prog)
	}
	return runCLI(args, stdout, stderr, prog)
}

// runCLI handles command-line mode.
func runCLI(args []string, stdout, stderr io.Writer, prog string) int {
	opts, action, tr, err := cli.Parse(args, prog)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n\n", prog, err)
		if cli.IsUsageError(err) {
			fmt.Fprintf(stderr, "%s --help\n", prog)
			return ExitUsage
		}
		return ExitFailure
	}

	switch action {
	case cli.ActionHelp:
		cli.PrintUsage(stdout, tr, prog)
		return ExitOK
	case cli.ActionVersion:
		fmt.Fprintln(stdout, version.String())
		return ExitOK
	case cli.ActionListRules:
		return listRules(stdout, tr, opts)
	default:
		return collect(stdout, stderr, tr, opts)
	}
}

// listRules prints the available rules.
// The rule engine is implemented in milestone M2.
func listRules(stdout io.Writer, tr *i18n.Translator, _ *cli.Options) int {
	fmt.Fprintln(stdout, tr.T("app.title"))
	return ExitOK
}

// collect runs an acquisition with validated options.
// The collection engine is implemented in milestone M2.
func collect(stdout, stderr io.Writer, tr *i18n.Translator, opts *cli.Options) int {
	fmt.Fprintln(stdout, tr.T("legal.notice"))
	_ = opts
	return ExitOK
}
