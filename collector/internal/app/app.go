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
	"sort"

	"github.com/Cybsquatch/WAEaA/collector/internal/cli"
	"github.com/Cybsquatch/WAEaA/collector/internal/engine"
	"github.com/Cybsquatch/WAEaA/collector/internal/i18n"
	"github.com/Cybsquatch/WAEaA/collector/internal/logging"
	"github.com/Cybsquatch/WAEaA/collector/internal/version"
	rulesfs "github.com/Cybsquatch/WAEaA/collector/rules"
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

// listRules prints the available rules and compounds.
func listRules(stdout io.Writer, tr *i18n.Translator, opts *cli.Options) int {
	reg, err := rulesfs.LoadDefaultRegistry()
	if err != nil {
		fmt.Fprintf(stdout, "Error loading built-in rules: %v\n", err)
		return ExitFailure
	}
	if opts.RulesDir != "" {
		if err := rulesfs.LoadCustomRulesDirectory(reg, opts.RulesDir); err != nil {
			fmt.Fprintf(stdout, "Warning loading custom rules: %v\n", err)
		}
	}

	all := reg.All()
	sort.Slice(all, func(i, j int) bool {
		return all[i].ID < all[j].ID
	})

	fmt.Fprintf(stdout, "%s - %s\n\n", tr.T("app.title"), tr.T("flag.list_rules"))
	fmt.Fprintf(stdout, "%-24s  %-14s  %-10s  %s\n", "ID", "CATEGORY", "TYPE", "DESCRIPTION")
	fmt.Fprintf(stdout, "%-24s  %-14s  %-10s  %s\n", "------------------------", "--------------", "----------", "-----------")

	for _, r := range all {
		kind := "Target"
		if r.Compound {
			kind = "Compound"
		}
		desc := r.Description
		if len(desc) > 60 {
			desc = desc[:57] + "..."
		}
		fmt.Fprintf(stdout, "%-24s  %-14s  %-10s  %s\n", r.ID, r.Category, kind, desc)
	}
	return ExitOK
}

// collect runs an acquisition with validated options.
func collect(stdout, stderr io.Writer, tr *i18n.Translator, opts *cli.Options) int {
	logger := logging.New(stdout, opts.LogLevel())
	if err := engine.Run(opts, logger, tr); err != nil {
		logger.Error("Acquisition aborted with error", "err", err)
		return ExitFailure
	}
	return ExitOK
}
