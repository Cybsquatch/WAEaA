// Package cli parses and validates the command-line interface of the
// collector.
//
// The syntax is WAEaA's own and exposes a full set of triage capabilities:
// source/destination selection, rule selection, VSS processing, de-duplication,
// filters, live response, archive naming and case metadata.
//
// Every flag has a long form (--output) and, for the most common ones, a
// short alias (-o). Thanks to the standard flag package both "-output" and
// "--output" are accepted, as well as "--output=value".
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Cybsquatch/WAEaA/collector/internal/i18n"
	"github.com/Cybsquatch/WAEaA/collector/internal/logging"
)

// Action is what the program must do after a successful parse.
type Action int

const (
	// ActionCollect runs an acquisition.
	ActionCollect Action = iota
	// ActionListRules prints the available rules.
	ActionListRules
	// ActionVersion prints build information.
	ActionVersion
	// ActionHelp prints the usage text.
	ActionHelp
)

// SupportedExtraHashes are the optional algorithms computed in addition to
// SHA-256, which is always computed for every collected file.
var SupportedExtraHashes = []string{"md5", "sha1"}

// Options holds every setting of an acquisition. The GUI and the TUI fill
// the very same struct, so the collection engine has a single entry point
// regardless of the user interface.
type Options struct {
	Source        string   // volume or directory to collect from
	Output        string   // destination directory
	Rules         []string // rule / compound-rule IDs
	RulesDir      string   // optional directory with custom rules
	VSS           bool     // process Volume Shadow Copies
	NoDedup       bool     // disable SHA-1 de-duplication
	Include       []string // include globs
	Exclude       []string // exclude globs
	MaxFileSizeMB int64    // 0 = unlimited
	Live          bool     // run live-response commands
	NoZip         bool     // leave files in a folder
	ZipName       string   // archive base name ("" = hostname)
	CaseID        string   // chain-of-custody: case identifier
	Examiner      string   // chain-of-custody: examiner name
	Notes         string   // chain-of-custody: free text
	Authorized    bool     // operator confirmed lawful authorisation
	ExtraHashes   []string // subset of SupportedExtraHashes
	Lang          string   // UI language code
	Debug         bool
	Trace         bool
	Quiet         bool
}

// LogLevel maps the verbosity flags to the console log level.
func (o *Options) LogLevel() logging.Level {
	switch {
	case o.Trace:
		return logging.LevelTrace
	case o.Debug:
		return logging.LevelDebug
	case o.Quiet:
		return logging.LevelWarn
	default:
		return logging.LevelInfo
	}
}

// UsageError marks errors caused by wrong invocation; callers should print
// the usage text and exit with status 2.
type UsageError struct{ msg string }

func (e *UsageError) Error() string { return e.msg }

// IsUsageError reports whether err is (or wraps) a *UsageError.
func IsUsageError(err error) bool {
	var u *UsageError
	return errors.As(err, &u)
}

// flagSpec describes one flag for registration and for the usage text.
type flagSpec struct {
	long, short string // names without dashes
	arg         string // placeholder shown in help ("" for booleans)
	key         string // i18n key of the description
}

// specs is the single source of truth for the CLI surface, in help order.
var specs = []flagSpec{
	{"source", "s", "<path>", "flag.source"},
	{"output", "o", "<dir>", "flag.output"},
	{"rules", "r", "<id,...>", "flag.rules"},
	{"rules-dir", "", "<dir>", "flag.rules_dir"},
	{"list-rules", "l", "", "flag.list_rules"},
	{"vss", "", "", "flag.vss"},
	{"no-dedup", "", "", "flag.no_dedup"},
	{"include", "", "<glob>", "flag.include"},
	{"exclude", "", "<glob>", "flag.exclude"},
	{"max-file-size", "", "<MB>", "flag.max_file_size"},
	{"live", "", "", "flag.live"},
	{"no-zip", "", "", "flag.no_zip"},
	{"zip-name", "", "<name>", "flag.zip_name"},
	{"case-id", "", "<id>", "flag.case_id"},
	{"examiner", "", "<name>", "flag.examiner"},
	{"notes", "", "<text>", "flag.notes"},
	{"authorized", "", "", "flag.authorized"},
	{"hash", "", "<alg,...>", "flag.hash"},
	{"lang", "", "<code>", "flag.lang"},
	{"debug", "", "", "flag.debug"},
	{"trace", "", "", "flag.trace"},
	{"quiet", "q", "", "flag.quiet"},
	{"version", "V", "", "flag.version"},
	{"help", "h", "", "flag.help"},
}

// Parse parses args (without the program name). The usage text and every
// error message are rendered in the language selected with --lang, or in the
// system language when --lang is absent.
//
// It returns the parsed options, the action to perform and the translator
// that the caller should keep using for the rest of the run.
func Parse(args []string, progName string) (*Options, Action, *i18n.Translator, error) {
	opts := &Options{Source: defaultSource()}

	// The language must be known before building the help text, so it is
	// pre-scanned before the real parse.
	lang := scanLang(args)
	if lang == "" {
		lang = i18n.Detect()
	}
	tr := i18n.MustNew(lang)
	opts.Lang = tr.Lang()

	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are reported by the caller
	var (
		rules, hashes      string
		listRules, version bool
		help               bool
		include, exclude   stringList
	)

	// Bind every spec (long + optional short alias) to its destination.
	for _, s := range specs {
		names := []string{s.long}
		if s.short != "" {
			names = append(names, s.short)
		}
		for _, n := range names {
			switch s.long {
			case "source":
				fs.StringVar(&opts.Source, n, opts.Source, "")
			case "output":
				fs.StringVar(&opts.Output, n, "", "")
			case "rules":
				fs.StringVar(&rules, n, "", "")
			case "rules-dir":
				fs.StringVar(&opts.RulesDir, n, "", "")
			case "list-rules":
				fs.BoolVar(&listRules, n, false, "")
			case "vss":
				fs.BoolVar(&opts.VSS, n, false, "")
			case "no-dedup":
				fs.BoolVar(&opts.NoDedup, n, false, "")
			case "include":
				fs.Var(&include, n, "")
			case "exclude":
				fs.Var(&exclude, n, "")
			case "max-file-size":
				fs.Int64Var(&opts.MaxFileSizeMB, n, 0, "")
			case "live":
				fs.BoolVar(&opts.Live, n, false, "")
			case "no-zip":
				fs.BoolVar(&opts.NoZip, n, false, "")
			case "zip-name":
				fs.StringVar(&opts.ZipName, n, "", "")
			case "case-id":
				fs.StringVar(&opts.CaseID, n, "", "")
			case "examiner":
				fs.StringVar(&opts.Examiner, n, "", "")
			case "notes":
				fs.StringVar(&opts.Notes, n, "", "")
			case "authorized":
				fs.BoolVar(&opts.Authorized, n, false, "")
			case "hash":
				fs.StringVar(&hashes, n, "", "")
			case "lang":
				fs.StringVar(&opts.Lang, n, opts.Lang, "")
			case "debug":
				fs.BoolVar(&opts.Debug, n, false, "")
			case "trace":
				fs.BoolVar(&opts.Trace, n, false, "")
			case "quiet":
				fs.BoolVar(&opts.Quiet, n, false, "")
			case "version":
				fs.BoolVar(&version, n, false, "")
			case "help":
				fs.BoolVar(&help, n, false, "")
			default:
				panic("cli: unbound flag " + s.long) // caught by tests
			}
		}
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, ActionHelp, tr, nil
		}
		return nil, ActionHelp, tr, &UsageError{err.Error()}
	}
	if fs.NArg() > 0 {
		return nil, ActionHelp, tr, &UsageError{tr.T("err.unexpected_args", strings.Join(fs.Args(), " "))}
	}

	opts.Rules = splitList(rules)
	opts.ExtraHashes = splitList(strings.ToLower(hashes))
	opts.Include, opts.Exclude = include, exclude
	opts.Lang = i18n.Normalize(opts.Lang)
	if opts.Trace {
		opts.Debug = true
	}

	switch {
	case help:
		return opts, ActionHelp, tr, nil
	case version:
		return opts, ActionVersion, tr, nil
	case listRules:
		return opts, ActionListRules, tr, nil
	}
	if err := opts.Validate(tr); err != nil {
		return nil, ActionCollect, tr, err
	}
	return opts, ActionCollect, tr, nil
}

// Validate checks the consistency of an acquisition request. It is also
// called by the GUI/TUI before starting a collection.
func (o *Options) Validate(tr *i18n.Translator) error {
	if !i18n.IsSupported(o.Lang) {
		return &UsageError{tr.T("err.invalid_lang", o.Lang)}
	}
	if strings.TrimSpace(o.Output) == "" {
		return &UsageError{tr.T("err.missing_output")}
	}
	if len(o.Rules) == 0 {
		return &UsageError{tr.T("err.missing_rules")}
	}
	if !o.Authorized {
		return &UsageError{tr.T("err.not_authorized")}
	}
	if o.Quiet && (o.Debug || o.Trace) {
		return &UsageError{tr.T("err.debug_quiet")}
	}
	if o.MaxFileSizeMB < 0 {
		return &UsageError{tr.T("err.negative_size")}
	}
	for _, h := range o.ExtraHashes {
		if !contains(SupportedExtraHashes, h) {
			return &UsageError{tr.T("err.invalid_hash", h)}
		}
	}
	if o.ZipName != "" && !ValidArchiveName(o.ZipName) {
		return &UsageError{tr.T("err.invalid_zip_name", o.ZipName)}
	}
	return nil
}

// ValidArchiveName reports whether name can be used as an archive base name
// on both Windows and Linux: no path components, no characters reserved by
// NTFS, no trailing dot/space and a reasonable length.
func ValidArchiveName(name string) bool {
	if name == "" || len(name) > 200 || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `<>:"/\|?*`) || filepath.Base(name) != name {
		return false
	}
	for _, r := range name {
		if r < 0x20 {
			return false
		}
	}
	last := name[len(name)-1]
	return last != '.' && last != ' '
}

// PrintUsage writes the translated help text.
func PrintUsage(w io.Writer, tr *i18n.Translator, progName string) {
	fmt.Fprintf(w, "%s - %s\n\n", tr.T("app.title"), tr.T("app.description"))
	fmt.Fprintln(w, tr.T("usage.header", progName))
	fmt.Fprintf(w, "\n%s\n", tr.T("usage.options"))

	// Compute the left column first to align descriptions.
	left := make([]string, len(specs))
	width := 0
	for i, s := range specs {
		col := "    "
		if s.short != "" {
			col = "-" + s.short + ", "
		}
		col += "--" + s.long
		if s.arg != "" {
			col += " " + s.arg
		}
		left[i] = col
		if len(col) > width {
			width = len(col)
		}
	}
	for i, s := range specs {
		fmt.Fprintf(w, "  %-*s  %s\n", width, left[i], tr.T(s.key))
	}
	fmt.Fprintf(w, "\n%s\n\n%s\n", tr.T("usage.examples", progName), tr.T("legal.notice"))
}

// scanLang finds the value of --lang / -lang (both "--lang it" and
// "--lang=it" forms) without performing a full parse.
func scanLang(args []string) string {
	for i, a := range args {
		if a == "--" {
			break
		}
		name := strings.TrimLeft(a, "-")
		if len(a)-len(name) < 1 || len(a)-len(name) > 2 {
			continue
		}
		if name == "lang" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(name, "lang=") {
			return strings.TrimPrefix(name, "lang=")
		}
	}
	return ""
}

// splitList splits a comma separated list, trimming blanks and dropping
// empty items: " a, b,,c " -> [a b c].
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// stringList is a repeatable string flag (--include a --include b).
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }
