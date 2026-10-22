package cli

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/Cybsquatch/WAEaA/collector/internal/i18n"
	"github.com/Cybsquatch/WAEaA/collector/internal/logging"
)

// validArgs is a minimal valid acquisition command line.
var validArgs = []string{"-o", "out", "-r", "triage", "--authorized", "--lang", "en"}

func TestParseValidCollect(t *testing.T) {
	args := append([]string{}, validArgs...)
	args = append(args,
		"--vss", "--no-dedup", "--live", "--no-zip",
		"--include", "*.evtx", "--include", "*.pf", "--exclude", "*.tmp",
		"--max-file-size", "500", "--zip-name", "HOST01",
		"--case-id", "IR-1", "--examiner", "Jane", "--notes", "n",
		"--hash", "MD5, sha1", "-s", "D:", "--rules-dir", "custom")
	opts, action, _, err := Parse(args, "waeaa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if action != ActionCollect {
		t.Fatalf("action = %v, want ActionCollect", action)
	}
	want := &Options{
		Source: "D:", Output: "out", Rules: []string{"triage"}, RulesDir: "custom",
		VSS: true, NoDedup: true, Include: []string{"*.evtx", "*.pf"}, Exclude: []string{"*.tmp"},
		MaxFileSizeMB: 500, Live: true, NoZip: true, ZipName: "HOST01",
		CaseID: "IR-1", Examiner: "Jane", Notes: "n", Authorized: true,
		ExtraHashes: []string{"md5", "sha1"}, Lang: "en",
	}
	if !reflect.DeepEqual(opts, want) {
		t.Errorf("got  %+v\nwant %+v", opts, want)
	}
}

func TestShortAndLongFormsAreEquivalent(t *testing.T) {
	a, _, _, err1 := Parse([]string{"-o", "x", "-r", "a,b", "--authorized", "--lang", "en"}, "waeaa")
	b, _, _, err2 := Parse([]string{"--output=x", "--rules", "a, b", "-authorized", "-lang=en"}, "waeaa")
	if err1 != nil || err2 != nil {
		t.Fatalf("errors: %v / %v", err1, err2)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("short %+v != long %+v", a, b)
	}
}

func TestParseActions(t *testing.T) {
	cases := map[string]Action{
		"--list-rules": ActionListRules,
		"-l":           ActionListRules,
		"--version":    ActionVersion,
		"-V":           ActionVersion,
		"--help":       ActionHelp,
		"-h":           ActionHelp,
	}
	for arg, want := range cases {
		_, got, _, err := Parse([]string{arg}, "waeaa")
		if err != nil {
			t.Errorf("%s: unexpected error %v", arg, err)
		}
		if got != want {
			t.Errorf("%s: action %v, want %v", arg, got, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string // substring of the English message
	}{
		{"no output", []string{"-r", "triage", "--authorized"}, "output directory is required"},
		{"no rules", []string{"-o", "x", "--authorized"}, "at least one rule"},
		{"not authorized", []string{"-o", "x", "-r", "t"}, "--authorized"},
		{"quiet+debug", append([]string{"-q", "--debug"}, validArgs...), "--quiet cannot"},
		{"bad hash", append([]string{"--hash", "crc32"}, validArgs...), "unsupported hash algorithm: crc32"},
		{"bad lang", []string{"-o", "x", "-r", "t", "--authorized", "--lang", "xx"}, "unsupported language: xx"},
		{"bad zip", append([]string{"--zip-name", "a/b"}, validArgs...), "invalid archive name"},
		{"negative size", append([]string{"--max-file-size", "-1"}, validArgs...), "cannot be negative"},
		{"positional", append([]string{"extra"}, validArgs...), ""},
		{"unknown flag", []string{"--nope"}, "nope"},
	}
	for _, c := range cases {
		args := c.args
		if !containsArg(args, "--lang") {
			args = append(args, "--lang", "en")
		}
		_, _, _, err := Parse(args, "waeaa")
		if err == nil {
			t.Errorf("%s: expected error", c.name)
			continue
		}
		if !IsUsageError(err) {
			t.Errorf("%s: error %v is not a UsageError", c.name, err)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not contain %q", c.name, err, c.want)
		}
	}
}

func TestErrorsAreTranslated(t *testing.T) {
	_, _, _, err := Parse([]string{"-r", "t", "--authorized", "--lang", "it"}, "waeaa")
	if err == nil || !strings.Contains(err.Error(), "obbligatoria") {
		t.Fatalf("expected Italian error, got %v", err)
	}
}

func TestTraceImpliesDebugAndLogLevel(t *testing.T) {
	opts, _, _, err := Parse(append([]string{"--trace"}, validArgs...), "waeaa")
	if err != nil {
		t.Fatal(err)
	}
	if !opts.Debug || opts.LogLevel() != logging.LevelTrace {
		t.Errorf("trace: debug=%v level=%v", opts.Debug, opts.LogLevel())
	}
	if (&Options{Quiet: true}).LogLevel() != logging.LevelWarn {
		t.Error("quiet should map to Warn")
	}
	if (&Options{}).LogLevel() != logging.LevelInfo {
		t.Error("default should map to Info")
	}
}

func TestValidArchiveName(t *testing.T) {
	good := []string{"HOST01", "srv-db_01", "WS 12"}
	bad := []string{"", ".", "..", "a/b", `a\b`, "a:b", "a*", "name.", "name ", "tab\tname", strings.Repeat("x", 201)}
	for _, n := range good {
		if !ValidArchiveName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range bad {
		if ValidArchiveName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}

// TestUsageListsEveryFlag ensures each spec appears in every language's help
// and that no translation key is missing (a missing key is echoed verbatim).
func TestUsageListsEveryFlag(t *testing.T) {
	for _, lang := range i18n.Supported {
		var buf bytes.Buffer
		PrintUsage(&buf, i18n.MustNew(lang), "waeaa")
		out := buf.String()
		for _, s := range specs {
			if !strings.Contains(out, "--"+s.long) {
				t.Errorf("%s: usage misses --%s", lang, s.long)
			}
			if strings.Contains(out, s.key) {
				t.Errorf("%s: untranslated key %s", lang, s.key)
			}
		}
	}
}

func TestScanLang(t *testing.T) {
	cases := map[string][]string{
		"it": {"--lang", "it"},
		"de": {"-lang=de"},
		"fr": {"-o", "x", "--lang=fr"},
		"":   {"--", "--lang", "it"},
	}
	for want, args := range cases {
		if got := scanLang(args); got != want {
			t.Errorf("scanLang(%v) = %q, want %q", args, got, want)
		}
	}
}

func containsArg(args []string, a string) bool {
	for _, x := range args {
		if x == a {
			return true
		}
	}
	return false
}
