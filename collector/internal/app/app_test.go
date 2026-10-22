package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Cybsquatch/WAEaA/collector/internal/version"
)

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Main(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersion(t *testing.T) {
	code, out, _ := run("--version")
	if code != ExitOK || !strings.Contains(out, version.Version) {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestHelpExitsOK(t *testing.T) {
	code, out, _ := run("--help", "--lang", "en")
	if code != ExitOK || !strings.Contains(out, "--output") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestUsageErrorExitCode(t *testing.T) {
	code, _, errOut := run("--lang", "en", "-r", "triage")
	if code != ExitUsage {
		t.Fatalf("code=%d, want %d", code, ExitUsage)
	}
	if !strings.Contains(errOut, "output directory is required") {
		t.Errorf("stderr=%q", errOut)
	}
}
