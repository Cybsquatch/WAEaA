package tui

import (
	"bytes"
	"strings"
	"testing"
)

func TestTUIAbortWhenNotAuthorized(t *testing.T) {
	// Simulate user entering defaults for output and rule, but "n" for authorization
	input := "/tmp/testout\n1\nnone\nCASE-1\nAnalyst\nNotes\nn\n"
	stdin := strings.NewReader(input)
	var stdout bytes.Buffer

	code := Run(stdin, &stdout)
	if code != 1 {
		t.Fatalf("expected exit code 1 for denied authorization, got %d", code)
	}

	outStr := stdout.String()
	if !strings.Contains(outStr, "Acquisition aborted: authorization not confirmed") {
		t.Errorf("expected abort message, got: %s", outStr)
	}
}
