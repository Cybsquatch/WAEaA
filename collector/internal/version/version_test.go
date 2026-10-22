package version

import (
	"strings"
	"testing"
)

// TestStringContainsMetadata verifies that the build banner exposes every
// field required by the chain-of-custody record.
func TestStringContainsMetadata(t *testing.T) {
	s := String()
	for _, want := range []string{Name, Version, Flavor, Commit, BuildDate} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
}
