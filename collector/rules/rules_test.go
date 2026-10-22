package rulesfs

import (
	"testing"
)

func TestLoadDefaultRegistry(t *testing.T) {
	reg, err := LoadDefaultRegistry()
	if err != nil {
		t.Fatalf("failed to load default registry: %v", err)
	}

	all := reg.All()
	if len(all) == 0 {
		t.Fatal("expected embedded rules, found none")
	}

	// Verify standard triage compound rule resolves cleanly
	resolvedRules, targets, err := reg.Resolve([]string{"triage"}, "windows")
	if err != nil {
		t.Fatalf("failed to resolve triage rule: %v", err)
	}

	if len(resolvedRules) < 5 {
		t.Errorf("expected at least 5 resolved sub-rules for triage, got %d", len(resolvedRules))
	}

	if len(targets) < 10 {
		t.Errorf("expected at least 10 targets for triage, got %d", len(targets))
	}
}
