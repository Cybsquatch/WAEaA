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

	// Verify Linux triage compound rule resolves cleanly
	linuxRules, linuxTargets, err := reg.Resolve([]string{"linux.triage"}, "linux")
	if err != nil {
		t.Fatalf("failed to resolve linux.triage rule: %v", err)
	}
	if len(linuxRules) < 4 {
		t.Errorf("expected at least 4 resolved sub-rules for linux.triage, got %d", len(linuxRules))
	}
	if len(linuxTargets) < 15 {
		t.Errorf("expected at least 15 targets for linux.triage, got %d", len(linuxTargets))
	}
}
