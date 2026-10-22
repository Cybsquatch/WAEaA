package rules

import (
	"testing"
)

func TestParseYAMLAndResolve(t *testing.T) {
	yamlEvtx := []byte(`
id: win.eventlogs
name: Windows Event Logs
category: EventLogs
os: windows
targets:
  - path: '%SystemRoot%\System32\winevt\Logs'
    mask: '*.evtx'
    recursive: false
`)

	yamlRegistry := []byte(`
id: win.registry
name: Registry Hives
category: Registry
os: windows
targets:
  - path: '%SystemRoot%\System32\config'
    mask: 'SYSTEM*'
    raw_ntfs: true
`)

	yamlTriage := []byte(`
id: win.triage
name: Basic Windows Triage
category: Compound
os: windows
compound: true
rules:
  - win.eventlogs
  - win.registry
`)

	reg := NewRegistry()
	if _, err := reg.ParseYAML(yamlEvtx); err != nil {
		t.Fatalf("failed to parse evtx: %v", err)
	}
	if _, err := reg.ParseYAML(yamlRegistry); err != nil {
		t.Fatalf("failed to parse registry: %v", err)
	}
	if _, err := reg.ParseYAML(yamlTriage); err != nil {
		t.Fatalf("failed to parse triage: %v", err)
	}

	// Resolve compound rule
	resolved, targets, err := reg.Resolve([]string{"win.triage"}, "windows")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	if len(resolved) != 3 {
		t.Fatalf("expected 3 resolved rules, got %d", len(resolved))
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	// Check OS filtering (requesting linux should yield 0)
	resolvedLinux, targetsLinux, err := reg.Resolve([]string{"win.triage"}, "linux")
	if err != nil {
		t.Fatalf("linux resolve failed: %v", err)
	}
	if len(resolvedLinux) != 0 || len(targetsLinux) != 0 {
		t.Fatalf("expected 0 for mismatched OS, got %d rules, %d targets", len(resolvedLinux), len(targetsLinux))
	}
}

func TestCircularReference(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&Rule{ID: "rule1", Compound: true, Rules: []string{"rule2"}})
	_ = reg.Register(&Rule{ID: "rule2", Compound: true, Rules: []string{"rule1"}})

	_, _, err := reg.Resolve([]string{"rule1"}, "all")
	if err == nil {
		t.Fatal("expected circular reference error, got nil")
	}
}

func TestDuplicateRuleID(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&Rule{ID: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(&Rule{ID: "test"}); err == nil {
		t.Fatal("expected duplicate error, got nil")
	}
}
