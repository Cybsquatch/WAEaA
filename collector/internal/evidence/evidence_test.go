package evidence

import (
	"bytes"
	"strings"
	"testing"
)

func TestManifestCSVAndJSON(t *testing.T) {
	m := NewManifest()
	m.Add(Item{
		SourcePath:   `C:\Windows\System32\winevt\Logs\System.evtx`,
		ArchivePath:  `C/Windows/System32/winevt/Logs/System.evtx`,
		Size:         1024,
		SHA256:       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		RuleID:       "win.eventlogs",
		Deduplicated: false,
	})
	m.Add(Item{
		SourcePath:          `C:\Users\test\NTUSER.DAT`,
		ArchivePath:         `C/Users/test/NTUSER.DAT`,
		Size:                2048,
		SHA256:              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		RuleID:              "win.registry",
		Deduplicated:        true,
		OriginalArchivePath: `C/Users/other/NTUSER.DAT`,
	})

	if m.Count() != 2 {
		t.Fatalf("expected count 2, got %d", m.Count())
	}
	if m.TotalBytes() != 3072 {
		t.Fatalf("expected 3072 bytes, got %d", m.TotalBytes())
	}

	var csvBuf bytes.Buffer
	if err := m.WriteCSV(&csvBuf); err != nil {
		t.Fatalf("WriteCSV failed: %v", err)
	}
	csvStr := csvBuf.String()
	if !strings.Contains(csvStr, "System.evtx") || !strings.Contains(csvStr, "original_archive_path") {
		t.Errorf("CSV output unexpected:\n%s", csvStr)
	}

	var jsonBuf bytes.Buffer
	if err := m.WriteJSON(&jsonBuf); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	jsonStr := jsonBuf.String()
	if !strings.Contains(jsonStr, "win.eventlogs") {
		t.Errorf("JSON output unexpected:\n%s", jsonStr)
	}
}

func TestCustodyHTMLAndJSON(t *testing.T) {
	rec := &Record{
		CaseID:        "CASE-2026-99",
		Examiner:      "Forensic Analyst",
		Hostname:      "WIN-TARGET",
		OS:            "windows",
		Platform:      "Windows 10",
		Architecture:  "amd64",
		TotalItems:    42,
		TotalBytes:    100000,
		ArchiveName:   "WIN-TARGET.zip",
		ArchiveSHA256: "abcdef1234567890",
		RulesExecuted: []string{"triage", "win.eventlogs"},
		Authorized:    true,
	}

	var jsonBuf bytes.Buffer
	if err := rec.WriteJSON(&jsonBuf); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if !strings.Contains(jsonBuf.String(), "CASE-2026-99") {
		t.Error("JSON does not contain CaseID")
	}

	htmlBytes, err := rec.GenerateHTML()
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	htmlStr := string(htmlBytes)
	if !strings.Contains(htmlStr, "CASE-2026-99") || !strings.Contains(htmlStr, "Authorised Acquisition") {
		t.Errorf("HTML output unexpected: %s", htmlStr)
	}
}

func TestResultsTrackerFormatText(t *testing.T) {
	tracker := NewResultsTracker()
	tracker.RecordTarget(TargetRecord{
		RuleID:        "win.eventlogs",
		Comment:       "Windows Event Logs",
		Source:        "C:\\",
		Path:          "C:\\Windows\\System32\\winevt\\Logs",
		Mask:          "*.evtx",
		Status:        StatusAcquired,
		FilesAcquired: 15,
		BytesAcquired: 1048576,
	})
	tracker.RecordTarget(TargetRecord{
		RuleID:  "win.prefetch",
		Comment: "Prefetch Files",
		Source:  "E:\\",
		Path:    "E:\\Windows\\Prefetch",
		Mask:    "*.pf",
		Status:  StatusNotFound,
		Details: "Path does not exist on source",
	})
	tracker.RecordFileError("F:\\corrupt.log", "win.tasks", ioError("file corrupted"))

	rec := &Record{
		CaseID:        "CASE-01",
		Examiner:      "Analyst",
		Hostname:      "HOST1",
		Platform:      "windows",
		Architecture:  "amd64",
		TotalItems:    15,
		TotalBytes:    1048576,
		ArchiveName:   "HOST1.zip",
		ArchiveSHA256: "hash123",
		RulesExecuted: []string{"win.eventlogs", "win.prefetch"},
	}

	out := tracker.FormatText(rec, []string{"C:\\", "E:\\"})
	text := string(out)

	if !strings.Contains(text, "WAEaA FORENSIC EXTRACTION RESULTS") {
		t.Errorf("Missing header in results.txt")
	}
	if !strings.Contains(text, "win.eventlogs") || !strings.Contains(text, "15 files") {
		t.Errorf("Missing acquired target info in results.txt")
	}
	if !strings.Contains(text, "NOT FOUND") || !strings.Contains(text, "win.prefetch") {
		t.Errorf("Missing skipped target info in results.txt")
	}
	if !strings.Contains(text, "file corrupted") {
		t.Errorf("Missing file read error in results.txt")
	}
}

type ioError string

func (e ioError) Error() string { return string(e) }
