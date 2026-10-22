package engine

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Cybsquatch/WAEaA/collector/internal/cli"
	"github.com/Cybsquatch/WAEaA/collector/internal/i18n"
	"github.com/Cybsquatch/WAEaA/collector/internal/logging"
)

func TestEngineEndToEnd(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "waeaa_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	mockSource := filepath.Join(tmpDir, "source")
	mockOut := filepath.Join(tmpDir, "output")
	mockRulesDir := filepath.Join(tmpDir, "custom_rules")
	_ = os.MkdirAll(mockSource, 0755)
	_ = os.MkdirAll(mockOut, 0755)
	_ = os.MkdirAll(mockRulesDir, 0755)

	// Create test files to collect
	logsDir := filepath.Join(mockSource, "Logs")
	_ = os.MkdirAll(logsDir, 0755)
	log1Content := []byte("EVTX-MOCK-CONTENT-12345")
	_ = os.WriteFile(filepath.Join(logsDir, "Security.evtx"), log1Content, 0644)

	// Create duplicate file to test deduplication
	dupDir := filepath.Join(mockSource, "Dup")
	_ = os.MkdirAll(dupDir, 0755)
	_ = os.WriteFile(filepath.Join(dupDir, "Security_Backup.evtx"), log1Content, 0644)

	// Write custom rule targeting mock directory
	customRuleYAML := []byte(`
id: test.mock_logs
name: Mock Test Logs
category: Test
os: all
targets:
  - path: '` + filepath.ToSlash(mockSource) + `'
    mask: '*.evtx'
    recursive: true
    comment: Test EVTX
`)
	_ = os.WriteFile(filepath.Join(mockRulesDir, "mock_rule.yaml"), customRuleYAML, 0644)

	opts := &cli.Options{
		Source:      mockSource,
		Output:      mockOut,
		Rules:       []string{"test.mock_logs"},
		RulesDir:    mockRulesDir,
		ZipName:     "MOCK_HOST",
		Authorized:  true,
		CaseID:      "TEST-CASE-001",
		Examiner:    "Lead Investigator",
		ExtraHashes: []string{"md5", "sha1"},
		Lang:        "en",
	}

	var logOut bytes.Buffer
	logger := logging.New(&logOut, logging.LevelDebug)
	tr := i18n.MustNew("en")

	if err := Run(opts, logger, tr); err != nil {
		t.Fatalf("Engine Run failed: %v", err)
	}

	// Verify zip file created
	zipPath := filepath.Join(mockOut, "MOCK_HOST.zip")
	if _, err := os.Stat(zipPath); err != nil {
		t.Fatalf("Expected archive %s not found: %v", zipPath, err)
	}

	// Verify sidecar sha256
	shaSidecar := zipPath + ".sha256"
	shaData, err := os.ReadFile(shaSidecar)
	if err != nil {
		t.Fatalf("Expected sidecar %s not found: %v", shaSidecar, err)
	}

	zipData, _ := os.ReadFile(zipPath)
	h := sha256.Sum256(zipData)
	expectedHex := hex.EncodeToString(h[:])
	if !strings.HasPrefix(string(shaData), expectedHex) {
		t.Errorf("Sidecar sha256 %s does not match computed %s", string(shaData), expectedHex)
	}

	// Inspect ZIP content
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("Failed to open zip reader: %v", err)
	}
	defer zr.Close()

	entries := make(map[string]*zip.File)
	for _, f := range zr.File {
		entries[f.Name] = f
	}

	// Check meta files inside zip
	expectedMetas := []string{
		"_meta/manifest.csv",
		"_meta/manifest.json",
		"_meta/chain_of_custody.json",
		"_meta/chain_of_custody.html",
		"_meta/collection.log",
	}
	for _, meta := range expectedMetas {
		if _, ok := entries[meta]; !ok {
			t.Errorf("Missing expected metadata entry in archive: %s", meta)
		}
	}

	// Read and verify manifest
	manifestF := entries["_meta/manifest.json"]
	if manifestF != nil {
		rc, err := manifestF.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		data, _ := io.ReadAll(rc)
		str := string(data)
		if !strings.Contains(str, "Security.evtx") {
			t.Errorf("Manifest does not contain Security.evtx: %s", str)
		}
		if !strings.Contains(str, `"deduplicated": true`) {
			t.Errorf("Manifest does not indicate deduplication: %s", str)
		}
	}
}
