package ntfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenForensic(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "waeaa_ntfs_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "testfile.dat")
	if err := os.WriteFile(filePath, []byte("FORENSIC-DATA-STREAM"), 0644); err != nil {
		t.Fatal(err)
	}

	f, err := OpenForensic(filePath)
	if err != nil {
		t.Fatalf("OpenForensic failed on accessible file: %v", err)
	}
	defer f.Close()

	buf := make([]byte, 8)
	n, err := f.Read(buf)
	if err != nil || n != 8 || string(buf) != "FORENSIC" {
		t.Fatalf("unexpected read: %s (err: %v)", string(buf), err)
	}
}

func TestOpenForensicNonExistent(t *testing.T) {
	_, err := OpenForensic(`C:\this_file_does_not_exist_at_all_99999.dat`)
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
}
