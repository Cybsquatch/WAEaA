package engine

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestApplySourceRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		cases := []struct {
			source, target, want string
		}{
			{`D:`, `C:\Windows\System32`, `D:\Windows\System32`},
			{`E:\mount`, `C:\Windows\System32`, `E:\mount\Windows\System32`},
			{`D:\`, `Users\test\NTUSER.DAT`, `D:\Users\test\NTUSER.DAT`},
		}

		for _, c := range cases {
			applied := applySourceRoot(c.source, c.target)
			got := filepath.Clean(applied)
			want := filepath.Clean(c.want)
			if !strings.EqualFold(got, want) {
				t.Errorf("applySourceRoot(%q, %q) = %q, want %q", c.source, c.target, got, want)
			}
		}
	} else {
		cases := []struct {
			source, target, want string
		}{
			{`/mnt/usb`, `/var/log`, `/mnt/usb/var/log`},
			{`/media/disk`, `etc/shadow`, `/media/disk/etc/shadow`},
		}

		for _, c := range cases {
			applied := applySourceRoot(c.source, c.target)
			got := filepath.Clean(applied)
			want := filepath.Clean(c.want)
			if got != want {
				t.Errorf("applySourceRoot(%q, %q) = %q, want %q", c.source, c.target, got, want)
			}
		}
	}
}

func TestReplaceEnvVar(t *testing.T) {
	in := `%systemroot%\System32\winevt\Logs`
	got := replaceEnvVar(in, "%SystemRoot%", `C:\Windows`)
	want := `C:\Windows\System32\winevt\Logs`
	if got != want {
		t.Errorf("replaceEnvVar = %q, want %q", got, want)
	}
}

func TestIsInsideOrSame(t *testing.T) {
	if runtime.GOOS == "windows" {
		if !isInsideOrSame(`C:\Windows\System32`, `C:\`) {
			t.Errorf("expected C:\\Windows\\System32 to be inside C:\\")
		}
		if !isInsideOrSame(`C:\Windows`, `C:\windows`) {
			t.Errorf("expected case-insensitive equality")
		}
		if isInsideOrSame(`D:\Windows`, `C:\`) {
			t.Errorf("expected D:\\Windows not to be inside C:\\")
		}
	} else {
		if !isInsideOrSame(`/tmp/test/source`, `/tmp/test/source`) {
			t.Errorf("expected exact match to be true")
		}
		if !isInsideOrSame(`/tmp/test/source/Logs`, `/tmp/test/source`) {
			t.Errorf("expected child path to be inside parent")
		}
		if isInsideOrSame(`/tmp/test/source_other`, `/tmp/test/source`) {
			t.Errorf("expected sibling path not to be inside parent")
		}
	}
}

func TestExpandPathSourceRoot(t *testing.T) {
	if runtime.GOOS != "windows" {
		mockSource := "/tmp/waeaa_test/source"
		res, err := ExpandPath(mockSource, mockSource)
		if err != nil {
			t.Fatalf("ExpandPath failed: %v", err)
		}
		if len(res) != 1 || res[0] != mockSource {
			t.Errorf("ExpandPath(%q, %q) = %v; want [%q]", mockSource, mockSource, res, mockSource)
		}
	}
}
