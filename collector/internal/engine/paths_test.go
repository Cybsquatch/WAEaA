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
