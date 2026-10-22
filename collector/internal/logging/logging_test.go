package logging

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// fixedClock makes timestamps deterministic in tests.
func fixedClock() time.Time {
	return time.Date(2026, 10, 22, 9, 30, 0, 123, time.UTC)
}

func newTestLogger(level Level) (*Logger, *bytes.Buffer, *bytes.Buffer) {
	var console, file bytes.Buffer
	l := New(&console, level)
	l.now = fixedClock
	l.AttachFile(&file)
	return l, &console, &file
}

func TestConsoleLevelFiltering(t *testing.T) {
	l, console, _ := newTestLogger(LevelWarn)
	l.Info("hidden")
	l.Warn("shown")
	out := console.String()
	if strings.Contains(out, "hidden") || !strings.Contains(out, "shown") {
		t.Fatalf("unexpected console output: %q", out)
	}
}

// TestFileAlwaysRecordsDebug verifies the evidence log keeps Debug entries
// even when the operator asked for a quiet console.
func TestFileAlwaysRecordsDebug(t *testing.T) {
	l, _, file := newTestLogger(LevelWarn)
	l.Trace("trace-not-recorded")
	l.Debug("debug-recorded")
	out := file.String()
	if strings.Contains(out, "trace-not-recorded") {
		t.Error("trace entry must not be recorded at default verbosity")
	}
	if !strings.Contains(out, "debug-recorded") {
		t.Error("debug entry missing from file log")
	}
}

func TestFileRecordsTraceWhenRequested(t *testing.T) {
	l, _, file := newTestLogger(LevelTrace)
	l.Trace("trace-recorded")
	if !strings.Contains(file.String(), "trace-recorded") {
		t.Error("trace entry missing with --trace")
	}
}

func TestJSONLinesFormat(t *testing.T) {
	l, _, file := newTestLogger(LevelInfo)
	l.Info("copied", "path", `C:\Windows\System32\config\SYSTEM`, "size", 42, "err", errors.New("boom"))
	l.Error("odd", "dangling")

	sc := bufio.NewScanner(file)
	var entries []Entry
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("invalid JSON line %q: %v", sc.Text(), err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	e := entries[0]
	if e.Time != "2026-10-22T09:30:00.000000123Z" || e.Level != "INFO" || e.Message != "copied" {
		t.Errorf("unexpected entry header: %+v", e)
	}
	if e.Fields["size"].(float64) != 42 || e.Fields["err"] != "boom" {
		t.Errorf("unexpected fields: %+v", e.Fields)
	}
	if entries[1].Fields["!BADKEY"] != "dangling" {
		t.Errorf("dangling key not preserved: %+v", entries[1].Fields)
	}
}

func TestConsoleFormatIsStable(t *testing.T) {
	l, console, _ := newTestLogger(LevelInfo)
	l.Info("msg", "b", 2, "a", 1)
	want := "09:30:00 INFO  msg a=1 b=2\n"
	if console.String() != want {
		t.Errorf("console = %q, want %q", console.String(), want)
	}
}

func TestNilConsole(t *testing.T) {
	l := New(nil, LevelInfo)
	l.Info("no panic expected")
}
