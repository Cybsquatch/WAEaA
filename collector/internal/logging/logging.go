// Package logging implements the dual-output logger of the collector.
//
// Every message is written to two independent sinks:
//
//   - the console (human readable, filtered by the verbosity chosen by the
//     user with --quiet / --debug / --trace);
//   - the collection log file (JSON Lines, one object per entry). This file is
//     part of the evidence package, so it always records at least Debug level
//     and every timestamp is in UTC with nanosecond precision.
//
// The standard library log/slog package is intentionally not used because it
// requires Go 1.21, while the legacy Windows 7 build is compiled with Go 1.20.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Level is the severity of a log entry. Higher values are more severe.
type Level int

// Log levels, from the most to the least verbose.
const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
)

// String returns the upper-case name used in both outputs.
func (l Level) String() string {
	switch l {
	case LevelTrace:
		return "TRACE"
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return fmt.Sprintf("LEVEL(%d)", int(l))
	}
}

// Entry is the JSON structure written to the collection log.
type Entry struct {
	Time    string                 `json:"ts"`
	Level   string                 `json:"level"`
	Message string                 `json:"msg"`
	Fields  map[string]interface{} `json:"fields,omitempty"`
}

// Logger writes entries to the console and, optionally, to a JSON log file.
// All methods are safe for concurrent use by multiple goroutines.
type Logger struct {
	mu           sync.Mutex
	console      io.Writer
	consoleLevel Level
	file         io.Writer
	fileLevel    Level
	now          func() time.Time // injectable clock, used by tests
}

// New creates a logger printing entries >= consoleLevel to console.
// A nil console disables console output (used by the GUI, which renders log
// entries itself through a custom writer).
func New(console io.Writer, consoleLevel Level) *Logger {
	return &Logger{
		console:      console,
		consoleLevel: consoleLevel,
		fileLevel:    LevelDebug,
		now:          time.Now,
	}
}

// AttachFile starts mirroring entries to w as JSON Lines. The file level is
// Debug, or Trace when the console level is Trace, so the evidence log is
// never less detailed than what the operator saw on screen.
func (l *Logger) AttachFile(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.file = w
	l.fileLevel = LevelDebug
	if l.consoleLevel < l.fileLevel {
		l.fileLevel = l.consoleLevel
	}
}

// Trace logs at LevelTrace. kv is an alternating list of keys and values.
func (l *Logger) Trace(msg string, kv ...interface{}) { l.log(LevelTrace, msg, kv) }

// Debug logs at LevelDebug.
func (l *Logger) Debug(msg string, kv ...interface{}) { l.log(LevelDebug, msg, kv) }

// Info logs at LevelInfo.
func (l *Logger) Info(msg string, kv ...interface{}) { l.log(LevelInfo, msg, kv) }

// Warn logs at LevelWarn.
func (l *Logger) Warn(msg string, kv ...interface{}) { l.log(LevelWarn, msg, kv) }

// Error logs at LevelError.
func (l *Logger) Error(msg string, kv ...interface{}) { l.log(LevelError, msg, kv) }

// log formats and dispatches one entry to the enabled sinks.
func (l *Logger) log(level Level, msg string, kv []interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	toConsole := l.console != nil && level >= l.consoleLevel
	toFile := l.file != nil && level >= l.fileLevel
	if !toConsole && !toFile {
		return
	}

	ts := l.now().UTC()
	fields := pairs(kv)

	if toConsole {
		// Console format: "11:23:10 INFO  message key=value key2=value2".
		var b strings.Builder
		fmt.Fprintf(&b, "%s %-5s %s", ts.Format("15:04:05"), level, msg)
		for _, k := range sortedKeys(fields) {
			fmt.Fprintf(&b, " %s=%v", k, fields[k])
		}
		b.WriteByte('\n')
		// Console write errors are deliberately ignored: losing a console line
		// must never abort an acquisition.
		_, _ = io.WriteString(l.console, b.String())
	}

	if toFile {
		e := Entry{
			Time:    ts.Format(time.RFC3339Nano),
			Level:   level.String(),
			Message: msg,
			Fields:  fields,
		}
		data, err := json.Marshal(e)
		if err != nil {
			// A value that cannot be marshalled is stored as its string form.
			for k, v := range e.Fields {
				e.Fields[k] = fmt.Sprint(v)
			}
			data, _ = json.Marshal(e)
		}
		_, _ = l.file.Write(append(data, '\n'))
	}
}

// pairs converts an alternating key/value slice into a map. A trailing key
// without value is kept under "!BADKEY" so that no information is lost.
func pairs(kv []interface{}) map[string]interface{} {
	if len(kv) == 0 {
		return nil
	}
	m := make(map[string]interface{}, len(kv)/2+1)
	for i := 0; i < len(kv); i += 2 {
		key := fmt.Sprint(kv[i])
		if i+1 >= len(kv) {
			m["!BADKEY"] = key
			break
		}
		v := kv[i+1]
		if err, ok := v.(error); ok {
			v = err.Error() // errors marshal to {} otherwise
		}
		m[key] = v
	}
	return m
}

// sortedKeys returns the map keys in lexical order for stable console output.
func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
