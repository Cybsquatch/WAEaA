package evidence

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
)

// TargetStatus describes the extraction outcome for a forensic target.
type TargetStatus string

const (
	StatusAcquired     TargetStatus = "ACQUIRED"
	StatusNotFound     TargetStatus = "NOT_FOUND"
	StatusAccessDenied TargetStatus = "ACCESS_DENIED"
	StatusCorrupted    TargetStatus = "CORRUPTED"
	StatusEmpty        TargetStatus = "EMPTY"
	StatusError        TargetStatus = "ERROR"
)

// TargetRecord tracks the extraction outcome of a target definition on a specific source.
type TargetRecord struct {
	RuleID        string
	Comment       string
	Source        string
	Path          string
	Mask          string
	Status        TargetStatus
	FilesAcquired int
	BytesAcquired int64
	Details       string
}

// FileErrorRecord tracks files that could not be read during acquisition.
type FileErrorRecord struct {
	Path   string
	RuleID string
	Error  string
}

// ResultsTracker collects and organizes acquisition results for reporting.
type ResultsTracker struct {
	mu         sync.Mutex
	targets    []TargetRecord
	fileErrors []FileErrorRecord
}

// NewResultsTracker instantiates a thread-safe tracker.
func NewResultsTracker() *ResultsTracker {
	return &ResultsTracker{}
}

// RecordTarget records the outcome of a target evaluation.
func (rt *ResultsTracker) RecordTarget(tr TargetRecord) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.targets = append(rt.targets, tr)
}

// RecordFileError records a read error for an individual file.
func (rt *ResultsTracker) RecordFileError(path, ruleID string, err error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	rt.fileErrors = append(rt.fileErrors, FileErrorRecord{
		Path:   path,
		RuleID: ruleID,
		Error:  msg,
	})
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// FormatText generates a human-readable results.txt report.
func (rt *ResultsTracker) FormatText(rec *Record, sources []string) []byte {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	var buf bytes.Buffer
	sep80 := strings.Repeat("=", 80)
	sepLine := strings.Repeat("-", 80)

	buf.WriteString(sep80 + "\n")
	buf.WriteString("                    WAEaA FORENSIC EXTRACTION RESULTS\n")
	buf.WriteString(sep80 + "\n\n")

	buf.WriteString(fmt.Sprintf("%-24s %s\n", "Case ID:", rec.CaseID))
	buf.WriteString(fmt.Sprintf("%-24s %s\n", "Examiner:", rec.Examiner))
	if rec.Notes != "" {
		buf.WriteString(fmt.Sprintf("%-24s %s\n", "Notes:", rec.Notes))
	}
	buf.WriteString(fmt.Sprintf("%-24s %s\n", "Hostname:", rec.Hostname))
	buf.WriteString(fmt.Sprintf("%-24s %s (%s)\n", "Platform:", rec.Platform, rec.Architecture))
	buf.WriteString(fmt.Sprintf("%-24s %s\n", "Extraction Start UTC:", rec.CollectionStartUTC))
	buf.WriteString(fmt.Sprintf("%-24s %s\n", "Extraction End UTC:", rec.CollectionEndUTC))
	buf.WriteString(fmt.Sprintf("%-24s %.2f seconds\n", "Duration:", rec.DurationSeconds))
	buf.WriteString(fmt.Sprintf("%-24s %s\n", "Target Sources:", strings.Join(sources, ", ")))
	buf.WriteString(fmt.Sprintf("%-24s %s\n", "Archive Name:", rec.ArchiveName))
	if rec.ArchiveSHA256 != "" {
		buf.WriteString(fmt.Sprintf("%-24s %s\n", "Archive SHA-256:", rec.ArchiveSHA256))
	}
	buf.WriteString("\n")

	// Calculate counts
	var acquiredCount, skippedCount int
	for _, t := range rt.targets {
		if t.Status == StatusAcquired {
			acquiredCount++
		} else {
			skippedCount++
		}
	}

	buf.WriteString(sepLine + "\n")
	buf.WriteString("EXECUTIVE SUMMARY\n")
	buf.WriteString(sepLine + "\n")
	buf.WriteString(fmt.Sprintf("%-34s %d\n", "Rules Executed:", len(rec.RulesExecuted)))
	buf.WriteString(fmt.Sprintf("%-34s %d (%s)\n", "Total Evidence Files Acquired:", rec.TotalItems, formatBytes(rec.TotalBytes)))
	buf.WriteString(fmt.Sprintf("%-34s %d\n", "Deduplicated Items:", rec.DeduplicatedItems))
	buf.WriteString(fmt.Sprintf("%-34s %d\n", "Target Targets Acquired:", acquiredCount))
	buf.WriteString(fmt.Sprintf("%-34s %d\n", "Target Targets Not Extracted:", skippedCount))
	buf.WriteString(fmt.Sprintf("%-34s %d\n", "File Read Errors Encountered:", len(rt.fileErrors)))
	buf.WriteString("\n")

	// Section 1: Successfully extracted targets
	buf.WriteString(sep80 + "\n")
	buf.WriteString("1. ARTEFACTS & TARGETS SUCCESSFULLY EXTRACTED [ACQUIRED]\n")
	buf.WriteString(sep80 + "\n")

	if acquiredCount == 0 {
		buf.WriteString("No artefacts were successfully acquired.\n\n")
	} else {
		for _, t := range rt.targets {
			if t.Status != StatusAcquired {
				continue
			}
			comment := t.Comment
			if comment == "" {
				comment = t.RuleID
			}
			buf.WriteString(fmt.Sprintf("[OK] Rule: %s (%s)\n", t.RuleID, comment))
			buf.WriteString(fmt.Sprintf("     Source Path: %s | Mask: %s\n", t.Path, t.Mask))
			buf.WriteString(fmt.Sprintf("     Acquired:    %d files (%s)\n", t.FilesAcquired, formatBytes(t.BytesAcquired)))
			if t.Details != "" {
				buf.WriteString(fmt.Sprintf("     Note:        %s\n", t.Details))
			}
			buf.WriteString("\n")
		}
	}

	// Section 2: Targets not found or inaccessible
	buf.WriteString(sep80 + "\n")
	buf.WriteString("2. TARGETS NOT FOUND OR INACCESSIBLE [NOT EXTRACTED]\n")
	buf.WriteString(sep80 + "\n")

	if skippedCount == 0 {
		buf.WriteString("All evaluated targets were present and successfully extracted.\n\n")
	} else {
		for _, t := range rt.targets {
			if t.Status == StatusAcquired {
				continue
			}
			comment := t.Comment
			if comment == "" {
				comment = t.RuleID
			}
			statusLabel := string(t.Status)
			switch t.Status {
			case StatusNotFound:
				statusLabel = "NOT FOUND"
			case StatusAccessDenied:
				statusLabel = "ACCESS DENIED"
			case StatusCorrupted:
				statusLabel = "FILE CORRUPTED / UNREADABLE"
			case StatusEmpty:
				statusLabel = "EMPTY DIRECTORY"
			case StatusError:
				statusLabel = "ERROR"
			}

			buf.WriteString(fmt.Sprintf("[%s] Rule: %s (%s)\n", statusLabel, t.RuleID, comment))
			buf.WriteString(fmt.Sprintf("  Target Path:   %s [Mask: %s]\n", t.Path, t.Mask))
			buf.WriteString(fmt.Sprintf("  Source Drive:  %s\n", t.Source))
			if t.Details != "" {
				buf.WriteString(fmt.Sprintf("  Reason/Error:  %s\n", t.Details))
			}
			buf.WriteString("\n")
		}
	}

	// Section 3: File read errors
	buf.WriteString(sep80 + "\n")
	buf.WriteString("3. INDIVIDUAL FILE READ ERRORS ENCOUNTERED\n")
	buf.WriteString(sep80 + "\n")

	if len(rt.fileErrors) == 0 {
		buf.WriteString("No file read or hashing errors were encountered during acquisition.\n")
	} else {
		for _, fe := range rt.fileErrors {
			buf.WriteString(fmt.Sprintf("[READ ERROR] %s\n", fe.Path))
			if fe.RuleID != "" {
				buf.WriteString(fmt.Sprintf("  Rule:  %s\n", fe.RuleID))
			}
			buf.WriteString(fmt.Sprintf("  Error: %s\n\n", fe.Error))
		}
	}

	buf.WriteString(sep80 + "\n")
	buf.WriteString("END OF WAEaA RESULTS REPORT\n")
	buf.WriteString(sep80 + "\n")

	return buf.Bytes()
}
