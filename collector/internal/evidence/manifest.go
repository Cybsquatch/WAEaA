// Package evidence implements forensic record-keeping: cryptographic hashing,
// file manifest generation (CSV and JSON) and chain-of-custody documentation
// (JSON and interactive HTML report).
package evidence

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"sync"
)

// Item represents a single forensic file collected or deduplicated.
type Item struct {
	SourcePath          string `json:"source_path"`
	ArchivePath         string `json:"archive_path"`
	Size                int64  `json:"size"`
	SHA256              string `json:"sha256"`
	SHA1                string `json:"sha1,omitempty"`
	MD5                 string `json:"md5,omitempty"`
	CreatedUTC          string `json:"created_utc"`
	ModifiedUTC         string `json:"modified_utc"`
	AccessedUTC         string `json:"accessed_utc"`
	AcquiredUTC         string `json:"acquired_utc"`
	RuleID              string `json:"rule_id"`
	Deduplicated        bool   `json:"deduplicated"`
	OriginalArchivePath string `json:"original_archive_path,omitempty"`
}

// Manifest collects items acquired during the forensic run.
type Manifest struct {
	mu    sync.RWMutex
	items []Item
}

// NewManifest creates an empty Manifest.
func NewManifest() *Manifest {
	return &Manifest{
		items: make([]Item, 0, 256),
	}
}

// Add appends an item to the manifest in a thread-safe manner.
func (m *Manifest) Add(item Item) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, item)
}

// Items returns a copy of all recorded items.
func (m *Manifest) Items() []Item {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]Item, len(m.items))
	copy(copied, m.items)
	return copied
}

// Count returns the number of items.
func (m *Manifest) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.items)
}

// TotalBytes returns the total size of items.
func (m *Manifest) TotalBytes() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var total int64
	for _, it := range m.items {
		total += it.Size
	}
	return total
}

// WriteCSV exports all manifest items in standard RFC 4180 CSV format.
func (m *Manifest) WriteCSV(w io.Writer) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{
		"source_path",
		"archive_path",
		"size",
		"sha256",
		"sha1",
		"md5",
		"created_utc",
		"modified_utc",
		"accessed_utc",
		"acquired_utc",
		"rule_id",
		"deduplicated",
		"original_archive_path",
	}

	if err := writer.Write(header); err != nil {
		return err
	}

	for _, it := range m.items {
		row := []string{
			it.SourcePath,
			it.ArchivePath,
			strconv.FormatInt(it.Size, 10),
			it.SHA256,
			it.SHA1,
			it.MD5,
			it.CreatedUTC,
			it.ModifiedUTC,
			it.AccessedUTC,
			it.AcquiredUTC,
			it.RuleID,
			strconv.FormatBool(it.Deduplicated),
			it.OriginalArchivePath,
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return writer.Error()
}

// WriteJSON exports all manifest items in JSON format.
func (m *Manifest) WriteJSON(w io.Writer) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(m.items); err != nil {
		return fmt.Errorf("evidence: json encode error: %w", err)
	}
	return nil
}
