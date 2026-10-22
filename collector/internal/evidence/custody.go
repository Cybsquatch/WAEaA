package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
)

// Record captures all forensic provenance data for an acquisition.
type Record struct {
	CaseID             string   `json:"case_id"`
	Examiner           string   `json:"examiner"`
	Notes              string   `json:"notes,omitempty"`
	Hostname           string   `json:"hostname"`
	OS                 string   `json:"os"`
	Platform           string   `json:"platform"`
	Architecture       string   `json:"architecture"`
	IPAddresses        []string `json:"ip_addresses"`
	MACAddresses       []string `json:"mac_addresses"`
	CollectorVersion   string   `json:"collector_version"`
	CollectorHash      string   `json:"collector_hash"`
	CollectionStartUTC string   `json:"collection_start_utc"`
	CollectionEndUTC   string   `json:"collection_end_utc"`
	DurationSeconds    float64  `json:"duration_seconds"`
	TotalItems         int      `json:"total_items"`
	TotalBytes         int64    `json:"total_bytes"`
	DeduplicatedItems  int      `json:"deduplicated_items"`
	ArchiveName        string   `json:"archive_name"`
	ArchiveSHA256      string   `json:"archive_sha256"`
	RulesExecuted      []string `json:"rules_executed"`
	Authorized         bool     `json:"authorized"`
}

// WriteJSON writes the Chain of Custody record as indented JSON.
func (r *Record) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WAEaA Forensic Chain of Custody - {{ .CaseID }}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 2rem; background: #f8fafc; color: #0f172a; }
  .card { max-width: 900px; margin: 0 auto; background: #fff; border-radius: 8px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); padding: 2rem; border-top: 6px solid #2563eb; }
  h1 { margin-top: 0; font-size: 1.5rem; color: #1e293b; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 1rem; }
  .badge { font-size: 0.8rem; background: #dcfce7; color: #166534; padding: 0.25rem 0.6rem; border-radius: 9999px; font-weight: 600; text-transform: uppercase; }
  .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1.25rem; margin-top: 1.5rem; }
  .full { grid-column: span 2; }
  .field { background: #f1f5f9; padding: 0.75rem 1rem; border-radius: 6px; }
  .label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; font-weight: 600; margin-bottom: 0.25rem; }
  .value { font-size: 0.95rem; font-weight: 500; word-break: break-all; }
  .hash { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.85rem; color: #0f172a; }
  .footer { margin-top: 2rem; text-align: center; font-size: 0.8rem; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 1rem; }
</style>
</head>
<body>
<div class="card">
  <h1>
    <span>WAEaA Forensic Chain of Custody</span>
    {{ if .Authorized }}<span class="badge">Authorised Acquisition</span>{{ end }}
  </h1>

  <div class="grid">
    <div class="field"><div class="label">Case Identifier</div><div class="value">{{ if .CaseID }}{{ .CaseID }}{{ else }}N/A{{ end }}</div></div>
    <div class="field"><div class="label">Examiner</div><div class="value">{{ if .Examiner }}{{ .Examiner }}{{ else }}N/A{{ end }}</div></div>
    
    <div class="field"><div class="label">Target Hostname</div><div class="value">{{ .Hostname }}</div></div>
    <div class="field"><div class="label">Target OS / Architecture</div><div class="value">{{ .OS }} ({{ .Platform }}) / {{ .Architecture }}</div></div>

    <div class="field"><div class="label">Collection Start (UTC)</div><div class="value">{{ .CollectionStartUTC }}</div></div>
    <div class="field"><div class="label">Collection End (UTC)</div><div class="value">{{ .CollectionEndUTC }} ({{ printf "%.2f" .DurationSeconds }}s)</div></div>

    <div class="field"><div class="label">Total Artefacts Acquired</div><div class="value">{{ .TotalItems }} files ({{ .DeduplicatedItems }} deduplicated)</div></div>
    <div class="field"><div class="label">Total Raw Volume</div><div class="value">{{ .TotalBytes }} bytes</div></div>

    <div class="field full"><div class="label">Rules Executed</div><div class="value">{{ range $i, $r := .RulesExecuted }}{{ if $i }}, {{ end }}{{ $r }}{{ end }}</div></div>

    <div class="field full"><div class="label">Evidence Archive</div><div class="value">{{ .ArchiveName }}</div></div>
    <div class="field full"><div class="label">Archive SHA-256 Hash</div><div class="value hash">{{ .ArchiveSHA256 }}</div></div>

    <div class="field full"><div class="label">Collector Tool Version & SHA-256</div><div class="value hash">{{ .CollectorVersion }}<br>{{ .CollectorHash }}</div></div>

    {{ if .Notes }}
    <div class="field full"><div class="label">Examiner Notes</div><div class="value">{{ .Notes }}</div></div>
    {{ end }}
  </div>

  <div class="footer">
    Acquired by WAEaA - Proprietary Forensic Toolkit. Evidence integrity sealed with SHA-256.
  </div>
</div>
</body>
</html>
`

// GenerateHTML builds a self-contained HTML page representing the chain of custody.
func (r *Record) GenerateHTML() ([]byte, error) {
	tmpl, err := template.New("custody").Parse(htmlTemplate)
	if err != nil {
		return nil, fmt.Errorf("evidence: template parse error: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, r); err != nil {
		return nil, fmt.Errorf("evidence: template execute error: %w", err)
	}
	return buf.Bytes(), nil
}
