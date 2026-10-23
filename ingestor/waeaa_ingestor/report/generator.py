"""Self-contained, offline HTML report generator for incident response findings.

Produces an interactive, single-file HTML report with embedded responsive styles,
composite multi-criteria filtering, row flagging and targeted CSV/JSON exports,
MITRE ATT&CK matrix, timeline navigation, and RDP bitmap cache screenshot reconstruction gallery
with zero external CDN dependencies.
"""

from __future__ import annotations

import base64
import html
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from waeaa_ingestor.detection.models import Finding
    from waeaa_ingestor.parsers.base import ParsedRecord


REPORT_CSS = """
:root {
  --bg-primary: #0d1117;
  --bg-secondary: #161b22;
  --bg-card: #21262d;
  --border-color: #30363d;
  --text-main: #c9d1d9;
  --text-muted: #8b949e;
  --text-bright: #f0f6fc;
  --accent-blue: #58a6ff;
  --accent-green: #3fb950;
  --accent-orange: #d29922;
  --accent-red: #f85149;
  --accent-purple: #bc8cff;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background-color: var(--bg-primary);
  color: var(--text-main);
  line-height: 1.5;
  padding: 0 0 40px 0;
}

header {
  background: var(--bg-secondary);
  border-bottom: 1px solid var(--border-color);
  padding: 20px 32px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  position: sticky;
  top: 0;
  z-index: 100;
}
header h1 { color: var(--text-bright); font-size: 20px; font-weight: 600; letter-spacing: 0.5px; }
header .meta { font-size: 13px; color: var(--text-muted); text-align: right; }

.header-actions { display: flex; gap: 10px; align-items: center; }

.container { max-width: 1480px; margin: 24px auto; padding: 0 24px; }

/* Metrics Cards */
.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.metric-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px 20px;
}
.metric-card .title { font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }
.metric-card .value { font-size: 26px; font-weight: 700; color: var(--text-bright); margin-top: 4px; }
.metric-card.critical .value { color: var(--accent-red); }
.metric-card.high .value { color: var(--accent-orange); }

/* Tabs Navigation */
.tabs {
  display: flex;
  gap: 8px;
  border-bottom: 1px solid var(--border-color);
  margin-bottom: 20px;
}
.tab-btn {
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--text-muted);
  font-size: 14px;
  font-weight: 600;
  padding: 10px 16px;
  cursor: pointer;
  transition: all 0.2s ease;
}
.tab-btn:hover { color: var(--text-bright); }
.tab-btn.active { color: var(--accent-blue); border-bottom-color: var(--accent-blue); }

.tab-content { display: none; }
.tab-content.active { display: block; }

/* Filter & Action Toolbars */
.filter-toolbar {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 16px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.filter-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
}
.filter-input {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  color: var(--text-bright);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
  flex: 1;
  min-width: 220px;
}
.filter-select {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  color: var(--text-bright);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
  min-width: 160px;
}
.filter-checkboxes {
  display: flex;
  gap: 12px;
  align-items: center;
  font-size: 13px;
  color: var(--text-main);
}
.filter-checkboxes label {
  display: flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
}

.action-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  padding: 10px 14px;
  margin-bottom: 14px;
  font-size: 13px;
}
.action-buttons { display: flex; gap: 8px; align-items: center; }

.btn {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  color: var(--text-bright);
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.15s ease;
}
.btn:hover { background: var(--bg-card); border-color: var(--accent-blue); }
.btn-primary { background: #238636; border-color: rgba(240, 246, 252, 0.1); color: #fff; }
.btn-primary:hover { background: #2ea043; }

/* Table Styles */
.table-wrapper {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow-x: auto;
}
table { width: 100%; border-collapse: collapse; font-size: 13px; }
thead th {
  background: var(--bg-card);
  padding: 12px 14px;
  color: var(--text-bright);
  font-weight: 600;
  border-bottom: 1px solid var(--border-color);
  text-align: left;
}
tbody td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-color);
  color: var(--text-main);
}
tbody tr:hover { background: rgba(110, 118, 129, 0.08); }
tbody tr.selected { background: rgba(88, 166, 255, 0.12); }
tbody tr.detail-row { background: var(--bg-card); display: none; }
tbody tr.detail-row.open { display: table-row; }
.detail-box {
  padding: 14px;
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  color: #8b949e;
}

/* Badges */
.badge {
  display: inline-block;
  padding: 3px 8px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
}
.badge-critical { background: rgba(248, 81, 73, 0.18); color: var(--accent-red); border: 1px solid var(--accent-red); }
.badge-high { background: rgba(210, 153, 34, 0.18); color: var(--accent-orange); border: 1px solid var(--accent-orange); }
.badge-medium { background: rgba(88, 166, 255, 0.18); color: var(--accent-blue); border: 1px solid var(--accent-blue); }
.badge-low { background: rgba(63, 185, 80, 0.18); color: var(--accent-green); border: 1px solid var(--accent-green); }
.badge-info { background: rgba(188, 140, 255, 0.18); color: var(--accent-purple); border: 1px solid var(--accent-purple); }

/* MITRE Matrix */
.mitre-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 16px;
}
.mitre-tactic-col {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
}
.mitre-tactic-title {
  font-size: 13px;
  font-weight: 700;
  color: var(--accent-blue);
  text-transform: uppercase;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 8px;
  margin-bottom: 12px;
}
.mitre-card {
  background: var(--bg-card);
  border-left: 3px solid var(--accent-blue);
  border-radius: 4px;
  padding: 10px 12px;
  margin-bottom: 10px;
  cursor: pointer;
  transition: transform 0.1s ease;
}
.mitre-card:hover { transform: translateX(3px); }
.mitre-card.crit { border-left-color: var(--accent-red); }
.mitre-card.high { border-left-color: var(--accent-orange); }
.mitre-card .tech-id { font-size: 11px; font-weight: 700; color: var(--text-muted); }
.mitre-card .tech-name { font-size: 13px; font-weight: 600; color: var(--text-bright); margin-top: 2px; }

/* RDP Gallery */
.rdp-container {
  display: flex;
  flex-direction: column;
  gap: 24px;
}
.rdp-screen-box {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 20px;
}
.rdp-screen-box h3 { color: var(--text-bright); margin-bottom: 12px; font-size: 16px; font-weight: 600; }
.rdp-canvas-view {
  background: #000;
  border: 1px solid var(--border-color);
  border-radius: 4px;
  overflow: auto;
  max-height: 600px;
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 10px;
}
.rdp-canvas-view img {
  max-width: 100%;
  height: auto;
  image-rendering: pixelated;
  border: 1px solid #333;
}
.rdp-tile-strip {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(68px, 1fr));
  gap: 8px;
  max-height: 300px;
  overflow-y: auto;
  background: var(--bg-card);
  padding: 12px;
  border-radius: 6px;
  border: 1px solid var(--border-color);
}
.rdp-tile-item {
  width: 64px;
  height: 64px;
  border: 1px solid var(--border-color);
  border-radius: 4px;
  overflow: hidden;
  background: #000;
  display: flex;
  align-items: center;
  justify-content: center;
}
.rdp-tile-item img { width: 64px; height: 64px; image-rendering: pixelated; }

@media print {
  body { background: #fff; color: #000; }
  header, .filter-toolbar, .action-bar, .tabs { display: none; }
  .tab-content { display: block !important; }
  .table-wrapper { border: none; }
  thead th, tbody td { border: 1px solid #ccc; color: #000; }
}
"""

REPORT_JS = """
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  const btn = document.getElementById('btn-' + tabId);
  const tab = document.getElementById('tab-' + tabId);
  if (btn) btn.classList.add('active');
  if (tab) tab.classList.add('active');
}

function toggleDetail(rowId) {
  const row = document.getElementById(rowId);
  if (row) row.classList.toggle('open');
}

/* Composite Findings Filter */
function applyFindingsFilters() {
  const q = document.getElementById('search-findings').value.toLowerCase();
  const selectedTactic = document.getElementById('filter-findings-tactic').value;
  
  const checkedSevs = Array.from(document.querySelectorAll('.chk-sev:checked')).map(cb => cb.value);

  const rows = document.querySelectorAll('#tbody-findings tr.data-row');
  let visibleCount = 0;

  rows.forEach(r => {
    const text = r.innerText.toLowerCase();
    const sev = r.dataset.sev;
    const tactic = r.dataset.tactic || '';

    const matchesQuery = !q || text.includes(q);
    const matchesSev = checkedSevs.includes(sev);
    const matchesTactic = (selectedTactic === 'ALL' || tactic === selectedTactic);

    const visible = matchesQuery && matchesSev && matchesTactic;
    r.style.display = visible ? '' : 'none';
    if (visible) visibleCount++;

    const detailRow = document.getElementById(r.id + '-detail');
    if (detailRow && !visible) {
      detailRow.classList.remove('open');
    }
  });

  const countBadge = document.getElementById('findings-visible-count');
  if (countBadge) countBadge.innerText = visibleCount;
}

/* Timeline Filter */
function applyTimelineFilters() {
  const q = document.getElementById('search-timeline').value.toLowerCase();
  const selectedType = document.getElementById('filter-timeline-type').value;

  const rows = document.querySelectorAll('#tbody-timeline tr.data-row');
  let visibleCount = 0;

  rows.forEach(r => {
    const text = r.innerText.toLowerCase();
    const type = r.dataset.type || '';

    const matchesQuery = !q || text.includes(q);
    const matchesType = (selectedType === 'ALL' || type === selectedType);

    const visible = matchesQuery && matchesType;
    r.style.display = visible ? '' : 'none';
    if (visible) visibleCount++;
  });

  const countBadge = document.getElementById('timeline-visible-count');
  if (countBadge) countBadge.innerText = visibleCount;
}

/* Row Flagging & Targeted Export */
function toggleSelectAll(masterCb, tableId) {
  const isChecked = masterCb.checked;
  const checkboxes = document.querySelectorAll('#' + tableId + ' tbody .row-cb');
  checkboxes.forEach(cb => {
    const tr = cb.closest('tr');
    if (tr && tr.style.display !== 'none') {
      cb.checked = isChecked;
      if (isChecked) tr.classList.add('selected');
      else tr.classList.remove('selected');
    }
  });
  updateSelectionCount(tableId);
}

function onRowChecked(cb, tableId) {
  const tr = cb.closest('tr');
  if (tr) {
    if (cb.checked) tr.classList.add('selected');
    else tr.classList.remove('selected');
  }
  updateSelectionCount(tableId);
}

function updateSelectionCount(tableId) {
  const checked = document.querySelectorAll('#' + tableId + ' tbody .row-cb:checked').length;
  const badge = document.getElementById(tableId + '-selected-count');
  if (badge) badge.innerText = checked;
}

function exportSelectedCsv(tableId, filename) {
  const selectedCbs = document.querySelectorAll('#' + tableId + ' tbody .row-cb:checked');
  if (selectedCbs.length === 0) {
    alert('Please check at least one row checkbox to export selected items.');
    return;
  }

  const theadCols = document.querySelectorAll('#' + tableId + ' thead th');
  let headerData = [];
  theadCols.forEach((th, idx) => {
    if (idx > 0) headerData.push('"' + th.innerText.replace(/"/g, '""').trim() + '"');
  });

  let csv = [headerData.join(',')];
  selectedCbs.forEach(cb => {
    const tr = cb.closest('tr');
    if (!tr) return;
    const cols = tr.querySelectorAll('td');
    let rowData = [];
    cols.forEach((c, idx) => {
      if (idx > 0) {
        let text = c.innerText.replace(/"/g, '""').trim();
        rowData.push('"' + text + '"');
      }
    });
    if (rowData.length > 0) csv.push(rowData.join(','));
  });

  downloadBlob(csv.join('\\n'), filename, 'text/csv;charset=utf-8;');
}

function exportSelectedJson(tableId, filename) {
  const selectedCbs = document.querySelectorAll('#' + tableId + ' tbody .row-cb:checked');
  if (selectedCbs.length === 0) {
    alert('Please check at least one row checkbox to export selected items.');
    return;
  }

  const theadCols = Array.from(document.querySelectorAll('#' + tableId + ' thead th'))
    .slice(1)
    .map(th => th.innerText.trim().toLowerCase().replace(/[^a-z0-9]/g, '_'));

  let records = [];
  selectedCbs.forEach(cb => {
    const tr = cb.closest('tr');
    if (!tr) return;
    const cols = Array.from(tr.querySelectorAll('td')).slice(1);
    let item = {};
    cols.forEach((c, idx) => {
      const key = theadCols[idx] || ('col_' + idx);
      item[key] = c.innerText.trim();
    });
    records.push(item);
  });

  downloadBlob(JSON.stringify(records, null, 2), filename, 'application/json');
}

function copySelectedToClipboard(tableId) {
  const selectedCbs = document.querySelectorAll('#' + tableId + ' tbody .row-cb:checked');
  if (selectedCbs.length === 0) {
    alert('Please check at least one row checkbox to copy.');
    return;
  }

  let rowsText = [];
  selectedCbs.forEach(cb => {
    const tr = cb.closest('tr');
    if (!tr) return;
    const cols = Array.from(tr.querySelectorAll('td')).slice(1);
    rowsText.push(cols.map(c => c.innerText.trim()).join(' | '));
  });

  navigator.clipboard.writeText(rowsText.join('\\n')).then(() => {
    alert('Copied ' + selectedCbs.length + ' selected rows to clipboard!');
  });
}

function filterByMitreTactic(tacticName) {
  switchTab('findings');
  document.getElementById('filter-findings-tactic').value = tacticName;
  applyFindingsFilters();
}

function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}
"""


@dataclass
class ReportData:
    """Consolidated forensic dataset used to populate the report."""

    hostname: str
    target_os: str
    analysis_time_utc: str
    custody: dict[str, Any] | None
    findings: list[Finding]
    timeline_records: list[ParsedRecord]
    parsed_by_type: dict[str, int]
    total_files_inspected: int
    rdp_tiles_count: int = 0
    rdp_screens: list[dict[str, Any]] = field(default_factory=list)
    sample_tiles_b64: list[str] = field(default_factory=list)


class HtmlReportGenerator:
    """Generates standalone single-file offline HTML reports."""

    def __init__(self, data: ReportData, language: str = "en") -> None:
        """Initialize generator with analysis dataset and UI language."""
        self.data = data
        self.language = language

    def render(self) -> str:
        """Render complete HTML string."""
        crit_count = sum(1 for f in self.data.findings if f.severity.value == "Critical")
        high_count = sum(1 for f in self.data.findings if f.severity.value == "High")
        med_count = sum(1 for f in self.data.findings if f.severity.value == "Medium")
        total_findings = len(self.data.findings)
        total_timeline = len(self.data.timeline_records)

        examiner = (
            str(self.data.custody.get("examiner", "Forensic Analyst"))
            if self.data.custody
            else "Forensic Analyst"
        )
        case_id = (
            str(self.data.custody.get("case_id", "N/A"))
            if self.data.custody
            else "N/A"
        )

        out: list[str] = []
        out.append("<!DOCTYPE html>")
        out.append(f'<html lang="{self.language}">')
        out.append("<head>")
        out.append('  <meta charset="utf-8">')
        out.append('  <meta name="viewport" content="width=device-width, initial-scale=1">')
        out.append(f"  <title>WAEaA Forensic Analysis Report - {html.escape(self.data.hostname)}</title>")
        out.append(f"  <style>{REPORT_CSS}</style>")
        out.append("</head>")
        out.append("<body>")

        # Header
        out.append("  <header>")
        out.append("    <div>")
        out.append(f"      <h1>WAEaA Forensic Analysis Report &mdash; {html.escape(self.data.hostname)}</h1>")
        out.append(f"      <div class='meta' style='text-align: left; margin-top: 4px;'>Case: <b>{html.escape(case_id)}</b> | Target: <b>{html.escape(self.data.target_os)}</b> | Examiner: <b>{html.escape(examiner)}</b> | Time: {html.escape(self.data.analysis_time_utc)}</div>")
        out.append("    </div>")
        out.append("    <div class='header-actions'>")
        out.append("      <button class='btn' onclick='window.print()'>Print / PDF</button>")
        out.append("    </div>")
        out.append("  </header>")

        out.append("  <div class='container'>")

        # KPI Metrics Cards
        out.append("    <div class='metrics-grid'>")
        out.append("      <div class='metric-card critical'>")
        out.append("        <div class='title'>Critical Alerts</div>")
        out.append(f"        <div class='value'>{crit_count}</div>")
        out.append("      </div>")
        out.append("      <div class='metric-card high'>")
        out.append("        <div class='title'>High Severity</div>")
        out.append(f"        <div class='value'>{high_count}</div>")
        out.append("      </div>")
        out.append("      <div class='metric-card'>")
        out.append("        <div class='title'>Total Findings</div>")
        out.append(f"        <div class='value'>{total_findings}</div>")
        out.append("      </div>")
        out.append("      <div class='metric-card'>")
        out.append("        <div class='title'>Super-Timeline Events</div>")
        out.append(f"        <div class='value'>{total_timeline:,}</div>")
        out.append("      </div>")
        out.append("      <div class='metric-card'>")
        out.append("        <div class='title'>Artefact Files Inspected</div>")
        out.append(f"        <div class='value'>{self.data.total_files_inspected:,}</div>")
        out.append("      </div>")
        if self.data.rdp_tiles_count > 0:
            out.append("      <div class='metric-card'>")
            out.append("        <div class='title'>RDP Tiles Extracted</div>")
            out.append(f"        <div class='value' style='color: var(--accent-purple);'>{self.data.rdp_tiles_count:,}</div>")
            out.append("      </div>")
        out.append("    </div>")

        # Tabs Navigation
        out.append("    <div class='tabs'>")
        out.append("      <button id='btn-findings' class='tab-btn active' onclick=\"switchTab('findings')\">Findings & Alerts</button>")
        out.append("      <button id='btn-mitre' class='tab-btn' onclick=\"switchTab('mitre')\">MITRE ATT&CK Matrix</button>")
        out.append("      <button id='btn-timeline' class='tab-btn' onclick=\"switchTab('timeline')\">Super-Timeline</button>")
        out.append("      <button id='btn-rdp-cache' class='tab-btn' onclick=\"switchTab('rdp-cache')\">RDP Screenshots & Tiles</button>")
        out.append("      <button id='btn-custody' class='tab-btn' onclick=\"switchTab('custody')\">Chain of Custody</button>")
        out.append("    </div>")

        # Tab 1: Findings & Alerts
        out.append("    <div id='tab-findings' class='tab-content active'>")
        out.append("      <div class='filter-toolbar'>")
        out.append("        <div class='filter-row'>")
        out.append("          <input type='text' id='search-findings' class='filter-input' placeholder='Search findings by title, description, artefact, details...' onkeyup='applyFindingsFilters()'>")
        out.append("          <select id='filter-findings-tactic' class='filter-select' onchange='applyFindingsFilters()'>")
        out.append("            <option value='ALL'>All MITRE Tactics</option>")
        for tactic in ("Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Impact"):
            out.append(f"            <option value='{tactic}'>{tactic}</option>")
        out.append("          </select>")
        out.append("        </div>")
        out.append("        <div class='filter-row'>")
        out.append("          <div class='filter-checkboxes'>")
        out.append("            <span style='font-weight: 600; color: var(--text-muted);'>Severities:</span>")
        out.append("            <label><input type='checkbox' class='chk-sev' value='Critical' checked onchange='applyFindingsFilters()'> <span class='badge badge-critical'>Critical</span></label>")
        out.append("            <label><input type='checkbox' class='chk-sev' value='High' checked onchange='applyFindingsFilters()'> <span class='badge badge-high'>High</span></label>")
        out.append("            <label><input type='checkbox' class='chk-sev' value='Medium' checked onchange='applyFindingsFilters()'> <span class='badge badge-medium'>Medium</span></label>")
        out.append("            <label><input type='checkbox' class='chk-sev' value='Low' checked onchange='applyFindingsFilters()'> <span class='badge badge-low'>Low</span></label>")
        out.append("            <label><input type='checkbox' class='chk-sev' value='Info' checked onchange='applyFindingsFilters()'> <span class='badge badge-info'>Info</span></label>")
        out.append("          </div>")
        out.append("        </div>")
        out.append("      </div>")

        # Action Bar for Findings
        out.append("      <div class='action-bar'>")
        out.append("        <div>Showing <b id='findings-visible-count'>" + str(total_findings) + "</b> of <b>" + str(total_findings) + "</b> findings | Selected: <b id='table-findings-selected-count'>0</b></div>")
        out.append("        <div class='action-buttons'>")
        out.append("          <button class='btn' onclick=\"exportSelectedCsv('table-findings', 'findings_selected.csv')\">Export Selected (CSV)</button>")
        out.append("          <button class='btn' onclick=\"exportSelectedJson('table-findings', 'findings_selected.json')\">Export Selected (JSON)</button>")
        out.append("          <button class='btn' onclick=\"copySelectedToClipboard('table-findings')\">Copy Selected</button>")
        out.append("        </div>")
        out.append("      </div>")

        # Findings Table
        out.append("      <div class='table-wrapper'>")
        out.append("        <table id='table-findings'>")
        out.append("          <thead>")
        out.append("            <tr>")
        out.append("              <th style='width: 36px;'><input type='checkbox' onclick=\"toggleSelectAll(this, 'table-findings')\"></th>")
        out.append("              <th style='width: 100px;'>Severity</th>")
        out.append("              <th>Finding Title</th>")
        out.append("              <th style='width: 170px;'>Timestamp (UTC)</th>")
        out.append("              <th style='width: 180px;'>MITRE ATT&CK</th>")
        out.append("              <th>Source Artefact</th>")
        out.append("            </tr>")
        out.append("          </thead>")
        out.append("          <tbody id='tbody-findings'>")

        for idx, f in enumerate(self.data.findings):
            sev_class = f.severity.value.lower()
            row_id = f"finding-{idx}"
            tactic = f.mitre.tactic
            out.append(f"            <tr id='{row_id}' class='data-row' data-sev='{f.severity.value}' data-tactic='{html.escape(tactic)}' onclick=\"toggleDetail('{row_id}-detail')\" style='cursor: pointer;'>")
            out.append(f"              <td onclick='event.stopPropagation()'><input type='checkbox' class='row-cb' onchange=\"onRowChecked(this, 'table-findings')\"></td>")
            out.append(f"              <td><span class='badge badge-{sev_class}'>{f.severity.value}</span></td>")
            out.append(f"              <td><b>{html.escape(f.title)}</b><div style='font-size: 11px; color: var(--text-muted); margin-top: 2px;'>{html.escape(f.summary[:110])}</div></td>")
            out.append(f"              <td><code>{html.escape(f.timestamp_utc or 'N/A')}</code></td>")
            out.append(f"              <td><span style='color: var(--accent-blue); font-weight: 600;'>{html.escape(f.mitre.technique_id)}</span> <span style='font-size: 11px; color: var(--text-muted);'>({html.escape(f.mitre.tactic)})</span></td>")
            out.append(f"              <td><code>{html.escape(f.source_artefact)}</code></td>")
            out.append("            </tr>")
            # Detail expandable row
            details_json = json.dumps(f.details, indent=2) if f.details else "{}"
            out.append(f"            <tr id='{row_id}-detail' class='detail-row'>")
            out.append(f"              <td colspan='6'><div class='detail-box'><strong>Description:</strong> {html.escape(f.description)}\\n\\n<strong>Details:</strong>\\n{html.escape(details_json)}</div></td>")
            out.append("            </tr>")

        out.append("          </tbody>")
        out.append("        </table>")
        out.append("      </div>")
        out.append("    </div>")

        # Tab 2: MITRE ATT&CK Matrix
        out.append("    <div id='tab-mitre' class='tab-content'>")
        out.append("      <div class='mitre-grid'>")
        tactic_map: dict[str, list[Finding]] = {}
        for f in self.data.findings:
            t = f.mitre.tactic or "Unknown"
            tactic_map.setdefault(t, []).append(f)

        ordered_tactics = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Impact",
        ]
        for tactic in ordered_tactics:
            findings_for_tactic = tactic_map.get(tactic, [])
            out.append("        <div class='mitre-tactic-col'>")
            out.append(f"          <div class='mitre-tactic-title'>{tactic} ({len(findings_for_tactic)})</div>")
            if not findings_for_tactic:
                out.append("          <div style='font-size: 12px; color: var(--text-muted); font-style: italic;'>No alerts detected</div>")
            else:
                seen_techs = set()
                for f in findings_for_tactic:
                    tech_key = f"{f.mitre.technique_id}:{f.mitre.technique_name}"
                    if tech_key in seen_techs:
                        continue
                    seen_techs.add(tech_key)
                    c_class = "crit" if f.severity.value == "Critical" else ("high" if f.severity.value == "High" else "")
                    out.append(f"          <div class='mitre-card {c_class}' onclick=\"filterByMitreTactic('{tactic}')\" title='Click to filter findings'>")
                    out.append(f"            <div class='tech-id'>{html.escape(f.mitre.technique_id)}</div>")
                    out.append(f"            <div class='tech-name'>{html.escape(f.mitre.technique_name)}</div>")
                    out.append("          </div>")
            out.append("        </div>")
        out.append("      </div>")
        out.append("    </div>")

        # Tab 3: Super-Timeline
        out.append("    <div id='tab-timeline' class='tab-content'>")
        out.append("      <div class='filter-toolbar'>")
        out.append("        <div class='filter-row'>")
        out.append("          <input type='text' id='search-timeline' class='filter-input' placeholder='Search timeline by action, user, process, file, summary...' onkeyup='applyTimelineFilters()'>")
        out.append("          <select id='filter-timeline-type' class='filter-select' onchange='applyTimelineFilters()'>")
        out.append("            <option value='ALL'>All Artefact Types</option>")
        for t in sorted(self.data.parsed_by_type.keys()):
            out.append(f"            <option value='{t}'>{t} ({self.data.parsed_by_type[t]:,})</option>")
        out.append("          </select>")
        out.append("        </div>")
        out.append("      </div>")

        out.append("      <div class='action-bar'>")
        timeline_display_limit = min(5000, total_timeline)
        out.append(f"        <div>Showing first <b>{timeline_display_limit:,}</b> of <b>{total_timeline:,}</b> chronological events | Selected: <b id='table-timeline-selected-count'>0</b></div>")
        out.append("        <div class='action-buttons'>")
        out.append("          <button class='btn' onclick=\"exportSelectedCsv('table-timeline', 'timeline_selected.csv')\">Export Selected (CSV)</button>")
        out.append("          <button class='btn' onclick=\"exportSelectedJson('table-timeline', 'timeline_selected.json')\">Export Selected (JSON)</button>")
        out.append("          <button class='btn' onclick=\"copySelectedToClipboard('table-timeline')\">Copy Selected</button>")
        out.append("        </div>")
        out.append("      </div>")

        out.append("      <div class='table-wrapper'>")
        out.append("        <table id='table-timeline'>")
        out.append("          <thead>")
        out.append("            <tr>")
        out.append("              <th style='width: 36px;'><input type='checkbox' onclick=\"toggleSelectAll(this, 'table-timeline')\"></th>")
        out.append("              <th style='width: 170px;'>Timestamp (UTC)</th>")
        out.append("              <th style='width: 120px;'>Artefact Type</th>")
        out.append("              <th style='width: 140px;'>Action / Event</th>")
        out.append("              <th>Summary & Context</th>")
        out.append("              <th style='width: 140px;'>User</th>")
        out.append("            </tr>")
        out.append("          </thead>")
        out.append("          <tbody id='tbody-timeline'>")

        for idx, r in enumerate(self.data.timeline_records[:timeline_display_limit]):
            row_id = f"tl-{idx}"
            out.append(f"            <tr id='{row_id}' class='data-row' data-type='{html.escape(r.artefact_type)}'>")
            out.append(f"              <td><input type='checkbox' class='row-cb' onchange=\"onRowChecked(this, 'table-timeline')\"></td>")
            out.append(f"              <td><code>{html.escape(r.timestamp_utc or 'N/A')}</code></td>")
            out.append(f"              <td><span class='badge badge-medium'>{html.escape(r.artefact_type)}</span></td>")
            out.append(f"              <td><b>{html.escape(r.action)}</b></td>")
            out.append(f"              <td>{html.escape(r.summary)}</td>")
            out.append(f"              <td>{html.escape(r.user or '')}</td>")
            out.append("            </tr>")

        out.append("          </tbody>")
        out.append("        </table>")
        out.append("      </div>")
        out.append("    </div>")

        # Tab 4: RDP Screenshots & Tiles
        out.append("    <div id='tab-rdp-cache' class='tab-content'>")
        out.append("      <div class='rdp-container'>")
        if not self.data.rdp_screens and not self.data.sample_tiles_b64:
            out.append("        <div class='rdp-screen-box'>")
            out.append("          <h3>No RDP Cache Tiles Detected</h3>")
            out.append("          <p style='color: var(--text-muted); font-size: 13px;'>No .bmc or .bin bitmap cache files were found in this acquisition, or the remote desktop sessions did not utilize client-side caching.</p>")
            out.append("        </div>")
        else:
            for s in self.data.rdp_screens:
                s_name = s.get("name", "Reconstructed Screen")
                b64 = s.get("bmp_base64", "")
                t_count = s.get("tile_count", 0)
                out.append("        <div class='rdp-screen-box'>")
                out.append(f"          <h3>{html.escape(s_name)} &mdash; {t_count} Reconstructed Tiles</h3>")
                out.append("          <p style='color: var(--text-muted); font-size: 12px; margin-bottom: 12px;'>Composite screen reconstructed by aligning adjacent 64x64 tiles with edge pixel color matching. Raw tiles and uncompressed BMPs are sealed in evidence folder <code>rdp_tiles/</code>.</p>")
                out.append("          <div class='rdp-canvas-view'>")
                out.append(f"            <img src='data:image/bmp;base64,{b64}' alt='{html.escape(s_name)}' />")
                out.append("          </div>")
                out.append("        </div>")

            if self.data.sample_tiles_b64:
                out.append("        <div class='rdp-screen-box'>")
                out.append(f"          <h3>Extracted 64x64 Tiles Preview ({len(self.data.sample_tiles_b64)} Samples)</h3>")
                out.append("          <div class='rdp-tile-strip'>")
                for tb64 in self.data.sample_tiles_b64[:200]:
                    out.append(f"            <div class='rdp-tile-item'><img src='data:image/bmp;base64,{tb64}' alt='RDP Tile' /></div>")
                out.append("          </div>")
                out.append("        </div>")
        out.append("      </div>")
        out.append("    </div>")

        # Tab 5: Chain of Custody
        out.append("    <div id='tab-custody' class='tab-content'>")
        out.append("      <div class='rdp-screen-box'>")
        out.append("        <h3>Cryptographic Chain of Custody & Acquisition Integrity</h3>")
        custody_json = json.dumps(self.data.custody or {}, indent=2)
        out.append(f"        <pre class='detail-box' style='background: var(--bg-card); border-radius: 6px; margin-top: 14px;'>{html.escape(custody_json)}</pre>")
        out.append("      </div>")
        out.append("    </div>")

        out.append("  </div>")  # /container

        out.append(f"  <script>{REPORT_JS}</script>")
        out.append("</body>")
        out.append("</html>")

        return "\n".join(out)
