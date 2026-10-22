"""Self-contained, offline HTML report generator for incident response findings.

Produces an interactive, single-file HTML report with embedded responsive styles,
client-side search, filtering, MITRE ATT&CK matrix, timeline navigation,
and CSV export with zero external CDN dependencies.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
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
  padding: 24px 32px;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
header h1 { color: var(--text-bright); font-size: 22px; font-weight: 600; letter-spacing: 0.5px; }
header .meta { font-size: 13px; color: var(--text-muted); text-align: right; }

.container { max-width: 1440px; margin: 24px auto; padding: 0 24px; }

/* Metrics Cards */
.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 28px;
}
.metric-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 18px 20px;
}
.metric-card .title { font-size: 13px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }
.metric-card .value { font-size: 28px; font-weight: 700; color: var(--text-bright); margin-top: 6px; }

/* Tabs Navigation */
.tabs {
  display: flex;
  gap: 8px;
  border-bottom: 1px solid var(--border-color);
  margin-bottom: 24px;
}
.tab-btn {
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: var(--text-muted);
  font-size: 14px;
  font-weight: 600;
  padding: 12px 18px;
  cursor: pointer;
  transition: all 0.2s ease;
}
.tab-btn:hover { color: var(--text-bright); }
.tab-btn.active { color: var(--accent-blue); border-bottom-color: var(--accent-blue); }

.tab-content { display: none; }
.tab-content.active { display: block; }

/* Toolbar controls */
.toolbar {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.search-input {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 6px;
  color: var(--text-bright);
  padding: 8px 14px;
  font-size: 13px;
  min-width: 300px;
}
.search-input:focus { outline: none; border-color: var(--accent-blue); }

.filter-group { display: flex; gap: 6px; }
.btn-filter {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  color: var(--text-main);
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 12px;
  cursor: pointer;
}
.btn-filter.active { background: var(--bg-card); border-color: var(--accent-blue); color: var(--accent-blue); font-weight: 600; }

.btn-action {
  background: #238636;
  border: 1px solid rgba(240, 246, 252, 0.1);
  color: #ffffff;
  padding: 7px 14px;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
}
.btn-action:hover { background: #2ea043; }

/* Tables */
.table-wrapper {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow-x: auto;
}
table { width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }
thead th {
  background: var(--bg-card);
  padding: 12px 14px;
  color: var(--text-bright);
  font-weight: 600;
  border-bottom: 1px solid var(--border-color);
}
tbody td {
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-color);
  color: var(--text-main);
}
tbody tr:hover { background: rgba(110, 118, 129, 0.08); }
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
}
.mitre-card.crit { border-left-color: var(--accent-red); }
.mitre-card.high { border-left-color: var(--accent-orange); }
.mitre-card .tech-id { font-size: 11px; font-weight: 700; color: var(--text-muted); }
.mitre-card .tech-name { font-size: 13px; font-weight: 600; color: var(--text-bright); margin-top: 2px; }

/* Pagination */
.pagination {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 16px;
  font-size: 13px;
  color: var(--text-muted);
}
.pagination-btns { display: flex; gap: 8px; }
.pagination-btn {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  color: var(--text-bright);
  padding: 4px 10px;
  border-radius: 4px;
  cursor: pointer;
}
.pagination-btn:disabled { opacity: 0.4; cursor: not-allowed; }
"""

REPORT_JS = """
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('btn-' + tabId).classList.add('active');
  document.getElementById('tab-' + tabId).classList.add('active');
}

function toggleDetail(rowId) {
  const row = document.getElementById(rowId);
  if (row) {
    row.classList.toggle('open');
  }
}

function filterFindings() {
  const q = document.getElementById('search-findings').value.toLowerCase();
  const activeSev = document.querySelector('.btn-sev-filter.active').dataset.sev;
  const rows = document.querySelectorAll('#tbody-findings tr.data-row');

  rows.forEach(r => {
    const text = r.innerText.toLowerCase();
    const sev = r.dataset.sev;
    const matchesQuery = !q || text.includes(q);
    const matchesSev = (activeSev === 'ALL' || sev === activeSev);
    const visible = matchesQuery && matchesSev;
    r.style.display = visible ? '' : 'none';
    const detailRow = document.getElementById(r.id + '-detail');
    if (detailRow && !visible) {
      detailRow.classList.remove('open');
    }
  });
}

function setSevFilter(btn, sev) {
  document.querySelectorAll('.btn-sev-filter').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  btn.dataset.sev = sev;
  filterFindings();
}

function filterTimeline() {
  const q = document.getElementById('search-timeline').value.toLowerCase();
  const activeType = document.getElementById('filter-timeline-type').value;
  const rows = document.querySelectorAll('#tbody-timeline tr');

  rows.forEach(r => {
    const text = r.innerText.toLowerCase();
    const t = r.dataset.type;
    const matchesQuery = !q || text.includes(q);
    const matchesType = (activeType === 'ALL' || t === activeType);
    r.style.display = (matchesQuery && matchesType) ? '' : 'none';
  });
}

function exportTableToCsv(tbodyId, filename) {
  const rows = document.querySelectorAll('#' + tbodyId + ' tr');
  let csv = [];
  rows.forEach(r => {
    if (r.classList.contains('detail-row') || r.style.display === 'none') return;
    const cols = r.querySelectorAll('td');
    let rowData = [];
    cols.forEach(c => {
      let data = c.innerText.replace(/"/g, '""').trim();
      rowData.push('"' + data + '"');
    });
    if (rowData.length > 0) csv.push(rowData.join(','));
  });

  const blob = new Blob([csv.join('\\n')], { type: 'text/csv;charset=utf-8;' });
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
        out.append(f"      <h1>WAEaA Forensic Report &mdash; {html.escape(self.data.hostname)}</h1>")
        out.append(f"      <div style='color: var(--text-muted); font-size: 13px;'>Case: {html.escape(case_id)} | OS: {html.escape(self.data.target_os)} | Examiner: {html.escape(examiner)}</div>")
        out.append("    </div>")
        out.append("    <div class='meta'>")
        out.append(f"      <div>Generated: {html.escape(self.data.analysis_time_utc)}</div>")
        out.append("      <div>Status: <strong>Analyzed & Verified</strong></div>")
        out.append("    </div>")
        out.append("  </header>")

        out.append("  <div class='container'>")

        # Executive Metrics Cards
        out.append("    <div class='metrics-grid'>")
        out.append(f"      <div class='metric-card'><div class='title'>Critical Detections</div><div class='value' style='color: var(--accent-red);'>{crit_count}</div></div>")
        out.append(f"      <div class='metric-card'><div class='title'>High Severity</div><div class='value' style='color: var(--accent-orange);'>{high_count}</div></div>")
        out.append(f"      <div class='metric-card'><div class='title'>Total Findings</div><div class='value'>{total_findings}</div></div>")
        out.append(f"      <div class='metric-card'><div class='title'>Timeline Events</div><div class='value' style='color: var(--accent-blue);'>{total_timeline}</div></div>")
        out.append(f"      <div class='metric-card'><div class='title'>Files Acquired</div><div class='value'>{self.data.total_files_inspected}</div></div>")
        out.append("    </div>")

        # Tabs Header
        out.append("    <div class='tabs'>")
        out.append("      <button id='btn-findings' class='tab-btn active' onclick=\"switchTab('findings')\">Findings & Detections (" + str(total_findings) + ")</button>")
        out.append("      <button id='btn-mitre' class='tab-btn' onclick=\"switchTab('mitre')\">MITRE ATT&CK Matrix</button>")
        out.append("      <button id='btn-timeline' class='tab-btn' onclick=\"switchTab('timeline')\">Super-Timeline (" + str(total_timeline) + ")</button>")
        out.append("      <button id='btn-artefacts' class='tab-btn' onclick=\"switchTab('artefacts')\">Parsed Artefacts</button>")
        out.append("      <button id='btn-custody' class='tab-btn' onclick=\"switchTab('custody')\">Chain of Custody</button>")
        out.append("    </div>")

        # Tab 1: Findings & Detections
        out.append("    <div id='tab-findings' class='tab-content active'>")
        out.append("      <div class='toolbar'>")
        out.append("        <div class='filter-group'>")
        out.append("          <button class='btn-filter btn-sev-filter active' data-sev='ALL' onclick=\"setSevFilter(this, 'ALL')\">All</button>")
        out.append("          <button class='btn-filter btn-sev-filter' data-sev='Critical' onclick=\"setSevFilter(this, 'Critical')\">Critical</button>")
        out.append("          <button class='btn-filter btn-sev-filter' data-sev='High' onclick=\"setSevFilter(this, 'High')\">High</button>")
        out.append("          <button class='btn-filter btn-sev-filter' data-sev='Medium' onclick=\"setSevFilter(this, 'Medium')\">Medium</button>")
        out.append("          <button class='btn-filter btn-sev-filter' data-sev='Low' onclick=\"setSevFilter(this, 'Low')\">Low</button>")
        out.append("        </div>")
        out.append("        <div style='display: flex; gap: 8px;'>")
        out.append("          <input type='text' id='search-findings' class='search-input' placeholder='Search findings, rules, commands...' onkeyup='filterFindings()'>")
        out.append("          <button class='btn-action' onclick=\"exportTableToCsv('tbody-findings', 'findings.csv')\">Export CSV</button>")
        out.append("        </div>")
        out.append("      </div>")
        out.append("      <div class='table-wrapper'>")
        out.append("        <table>")
        out.append("          <thead><tr>")
        out.append("            <th>Severity</th><th>Timestamp (UTC)</th><th>Title</th><th>MITRE Technique</th><th>Source Artefact</th><th>Action</th>")
        out.append("          </tr></thead>")
        out.append("          <tbody id='tbody-findings'>")
        for idx, f in enumerate(self.data.findings):
            sev_class = f"badge-{f.severity.value.lower()}"
            t_str = f"{f.mitre.technique_id} ({f.mitre.technique_name})" if f.mitre else "N/A"
            row_id = f"f-row-{idx}"
            out.append(f"            <tr id='{row_id}' class='data-row' data-sev='{html.escape(f.severity.value)}'>")
            out.append(f"              <td><span class='badge {sev_class}'>{html.escape(f.severity.value)}</span></td>")
            out.append(f"              <td style='white-space: nowrap;'>{html.escape(f.timestamp_utc or 'N/A')}</td>")
            out.append(f"              <td><strong>{html.escape(f.title)}</strong><div style='font-size: 12px; color: var(--text-muted);'>{html.escape(f.summary)}</div></td>")
            out.append(f"              <td><span style='color: var(--accent-blue); font-weight: 600;'>{html.escape(t_str)}</span></td>")
            out.append(f"              <td style='font-family: monospace; font-size: 12px;'>{html.escape(f.source_artefact)}</td>")
            out.append(f"              <td><button class='btn-filter' onclick=\"toggleDetail('{row_id}-detail')\">Details</button></td>")
            out.append("            </tr>")
            # Expandable detail row
            detail_json = json.dumps(
                {
                    "rule_id": f.rule_id,
                    "description": f.description,
                    "mitre_tactic": f.mitre.tactic if f.mitre else "",
                    "details": f.details,
                },
                indent=2,
            )
            out.append(f"            <tr id='{row_id}-detail' class='detail-row'>")
            out.append(f"              <td colspan='6'><div class='detail-box'>{html.escape(detail_json)}</div></td>")
            out.append("            </tr>")
        out.append("          </tbody>")
        out.append("        </table>")
        out.append("      </div>")
        out.append("    </div>")

        # Tab 2: MITRE ATT&CK Matrix
        out.append("    <div id='tab-mitre' class='tab-content'>")
        out.append("      <div class='mitre-grid'>")
        tactics_map: dict[str, list[Finding]] = {}
        for f in self.data.findings:
            tac = f.mitre.tactic if f.mitre else "Uncategorized"
            tactics_map.setdefault(tac, []).append(f)

        for tactic_name, t_findings in tactics_map.items():
            out.append("        <div class='mitre-tactic-col'>")
            out.append(f"          <div class='mitre-tactic-title'>{html.escape(tactic_name)} ({len(t_findings)})</div>")
            for tf in t_findings:
                c_cls = "crit" if tf.severity.value == "Critical" else ("high" if tf.severity.value == "High" else "")
                t_id = tf.mitre.technique_id if tf.mitre else "Custom"
                t_name = tf.mitre.technique_name if tf.mitre else tf.title
                out.append(f"          <div class='mitre-card {c_cls}'>")
                out.append(f"            <div class='tech-id'>{html.escape(t_id)} &bull; {html.escape(tf.severity.value)}</div>")
                out.append(f"            <div class='tech-name'>{html.escape(t_name)}</div>")
                out.append(f"            <div style='font-size: 11px; color: var(--text-muted); margin-top: 4px;'>{html.escape(tf.title)}</div>")
                out.append("          </div>")
            out.append("        </div>")
        out.append("      </div>")
        out.append("    </div>")

        # Tab 3: Super-Timeline
        out.append("    <div id='tab-timeline' class='tab-content'>")
        out.append("      <div class='toolbar'>")
        out.append("        <div style='display: flex; gap: 8px; align-items: center;'>")
        out.append("          <select id='filter-timeline-type' class='search-input' style='min-width: 180px;' onchange='filterTimeline()'>")
        out.append("            <option value='ALL'>All Artefact Types</option>")
        for t_type in sorted(self.data.parsed_by_type.keys()):
            out.append(f"            <option value='{html.escape(t_type)}'>{html.escape(t_type)}</option>")
        out.append("          </select>")
        out.append("          <input type='text' id='search-timeline' class='search-input' placeholder='Filter timeline records...' onkeyup='filterTimeline()'>")
        out.append("        </div>")
        out.append("        <button class='btn-action' onclick=\"exportTableToCsv('tbody-timeline', 'timeline.csv')\">Export CSV</button>")
        out.append("      </div>")
        out.append("      <div class='table-wrapper'>")
        out.append("        <table>")
        out.append("          <thead><tr>")
        out.append("            <th>Timestamp (UTC)</th><th>Type</th><th>Action</th><th>User / Host</th><th>Summary</th><th>Source</th>")
        out.append("          </tr></thead>")
        out.append("          <tbody id='tbody-timeline'>")
        for rec in self.data.timeline_records[:2000]:  # Cap at 2000 for browser DOM responsiveness
            out.append(f"            <tr data-type='{html.escape(rec.artefact_type)}'>")
            out.append(f"              <td style='white-space: nowrap; font-family: monospace;'>{html.escape(rec.timestamp_utc or 'N/A')}</td>")
            out.append(f"              <td><span class='badge badge-medium'>{html.escape(rec.artefact_type)}</span></td>")
            out.append(f"              <td><strong>{html.escape(rec.action)}</strong></td>")
            out.append(f"              <td>{html.escape(rec.user or rec.computer or '')}</td>")
            out.append(f"              <td>{html.escape(rec.summary)}</td>")
            out.append(f"              <td style='font-family: monospace; font-size: 11px;'>{html.escape(rec.source_file)}</td>")
            out.append("            </tr>")
        out.append("          </tbody>")
        out.append("        </table>")
        out.append("      </div>")
        out.append("    </div>")

        # Tab 4: Parsed Artefacts
        out.append("    <div id='tab-artefacts' class='tab-content'>")
        out.append("      <div class='table-wrapper'>")
        out.append("        <table>")
        out.append("          <thead><tr>")
        out.append("            <th>Artefact Category</th><th>Record Count</th><th>Format</th><th>Extracted CSV</th>")
        out.append("          </tr></thead>")
        out.append("          <tbody>")
        for cat, cnt in sorted(self.data.parsed_by_type.items()):
            csv_name = f"{cat.lower()}_records.csv"
            out.append("            <tr>")
            out.append(f"              <td><strong>{html.escape(cat)}</strong></td>")
            out.append(f"              <td><span class='badge badge-info'>{cnt}</span></td>")
            out.append("              <td>Normalized Tabular Data</td>")
            out.append(f"              <td style='font-family: monospace;'>parsed/{html.escape(csv_name)}</td>")
            out.append("            </tr>")
        out.append("          </tbody>")
        out.append("        </table>")
        out.append("      </div>")
        out.append("    </div>")

        # Tab 5: Chain of Custody & Evidence Verification
        out.append("    <div id='tab-custody' class='tab-content'>")
        out.append("      <div class='table-wrapper' style='padding: 24px;'>")
        out.append("        <h3 style='color: var(--text-bright); margin-bottom: 16px;'>Chain of Custody Record</h3>")
        custody_dict = self.data.custody or {}
        out.append(f"        <div class='detail-box'>{html.escape(json.dumps(custody_dict, indent=2))}</div>")
        out.append("      </div>")
        out.append("    </div>")

        out.append("  </div>")  # /container
        out.append(f"  <script>{REPORT_JS}</script>")
        out.append("</body>")
        out.append("</html>")

        return "\n".join(out)
