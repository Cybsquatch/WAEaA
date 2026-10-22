"""Unit tests for offline HTML report generator."""

from __future__ import annotations

from waeaa_ingestor.detection.models import Finding, MitreAttack, Severity
from waeaa_ingestor.parsers.base import ParsedRecord
from waeaa_ingestor.report.generator import HtmlReportGenerator, ReportData


def test_html_report_generator_content() -> None:
    custody = {
        "case_id": "CASE-2026-99",
        "hostname": "WORKSTATION-01",
        "os": "windows",
        "examiner": "Chief Investigator",
        "description": "Incident triage",
        "authorized": True,
        "collection_start_utc": "2026-10-22T08:00:00Z",
        "collection_end_utc": "2026-10-22T08:15:00Z",
    }

    finding = Finding(
        finding_id="FIND-01",
        rule_id="waeaa.evtx.log_clearing",
        title="Security Audit Log Cleared",
        severity=Severity.CRITICAL,
        description="Audit log cleared by attacker",
        timestamp_utc="2026-10-22T08:05:00Z",
        source_artefact="Security.evtx",
        summary="Event 1102 cleared",
        mitre=MitreAttack(
            tactic="Defense Evasion",
            technique_id="T1070.001",
            technique_name="Clear Windows Event Records",
        ),
        details={"event_id": 1102},
    )

    record = ParsedRecord(
        artefact_type="EventLog",
        source_file="Security.evtx",
        timestamp_utc="2026-10-22T08:05:00Z",
        action="AuditLogCleared",
        summary="Log cleared",
    )

    data = ReportData(
        hostname="WORKSTATION-01",
        target_os="windows",
        analysis_time_utc="2026-10-22T08:30:00Z",
        custody=custody,
        findings=[finding],
        timeline_records=[record],
        parsed_by_type={"EventLog": 1},
        total_files_inspected=10,
    )

    generator = HtmlReportGenerator(data, language="en")
    html_output = generator.render()

    assert "<!DOCTYPE html>" in html_output
    assert "WORKSTATION-01" in html_output
    assert "CASE-2026-99" in html_output
    assert "Chief Investigator" in html_output
    assert "Security Audit Log Cleared" in html_output
    assert "T1070.001" in html_output
    assert "badge-critical" in html_output
    # Ensure offline self-contained (no external CDN links)
    assert "http://" not in html_output.split("<head>")[1].split("</head>")[0]
    assert "https://" not in html_output.split("<head>")[1].split("</head>")[0]
