"""Proprietary forensic detection rules.

Evaluates parsed records against MITRE ATT&CK categorized indicators:
credential dumping, execution of LOLBins, persistence, anti-forensics,
and Linux-specific exploit patterns.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

from waeaa_ingestor.detection.models import Finding, MitreAttack, Severity
from waeaa_ingestor.parsers.base import ParsedRecord


class BaseRule(ABC):
    """Abstract base detection rule."""

    rule_id: str
    title: str
    severity: Severity
    mitre: MitreAttack
    description: str

    @abstractmethod
    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Evaluate record and return Finding if condition triggers."""


class LogClearingRule(BaseRule):
    """Detects clearing of Windows Event Logs (Event ID 1102 / 104)."""

    rule_id = "waeaa.evtx.log_clearing"
    title = "Audit or System Event Log Cleared"
    severity = Severity.CRITICAL
    mitre = MitreAttack(
        tactic="Defense Evasion",
        technique_id="T1070.001",
        technique_name="Clear Windows Event Records",
    )
    description = (
        "The security audit log or system event log was intentionally cleared. "
        "Adversaries frequently clear logs to evade detection and hinder forensic analysis."
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for event log clearing events."""
        if record.artefact_type != "EventLog":
            return None

        event_id = record.details.get("event_id")
        action = record.action
        if event_id in (1102, 104) or action == "AuditLogCleared":
            return Finding(
                finding_id=f"{self.rule_id}-{record.source_file}-{record.timestamp_utc}",
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=self.description,
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=record.summary,
                mitre=self.mitre,
                details=record.details,
            )
        return None


class SuspiciousServiceRule(BaseRule):
    """Detects suspicious service installations (Event ID 7045)."""

    rule_id = "waeaa.evtx.suspicious_service"
    title = "Suspicious Windows Service Created"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Persistence",
        technique_id="T1543.003",
        technique_name="Windows Service",
    )
    description = (
        "A new service was created with an executable pointing to command shells, "
        "script interpreters, or temporary directories."
    )

    SUSPICIOUS_PATTERN = re.compile(
        r"(powershell|cmd\.exe|mshta|rundll32|certutil|cscript|wscript|\\temp\\|\\appdata\\)",
        re.IGNORECASE,
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for suspicious services in event logs or registry."""
        img = record.details.get("image_path", "")
        cmd = record.details.get("command", "")
        text = f"{record.summary} {img} {cmd}"
        is_service = (
            record.details.get("event_id") == 7045 or record.artefact_type == "RegistryService"
        )
        if is_service and self.SUSPICIOUS_PATTERN.search(text):
            return Finding(
                    finding_id=f"{self.rule_id}-{record.timestamp_utc}",
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=self.description,
                    timestamp_utc=record.timestamp_utc,
                    source_artefact=record.source_file,
                    summary=record.summary,
                    mitre=self.mitre,
                    details=record.details,
                )
        return None


class PowerShellSuspiciousRule(BaseRule):
    """Detects obfuscated, encoded, or malicious PowerShell execution."""

    rule_id = "waeaa.powershell.suspicious_execution"
    title = "Suspicious PowerShell Execution or Download Cradle"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Execution",
        technique_id="T1059.001",
        technique_name="PowerShell",
    )
    description = (
        "PowerShell executed with encoded arguments, download cradles, or bypass flags "
        "characteristic of malicious payload stagers."
    )

    SUSP_PATTERNS = [
        re.compile(r"downloadstring", re.IGNORECASE),
        re.compile(r"frombase64string", re.IGNORECASE),
        re.compile(r"-\s*enc(odedcommand)?\s+[a-z0-9+/=]{10,}", re.IGNORECASE),
        re.compile(r"\b(iex|invoke-expression)\b", re.IGNORECASE),
        re.compile(r"net\.webclient", re.IGNORECASE),
        re.compile(r"executionpolicy\s+bypass", re.IGNORECASE),
        re.compile(r"reflection\.assembly::load", re.IGNORECASE),
    ]

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check command text against malicious PowerShell patterns."""
        content = (
            f"{record.summary} "
            f"{record.details.get('command', '')} "
            f"{record.details.get('script_text', '')}"
        )
        if "powershell" not in content.lower() and record.details.get("event_id") != 4104:
            return None

        for pattern in self.SUSP_PATTERNS:
            if pattern.search(content):
                return Finding(
                    finding_id=f"{self.rule_id}-{record.timestamp_utc}",
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=self.description,
                    timestamp_utc=record.timestamp_utc,
                    source_artefact=record.source_file,
                    summary=record.summary,
                    mitre=self.mitre,
                    details=record.details,
                )
        return None


class ShadowCopyDeletionRule(BaseRule):
    """Detects volume shadow copy deletion (anti-recovery / ransomware activity)."""

    rule_id = "waeaa.ransomware.shadow_copy_deletion"
    title = "Volume Shadow Copy Deletion"
    severity = Severity.CRITICAL
    mitre = MitreAttack(
        tactic="Impact",
        technique_id="T1490",
        technique_name="Inhibit System Recovery",
    )
    description = (
        "Commands detected attempting to delete shadow copies or system recovery state, "
        "a signature tactic of ransomware operators."
    )

    PATTERNS = [
        re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE),
        re.compile(r"wmic(\.exe)?\s+shadowcopy\s+delete", re.IGNORECASE),
        re.compile(r"wbadmin(\.exe)?\s+delete\s+catalog", re.IGNORECASE),
        re.compile(
            r"bcdedit(\.exe)?\s+/set\s+.*bootstatuspolicy\s+ignoreallfailures",
            re.IGNORECASE,
        ),
    ]

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for shadow copy deletion in commands or events."""
        text = f"{record.summary} {record.details.get('command', '')}"
        for p in self.PATTERNS:
            if p.search(text):
                return Finding(
                    finding_id=f"{self.rule_id}-{record.timestamp_utc}",
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=self.description,
                    timestamp_utc=record.timestamp_utc,
                    source_artefact=record.source_file,
                    summary=record.summary,
                    mitre=self.mitre,
                    details=record.details,
                )
        return None


class CredentialDumpingRule(BaseRule):
    """Detects LSASS memory dump and credential dumping tool indicators."""

    rule_id = "waeaa.credential.dumping"
    title = "LSASS Memory Access or Credential Dumping"
    severity = Severity.CRITICAL
    mitre = MitreAttack(
        tactic="Credential Access",
        technique_id="T1003.001",
        technique_name="OS Credential Dumping: LSASS Memory",
    )
    description = (
        "Detected access patterns or utility execution targeting the Local Security "
        "Authority Subsystem Service (LSASS) memory to harvest plaintext credentials or hashes."
    )

    PATTERNS = [
        re.compile(r"\bsekurlsa\b", re.IGNORECASE),
        re.compile(r"\blsadump\b", re.IGNORECASE),
        re.compile(r"procdump(\.exe)?\s+.*-ma\s+lsass", re.IGNORECASE),
        re.compile(r"comsvcs(\.dll)?\s+.*(#24|MiniDump)", re.IGNORECASE),
        re.compile(r"rundll32(\.exe)?\s+.*comsvcs", re.IGNORECASE),
        re.compile(r"ntdsutil(\.exe)?\s+.*ac\s+i\s+ntds", re.IGNORECASE),
    ]

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for credential dumping signatures."""
        text = f"{record.summary} {record.details.get('command', '')}"
        for p in self.PATTERNS:
            if p.search(text):
                return Finding(
                    finding_id=f"{self.rule_id}-{record.timestamp_utc}",
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=self.description,
                    timestamp_utc=record.timestamp_utc,
                    source_artefact=record.source_file,
                    summary=record.summary,
                    mitre=self.mitre,
                    details=record.details,
                )
        return None


class LOLBinsExecutionRule(BaseRule):
    """Detects living-off-the-land binaries (LOLBins) used for proxy execution or downloads."""

    rule_id = "waeaa.execution.lolbins"
    title = "Suspicious Living-Off-The-Land Binary (LOLBin) Execution"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Defense Evasion",
        technique_id="T1218",
        technique_name="System Binary Proxy Execution",
    )
    description = (
        "Legitimate system utility executed with suspicious flags used to download "
        "remote payloads, execute arbitrary scripts, or bypass application whitelisting."
    )

    PATTERNS = [
        re.compile(r"certutil(\.exe)?\s+.*-(urlcache|split|decode)", re.IGNORECASE),
        re.compile(r"bitsadmin(\.exe)?\s+/transfer", re.IGNORECASE),
        re.compile(r"mshta(\.exe)?\s+(http|javascript|vbscript)", re.IGNORECASE),
        re.compile(r"regsvr32(\.exe)?\s+.*(/s\s+/u\s+/i:http|scrobj\.dll)", re.IGNORECASE),
        re.compile(r"curl(\.exe)?\s+.*\|\s*(bash|sh|cmd|powershell)", re.IGNORECASE),
    ]

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for LOLBins command lines."""
        text = f"{record.summary} {record.details.get('command', '')}"
        for p in self.PATTERNS:
            if p.search(text):
                return Finding(
                    finding_id=f"{self.rule_id}-{record.timestamp_utc}",
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=self.description,
                    timestamp_utc=record.timestamp_utc,
                    source_artefact=record.source_file,
                    summary=record.summary,
                    mitre=self.mitre,
                    details=record.details,
                )
        return None


class ExecutionFromTempRule(BaseRule):
    """Detects binary execution from temporary directories."""

    rule_id = "waeaa.execution.temp_directory"
    title = "Execution from Temporary Directory"
    severity = Severity.MEDIUM
    mitre = MitreAttack(
        tactic="Defense Evasion",
        technique_id="T1036",
        technique_name="Masquerading",
    )
    description = (
        "Execution observed from temporary directories (Temp, AppData, /tmp, /dev/shm). "
        "Threat actors frequently stage and launch payloads from world-writable paths."
    )

    TEMP_PATTERN = re.compile(
        r"(\\appdata\\local\\temp\\|\\windows\\temp\\|/tmp/|/dev/shm/|/var/tmp/)",
        re.IGNORECASE,
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check if execution path is within temporary directories."""
        if record.artefact_type not in ("Prefetch", "ShellHistory", "LNK", "EventLog"):
            return None

        text = f"{record.source_file} {record.summary} {record.details.get('target_path', '')}"
        if self.TEMP_PATTERN.search(text) and (
            record.action in ("Executed", "ShellCommand", "ProcessCreated")
            or record.artefact_type == "Prefetch"
        ):
            return Finding(
                finding_id=f"{self.rule_id}-{record.timestamp_utc}",
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=self.description,
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=record.summary,
                mitre=self.mitre,
                details=record.details,
            )
        return None


class RegistryRunPersistenceRule(BaseRule):
    """Detects persistence installed via Run / RunOnce registry keys."""

    rule_id = "waeaa.persistence.registry_run"
    title = "Registry Run Key Persistence"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Persistence",
        technique_id="T1547.001",
        technique_name="Boot or Logon Autostart Execution: Registry Run Keys",
    )
    description = (
        "Autostart execution persistence established in Registry Run or RunOnce keys."
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for Run key registry records."""
        if record.artefact_type != "RegistryRunKey":
            return None

        val_data = str(record.details.get("value_data", "")).lower()
        # Escalate if pointing to script interpreters, temp folders, or suspicious extensions
        if any(term in val_data for term in ("temp", "powershell", "cmd.exe", "mshta", "vbs")):
            return Finding(
                finding_id=f"{self.rule_id}-{record.timestamp_utc}",
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=self.description,
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=record.summary,
                mitre=self.mitre,
                details=record.details,
            )
        return None


class LinuxShadowAccessRule(BaseRule):
    """Detects privileged access or reading of /etc/shadow."""

    rule_id = "waeaa.linux.shadow_access"
    title = "Unauthorized Access to /etc/shadow"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Credential Access",
        technique_id="T1003.008",
        technique_name="OS Credential Dumping: /etc/passwd and /etc/shadow",
    )
    description = (
        "Commands or sudo privileges detected accessing or dumping /etc/shadow password hashes."
    )

    PATTERN = re.compile(
        r"\b(cat|head|tail|less|more|grep|cp|tar)\s+.*(/etc/shadow|/etc/gshadow)\b",
        re.IGNORECASE,
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for shadow access commands."""
        text = f"{record.summary} {record.details.get('command', '')}"
        if self.PATTERN.search(text):
            return Finding(
                finding_id=f"{self.rule_id}-{record.timestamp_utc}",
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=self.description,
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=record.summary,
                mitre=self.mitre,
                details=record.details,
            )
        return None


class LinuxReverseShellRule(BaseRule):
    """Detects interactive reverse shell commands on Linux."""

    rule_id = "waeaa.linux.reverse_shell"
    title = "Interactive Reverse Shell Execution"
    severity = Severity.CRITICAL
    mitre = MitreAttack(
        tactic="Execution",
        technique_id="T1059.004",
        technique_name="Command and Scripting Interpreter: Unix Shell",
    )
    description = (
        "Execution of interactive reverse shells redirecting stdin/stdout across network sockets."
    )

    PATTERNS = [
        re.compile(r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+", re.IGNORECASE),
        re.compile(r"nc(\.traditional|\.openbsd)?\s+.*-e\s+(/bin/sh|/bin/bash)", re.IGNORECASE),
        re.compile(r"mkfifo\s+/tmp/.*\|.*nc\s+", re.IGNORECASE),
        re.compile(r"bash\s+-i\s+>&\s+/dev/tcp/", re.IGNORECASE),
        re.compile(r"python(\d)?\s+-c\s+.*socket.*connect.*os\.dup2", re.IGNORECASE),
    ]

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for reverse shell signatures."""
        text = f"{record.summary} {record.details.get('command', '')}"
        for p in self.PATTERNS:
            if p.search(text):
                return Finding(
                    finding_id=f"{self.rule_id}-{record.timestamp_utc}",
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=self.description,
                    timestamp_utc=record.timestamp_utc,
                    source_artefact=record.source_file,
                    summary=record.summary,
                    mitre=self.mitre,
                    details=record.details,
                )
        return None


class LinuxCronSuspiciousRule(BaseRule):
    """Detects scheduled tasks downloading and executing remote payloads."""

    rule_id = "waeaa.linux.cron_suspicious"
    title = "Suspicious Cron Job Payload Execution"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Persistence",
        technique_id="T1053.003",
        technique_name="Scheduled Task/Job: Cron",
    )
    description = (
        "Cron job configured with direct network downloads (curl/wget piping to shell) "
        "or reverse shell payloads."
    )

    PATTERN = re.compile(r"(curl|wget)\s+.*\|\s*(sh|bash)", re.IGNORECASE)

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check cron jobs for suspicious pipe-to-shell patterns."""
        if record.artefact_type != "CronJob":
            return None

        text = f"{record.summary} {record.details.get('command', '')}"
        if self.PATTERN.search(text):
            return Finding(
                finding_id=f"{self.rule_id}-{record.timestamp_utc}",
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                description=self.description,
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=record.summary,
                mitre=self.mitre,
                details=record.details,
            )
        return None


def get_default_detection_rules() -> list[BaseRule]:
    """Instantiate and return standard detection rules."""
    return [
        LogClearingRule(),
        SuspiciousServiceRule(),
        PowerShellSuspiciousRule(),
        ShadowCopyDeletionRule(),
        CredentialDumpingRule(),
        LOLBinsExecutionRule(),
        ExecutionFromTempRule(),
        RegistryRunPersistenceRule(),
        LinuxShadowAccessRule(),
        LinuxReverseShellRule(),
        LinuxCronSuspiciousRule(),
    ]
