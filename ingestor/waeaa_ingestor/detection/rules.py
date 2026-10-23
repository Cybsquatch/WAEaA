"""Proprietary forensic detection rules.

Evaluates parsed records against MITRE ATT&CK categorized indicators:
credential dumping, execution of LOLBins, persistence, anti-forensics,
RDP intrusion, lateral movement, ransomware deployment, defender malware alerts,
and Linux-specific exploit patterns.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod

from waeaa_ingestor.detection.models import Finding, MitreAttack, Severity
from waeaa_ingestor.parsers.base import ParsedRecord


def get_record_full_text(record: ParsedRecord) -> str:
    """Concatenate summary, action, source file, and all detail values for robust pattern matching."""
    parts = [record.summary, record.action, record.source_file]
    for v in record.details.values():
        if isinstance(v, (str, int, float)):
            parts.append(str(v))
    return " ".join(parts)


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
            provider = record.details.get("provider", "System")
            channel = record.details.get("channel", "")
            return Finding(
                finding_id=f"{self.rule_id}-{record.source_file}-{record.timestamp_utc}-{event_id}",
                rule_id=self.rule_id,
                title=f"Event Log Cleared ({channel or provider})",
                severity=self.severity,
                description=self.description,
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=f"Event log cleared: Event ID {event_id} ({provider}) on {channel}",
                mitre=self.mitre,
                details=record.details,
            )
        return None


class RdpIntrusionRule(BaseRule):
    """Detects incoming Remote Desktop (RDP) logons, sessions, and external connections."""

    rule_id = "waeaa.rdp.connection"
    title = "Remote Desktop (RDP) Inbound Authentication or Session"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Initial Access",
        technique_id="T1078.002",
        technique_name="Valid Accounts: Domain Accounts",
    )
    description = (
        "Inbound Remote Desktop authentication (Event 1149) or session reconnection/logon "
        "(Event 21, 24, 25) detected. Threat actors leverage exposed RDP services for initial access."
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for incoming RDP session events."""
        if record.artefact_type != "EventLog":
            return None

        event_id = record.details.get("event_id")
        channel = str(record.details.get("channel", "")).lower()
        provider = str(record.details.get("provider", "")).lower()

        is_rdp = "terminalservices" in channel or "rdp" in channel or "terminalservices" in provider
        if not is_rdp:
            return None

        if event_id == 1149:
            user = record.user or record.details.get("user") or record.details.get("Param1") or record.details.get("param_4", "Unknown")
            src_ip = record.details.get("ip_address") or record.details.get("Param3") or record.details.get("param_5", "Unknown")
            return Finding(
                finding_id=f"{self.rule_id}-1149-{record.timestamp_utc}-{src_ip}",
                rule_id=self.rule_id,
                title="RDP Authentication Succeeded (Event 1149)",
                severity=Severity.CRITICAL if (src_ip and not src_ip.startswith(("10.", "192.168.", "172.16."))) else Severity.HIGH,
                description=f"Successful RDP user authentication for account '{user}' from IP address {src_ip}.",
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=f"RDP Logon: User '{user}' authenticated from source IP {src_ip}",
                mitre=self.mitre,
                details=record.details,
            )
        elif event_id in (21, 25):
            action_desc = "Session Logon" if event_id == 21 else "Session Reconnected"
            return Finding(
                finding_id=f"{self.rule_id}-{event_id}-{record.timestamp_utc}",
                rule_id=self.rule_id,
                title=f"RDP {action_desc} (Event {event_id})",
                severity=Severity.MEDIUM,
                description=f"Terminal Services {action_desc} recorded for user session.",
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=f"RDP {action_desc} (Event ID {event_id})",
                mitre=self.mitre,
                details=record.details,
            )
        return None


class SmbAdminShareLateralMovementRule(BaseRule):
    """Detects outbound or inbound SMB Admin Share access (ADMIN$, C$, IPC$) for lateral movement."""

    rule_id = "waeaa.lateral_movement.smb_admin_share"
    title = "SMB Administrative Share Lateral Movement"
    severity = Severity.CRITICAL
    mitre = MitreAttack(
        tactic="Lateral Movement",
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares",
    )
    description = (
        "Access to administrative network shares (ADMIN$, C$, IPC$) identified. "
        "Threat actors use administrative shares to stage payloads, execute remote services, and propagate ransomware."
    )

    ADMIN_SHARE_PATTERN = re.compile(r"\\([a-zA-Z0-9_\-\.\*]+)\\(admin\$|c\$|ipc\$)", re.IGNORECASE)

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for admin share access in SMB client events or security logs."""
        text = get_record_full_text(record)
        match = self.ADMIN_SHARE_PATTERN.search(text)
        if match:
            target_host = match.group(1)
            share_name = match.group(2).upper()
            return Finding(
                finding_id=f"{self.rule_id}-{target_host}-{share_name}-{record.timestamp_utc}",
                rule_id=self.rule_id,
                title=f"Lateral Movement to \\\\{target_host}\\{share_name}",
                severity=self.severity,
                description=f"Connection or access established to administrative share \\\\{target_host}\\{share_name}.",
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=f"Admin Share Access: \\\\{target_host}\\{share_name}",
                mitre=self.mitre,
                details=record.details,
            )
        return None


class PsExecRansomwareDeploymentRule(BaseRule):
    """Detects PsExec execution, hardcoded credentials, and ransomware staging in tasks or commands."""

    rule_id = "waeaa.ransomware.psexec_deployment"
    title = "PsExec Remote Execution / Ransomware Staging"
    severity = Severity.CRITICAL
    mitre = MitreAttack(
        tactic="Lateral Movement",
        technique_id="T1570",
        technique_name="Lateral Tool Transfer",
    )
    description = (
        "PsExec remote execution command identified targeting multiple network endpoints with "
        "credentials or executing suspicious staging binaries (e.g. rename.exe, petya)."
    )

    PSEXEC_PATTERN = re.compile(r"(psexec(\.exe)?|-accept-eula|rename\.exe)", re.IGNORECASE)

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for PsExec and ransomware command lines."""
        text = get_record_full_text(record)
        if self.PSEXEC_PATTERN.search(text):
            return Finding(
                finding_id=f"{self.rule_id}-{record.timestamp_utc}",
                rule_id=self.rule_id,
                title="PsExec Remote Command / Ransomware Deployment",
                severity=self.severity,
                description=(
                    "PsExec remote command execution identified with arguments indicative of "
                    "mass lateral propagation or ransomware staging."
                ),
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=f"PsExec Deployment: {record.summary[:100]}",
                mitre=self.mitre,
                details=record.details,
            )
        return None


class RemoteLogonRule(BaseRule):
    """Detects remote network or RDP logons (Event 4624) from external or suspicious IP addresses."""

    rule_id = "waeaa.security.remote_logon"
    title = "Remote Network or RDP Logon (Event 4624)"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Lateral Movement",
        technique_id="T1078.002",
        technique_name="Valid Accounts: Domain Accounts",
    )
    description = (
        "Successful network or remote interactive (RDP) logon recorded. "
        "Adversaries leverage compromised or valid administrative credentials for lateral movement."
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for remote logons with IP addresses or administrative accounts."""
        if record.artefact_type != "EventLog":
            return None

        event_id = record.details.get("event_id")
        if event_id != 4624:
            return None

        ip = str(record.details.get("ip_address", "")).strip()
        lt = str(record.details.get("logon_type", ""))
        user = record.user or str(record.details.get("user", ""))

        # Only alert on network/remote logons (LogonType 3, 10, or when an IP is present)
        is_remote = "3" in lt or "10" in lt or bool(ip and ip not in ("-", "127.0.0.1", "::1"))
        if not is_remote:
            return None

        # Determine severity: external IP or privileged account -> CRITICAL/HIGH
        is_external_ip = bool(ip and not ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.")))
        is_admin_user = any(a in user.lower() for a in ("admin", "administrator", "root"))

        if is_external_ip and is_admin_user:
            sev = Severity.CRITICAL
        elif is_external_ip:
            sev = Severity.HIGH
        elif is_admin_user:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM

        ws = record.details.get("workstation", "")
        ws_part = f" from Workstation '{ws}'" if ws else ""
        ip_part = f" (IP: {ip})" if ip else ""

        return Finding(
            finding_id=f"{self.rule_id}-{record.timestamp_utc}-{user}-{ip}",
            rule_id=self.rule_id,
            title=f"Remote Logon: '{user}'{ip_part}",
            severity=sev,
            description=f"Successful remote logon for account '{user}' via LogonType {lt}{ws_part}{ip_part}.",
            timestamp_utc=record.timestamp_utc,
            source_artefact=record.source_file,
            summary=record.summary,
            mitre=self.mitre,
            details=record.details,
        )


class FailedLogonRule(BaseRule):
    """Detects failed authentication attempts (Event 4625) indicative of password spraying or brute force."""

    rule_id = "waeaa.security.failed_logon"
    title = "Failed Authentication Attempt (Event 4625)"
    severity = Severity.MEDIUM
    mitre = MitreAttack(
        tactic="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
    )
    description = (
        "An account failed to log on. Multiple failed logon attempts indicate brute force, "
        "credential stuffing, or password guessing attacks."
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for Event 4625 failed logons."""
        if record.artefact_type != "EventLog":
            return None

        event_id = record.details.get("event_id")
        if event_id != 4625:
            return None

        user = record.user or str(record.details.get("user", "Unknown"))
        ip = str(record.details.get("ip_address", ""))
        is_external = bool(ip and not ip.startswith(("10.", "192.168.", "172.16.", "127.")))

        return Finding(
            finding_id=f"{self.rule_id}-{record.timestamp_utc}-{user}-{ip}",
            rule_id=self.rule_id,
            title=f"Failed Logon: '{user}'" + (f" from {ip}" if ip else ""),
            severity=Severity.HIGH if is_external else Severity.MEDIUM,
            description=f"Logon failure recorded for account '{user}'. {record.summary}",
            timestamp_utc=record.timestamp_utc,
            source_artefact=record.source_file,
            summary=record.summary,
            mitre=self.mitre,
            details=record.details,
        )


class UserAccountCreatedRule(BaseRule):
    """Detects the creation of new Windows local or domain user accounts (Event 4720)."""

    rule_id = "waeaa.persistence.account_created"
    title = "New User Account Created (Event 4720)"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Persistence",
        technique_id="T1136.001",
        technique_name="Create Account: Local Account",
    )
    description = (
        "A new user account was created. Adversaries frequently create rogue administrative "
        "accounts to maintain persistence within compromised environments."
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for Event 4720 account creations."""
        if record.artefact_type != "EventLog":
            return None

        event_id = record.details.get("event_id")
        if event_id != 4720:
            return None

        target = record.details.get("TargetUserName", "Unknown")
        actor = record.user or "Unknown"

        return Finding(
            finding_id=f"{self.rule_id}-{record.timestamp_utc}-{target}",
            rule_id=self.rule_id,
            title=f"User Account Created: '{target}'",
            severity=self.severity,
            description=f"User account '{target}' was created by '{actor}'.",
            timestamp_utc=record.timestamp_utc,
            source_artefact=record.source_file,
            summary=record.summary,
            mitre=self.mitre,
            details=record.details,
        )


class PrivilegedGroupModificationRule(BaseRule):
    """Detects addition of users to security-enabled groups (Event 4728, 4732, 4756)."""

    rule_id = "waeaa.persistence.privileged_group_add"
    title = "User Added to Security Group (Event 4728/4732/4756)"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Privilege Escalation",
        technique_id="T1098",
        technique_name="Account Manipulation",
    )
    description = (
        "A member was added to a security-enabled group (such as Administrators or Remote Desktop Users). "
        "Threat actors use group membership changes to elevate privileges."
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for group membership additions."""
        if record.artefact_type != "EventLog":
            return None

        event_id = record.details.get("event_id")
        if event_id not in (4728, 4732, 4756):
            return None

        member = record.details.get("MemberName", record.details.get("param_0", "Unknown"))
        target_grp = record.details.get("TargetUserName", "SecurityGroup")

        return Finding(
            finding_id=f"{self.rule_id}-{record.timestamp_utc}-{target_grp}-{member}",
            rule_id=self.rule_id,
            title=f"Member '{member}' Added to Group '{target_grp}'",
            severity=self.severity,
            description=f"Account '{member}' was granted membership in group '{target_grp}'.",
            timestamp_utc=record.timestamp_utc,
            source_artefact=record.source_file,
            summary=record.summary,
            mitre=self.mitre,
            details=record.details,
        )


class NetworkShareAccessRule(BaseRule):
    """Detects access to administrative network shares (ADMIN$, C$, IPC$) via Security Events 5140 and 5145."""

    rule_id = "waeaa.lateral_movement.network_share_access"
    title = "Administrative Network Share Accessed (Event 5140/5145)"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Lateral Movement",
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares",
    )
    description = (
        "A network share or file within an administrative share (ADMIN$, C$, IPC$) was accessed. "
        "Adversaries use admin shares to transfer tools and execute commands remotely."
    )

    ADMIN_SHARE_PATTERN = re.compile(r"\\([a-zA-Z0-9_\-\.\*]+)\\(admin\$|c\$|ipc\$)", re.IGNORECASE)

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for Event 5140/5145 administrative share events."""
        if record.artefact_type != "EventLog":
            return None

        event_id = record.details.get("event_id")
        if event_id not in (5140, 5145):
            return None

        share = str(record.details.get("share_name", record.details.get("ShareName", "")))
        if not self.ADMIN_SHARE_PATTERN.search(share):
            return None

        user = record.user or str(record.details.get("user", "Unknown"))
        ip = str(record.details.get("ip_address", ""))
        rel_target = str(record.details.get("relative_target", record.details.get("RelativeTargetName", "")))

        target_part = f" (File: {rel_target})" if rel_target else ""
        ip_part = f" from IP: {ip}" if ip else ""

        return Finding(
            finding_id=f"{self.rule_id}-{record.timestamp_utc}-{share}-{user}",
            rule_id=self.rule_id,
            title=f"Admin Share Accessed: '{share}'{ip_part}",
            severity=self.severity,
            description=f"Administrative share '{share}' was accessed by '{user}'{ip_part}{target_part}.",
            timestamp_utc=record.timestamp_utc,
            source_artefact=record.source_file,
            summary=record.summary,
            mitre=self.mitre,
            details=record.details,
        )


class SuspiciousScheduledTaskRule(BaseRule):
    """Detects persistence installed via non-standard or malicious scheduled tasks."""

    rule_id = "waeaa.persistence.scheduled_task"
    title = "Suspicious Scheduled Task Persistence"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Persistence",
        technique_id="T1053.005",
        technique_name="Scheduled Task/Job: Scheduled Task",
    )
    description = (
        "Scheduled task configured to execute utilities from Downloads, Desktop, Temp, "
        "or non-standard administrative tools with elevated privileges."
    )

    SUSP_LOCATIONS = re.compile(
        r"(\\users\\.*\\(downloads|desktop|temp|appdata)|psexec|powershell.*-w\s+hidden|cscript|wscript)",
        re.IGNORECASE,
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check scheduled tasks for suspicious paths or commands."""
        if record.artefact_type != "ScheduledTask":
            return None

        cmd = str(record.details.get("command", ""))
        name = str(record.details.get("task_name", ""))
        full_text = f"{name} {cmd}"

        if self.SUSP_LOCATIONS.search(full_text):
            return Finding(
                finding_id=f"{self.rule_id}-{name}-{record.timestamp_utc}",
                rule_id=self.rule_id,
                title=f"Suspicious Scheduled Task: '{name}'",
                severity=self.severity,
                description=f"Task '{name}' executes commands from suspicious location: {cmd[:120]}",
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=f"Task '{name}' -> {cmd[:90]}",
                mitre=self.mitre,
                details=record.details,
            )
        return None


class DefenderMalwareDetectionRule(BaseRule):
    """Detects Windows Defender malware detections, infected resources, and configuration changes."""

    rule_id = "waeaa.antivirus.malware_detected"
    title = "Antivirus Malware Detection or Protection Event"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Execution",
        technique_id="T1204.002",
        technique_name="User Execution: Malicious File",
    )
    description = (
        "Windows Defender Antivirus recorded a malware detection event, suspicious threat item, "
        "or antimalware configuration alteration."
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for Windows Defender alerts."""
        if record.artefact_type != "EventLog":
            return None

        channel = str(record.details.get("channel", "")).lower()
        provider = str(record.details.get("provider", "")).lower()
        if "defender" not in channel and "defender" not in provider:
            return None

        event_id = record.details.get("event_id")
        if event_id in (1000, 1001, 1002, 1116, 1117):
            return Finding(
                finding_id=f"{self.rule_id}-{record.timestamp_utc}-{event_id}",
                rule_id=self.rule_id,
                title=f"Defender Detection Event (Event ID {event_id})",
                severity=Severity.HIGH,
                description="Windows Defender Antivirus identified malware or suspicious software.",
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary=f"Defender Malware Event ID {event_id}",
                mitre=self.mitre,
                details=record.details,
            )
        elif event_id == 5007:
            return Finding(
                finding_id=f"{self.rule_id}-5007-{record.timestamp_utc}",
                rule_id=self.rule_id,
                title="Defender Antivirus Configuration Changed",
                severity=Severity.MEDIUM,
                description="Defender protection configuration or exclusion setting was modified.",
                timestamp_utc=record.timestamp_utc,
                source_artefact=record.source_file,
                summary="Defender Configuration Modified (Event ID 5007)",
                mitre=MitreAttack(tactic="Defense Evasion", technique_id="T1562.001", technique_name="Impair Defenses: Disable or Modify Tools"),
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
        text = get_record_full_text(record)
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
        content = get_record_full_text(record)
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
        text = get_record_full_text(record)
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
        text = get_record_full_text(record)
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
        text = get_record_full_text(record)
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

        text = get_record_full_text(record)
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
    title = "Persistence via Registry Run or Startup Key"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Persistence",
        technique_id="T1547.001",
        technique_name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    )
    description = (
        "Entry identified in autostart execution registry locations "
        "(CurrentVersion\\Run, RunOnce, Winlogon, or Image File Execution Options)."
    )

    RUN_KEY_PATTERN = re.compile(
        r"\\(run|runonce|winlogon|image file execution options)",
        re.IGNORECASE,
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for autostart registry entries."""
        if record.artefact_type not in ("Registry", "RegistryRunKey"):
            return None

        path = record.details.get("key_path", "")
        summary = record.summary.lower()
        if not (self.RUN_KEY_PATTERN.search(path) or "run key" in summary or record.artefact_type == "RegistryRunKey"):
            return None

        val_data = str(record.details.get("value_data", "")).lower()
        if not val_data or val_data in ("(default)", "none"):
            return None

        return Finding(
            finding_id=f"{self.rule_id}-{record.timestamp_utc}",
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            description=self.description,
            timestamp_utc=record.timestamp_utc,
            source_artefact=record.source_file,
            summary=f"Autostart value in {path}: {val_data[:80]}",
            mitre=self.mitre,
            details=record.details,
        )


class LinuxShadowAccessRule(BaseRule):
    """Detects unauthorized access or tampering with /etc/shadow."""

    rule_id = "waeaa.linux.shadow_access"
    title = "Unauthorized Access to Linux Shadow Password Database"
    severity = Severity.HIGH
    mitre = MitreAttack(
        tactic="Credential Access",
        technique_id="T1003.008",
        technique_name="/etc/passwd and /etc/shadow",
    )
    description = (
        "Command execution attempting to read, dump, or copy /etc/shadow, "
        "indicating password hash harvesting."
    )

    PATTERN = re.compile(
        r"\b(cat|head|tail|less|more|grep|cp|tar)\s+.*(/etc/shadow|/etc/gshadow)\b",
        re.IGNORECASE,
    )

    def evaluate(self, record: ParsedRecord) -> Finding | None:
        """Check for shadow access commands."""
        text = get_record_full_text(record)
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
        text = get_record_full_text(record)
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

        text = get_record_full_text(record)
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
        RdpIntrusionRule(),
        RemoteLogonRule(),
        FailedLogonRule(),
        UserAccountCreatedRule(),
        PrivilegedGroupModificationRule(),
        NetworkShareAccessRule(),
        SmbAdminShareLateralMovementRule(),
        PsExecRansomwareDeploymentRule(),
        SuspiciousScheduledTaskRule(),
        DefenderMalwareDetectionRule(),
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
