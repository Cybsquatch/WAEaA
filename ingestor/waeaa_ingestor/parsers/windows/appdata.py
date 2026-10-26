"""Windows AppData Staged Executables and Scripts forensic parser.

Inspects scripts (.bat, .ps1, .vbs, .js, .hta, .cmd) and portable executables
staged in volatile user directories (AppData/Local/Temp, AppData/Roaming, ProgramData)
frequently targeted by attackers for initial staging, living-off-the-land executions,
or persistence mechanisms.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord

# High-risk scripting indicators commonly associated with malware staging
SUSPICIOUS_SCRIPT_PATTERNS = [
    (re.compile(r"(?i)\b(invoke-expression|iex)\b"), "PowerShell Dynamic Code Execution (IEX)"),
    (re.compile(r"(?i)\b(invoke-webrequest|iwr|downloadfile|downloadstring|curl|wget)\b"), "File Download Cradle"),
    (re.compile(r"(?i)\b(certutil|bitsadmin)\b.*?(\-urlcache|\/transfer)"), "Living-off-the-Land Downloader"),
    (re.compile(r"(?i)\b(vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.*?recoveryenabled\s+no)\b"), "Shadow Copy Deletion / Ransomware"),
    (re.compile(r"(?i)\b(powershell(?:\.exe)?\s+.*?(?:\-enc|\-encodedcommand|\-nop|\-w\s+hidden))\b"), "Encoded/Hidden PowerShell Launch"),
    (re.compile(r"(?i)\b(rundll32(?:\.exe)?\s+.*?javascript\:|mshta(?:\.exe)?\s+.*?http)\b"), "Scriptlet Proxy Execution"),
    (re.compile(r"(?i)\b(mimikatz|sekurlsa|lsass|procdump)\b"), "Credential Dumping Tool Reference"),
    (re.compile(r"(?i)\b(net\s+user\s+.*?\s+\/add|net\s+localgroup\s+administrators\s+.*?\s+\/add)\b"), "Account Creation / Privilege Escalation"),
    (re.compile(r"(?i)\b(set-mppreference\s+\-disablerealtime)\b"), "Windows Defender Tampering"),
]


class AppDataStagingParser(BaseParser):
    """Parser for executables and scripts staged in AppData / ProgramData directories."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file_path is a staged script or binary in AppData or ProgramData."""
        lower = file_path.lower().replace("\\", "/")
        in_staged_dir = (
            "appdata/local/temp" in lower
            or "appdata/roaming" in lower
            or "appdata/local" in lower
            or "programdata" in lower
        )
        if not in_staged_dir:
            return False

        ext = Path(lower).suffix
        return ext in (".bat", ".ps1", ".vbs", ".js", ".hta", ".cmd", ".exe", ".dll")

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Inspect staged file content and yield ParsedRecords."""
        raw_data = stream.read()
        if not raw_data:
            return

        lower = file_path.lower().replace("\\", "/")
        ext = Path(lower).suffix
        file_size = len(raw_data)
        sha256_hash = hashlib.sha256(raw_data).hexdigest()

        if ext in (".bat", ".ps1", ".vbs", ".js", ".hta", ".cmd"):
            text = raw_data.decode("utf-8", errors="replace")
            matched_indicators = []
            for pattern, label in SUSPICIOUS_SCRIPT_PATTERNS:
                if pattern.search(text):
                    matched_indicators.append(label)

            details: dict[str, Any] = {
                "file_size": file_size,
                "sha256": sha256_hash,
                "extension": ext,
                "matched_threat_indicators": matched_indicators,
                "script_preview": text[:200].replace("\r", " ").replace("\n", " ").strip(),
            }

            has_threats = len(matched_indicators) > 0
            action = "SuspiciousScriptStaged" if has_threats else "ScriptStagedInAppData"
            summary = (
                f"Staged {ext.upper()} script '{Path(file_path).name}' ({file_size} bytes)"
                + (f" [Indicators: {', '.join(matched_indicators)}]" if has_threats else "")
            )

            yield ParsedRecord(
                artefact_type="AppDataStaging",
                source_file=file_path,
                timestamp_utc="",
                action=action,
                summary=summary,
                user="",
                computer="",
                details=details,
            )

        elif ext in (".exe", ".dll"):
            is_pe = raw_data.startswith(b"MZ")
            details = {
                "file_size": file_size,
                "sha256": sha256_hash,
                "is_valid_pe": is_pe,
                "extension": ext,
            }

            summary = f"Staged PE Binary '{Path(file_path).name}' ({file_size:,} bytes, SHA256: {sha256_hash[:16]}...)"
            yield ParsedRecord(
                artefact_type="AppDataStaging",
                source_file=file_path,
                timestamp_utc="",
                action="BinaryStagedInAppData",
                summary=summary,
                user="",
                computer="",
                details=details,
            )
