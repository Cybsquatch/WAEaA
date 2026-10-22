"""Matching engine evaluating evidence records against Threat Intel indicators."""

from __future__ import annotations

from pathlib import Path

from waeaa_ingestor.archive.reader import ManifestEntry
from waeaa_ingestor.detection.models import Finding, MitreAttack, Severity
from waeaa_ingestor.intel.database import ThreatIntelDB
from waeaa_ingestor.parsers.base import ParsedRecord


class ThreatIntelMatcher:
    """Matches files, hashes, and IP addresses against the Threat Intel database."""

    def __init__(self, db: ThreatIntelDB | None = None) -> None:
        """Initialize matcher with database instance."""
        self.db = db or ThreatIntelDB()

    def evaluate_manifest_entry(self, entry: ManifestEntry) -> list[Finding]:
        """Check acquired file hash and filename against threat intel databases."""
        findings: list[Finding] = []

        # 1. Check SHA-256 hash match
        if entry.sha256:
            match = self.db.check_hash(entry.sha256)
            if match:
                findings.append(
                    Finding(
                        finding_id=f"INTEL-HASH-{entry.sha256[:8]}",
                        rule_id="intel.known_malicious_hash",
                        title=f"Known Malicious File: {match.threat_name}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"File matches known threat signature [{match.threat_name}]. "
                            f"{match.description}"
                        ),
                        timestamp_utc=entry.acquired_utc or entry.modified_utc,
                        source_artefact=entry.source_path,
                        summary=f"Matched hash {entry.sha256} ({match.threat_name})",
                        mitre=MitreAttack(
                            tactic="Execution",
                            technique_id="T1204.002",
                            technique_name="Malicious File",
                        ),
                        details={
                            "sha256": entry.sha256,
                            "file_size": entry.size,
                            "source_path": entry.source_path,
                            "threat_type": match.threat_type,
                            "threat_name": match.threat_name,
                        },
                    )
                )

        # 2. Check vulnerable driver filename
        fname = Path(entry.source_path).name.lower()
        vuln_desc = self.db.check_driver_name(fname)
        if vuln_desc:
            findings.append(
                Finding(
                    finding_id=f"INTEL-BYOVD-{fname}",
                    rule_id="intel.vulnerable_driver_byovd",
                    title=f"Known Vulnerable Driver: {fname}",
                    severity=Severity.HIGH,
                    description=(
                        f"Potential Bring Your Own Vulnerable Driver (BYOVD) artifact: {vuln_desc}"
                    ),
                    timestamp_utc=entry.acquired_utc or entry.modified_utc,
                    source_artefact=entry.source_path,
                    summary=f"Vulnerable driver identified: {fname}",
                    mitre=MitreAttack(
                        tactic="Defense Evasion",
                        technique_id="T1068",
                        technique_name="Exploitation for Privilege Escalation",
                    ),
                    details={
                        "filename": fname,
                        "source_path": entry.source_path,
                        "vulnerability": vuln_desc,
                        "sha256": entry.sha256,
                    },
                )
            )

        return findings

    def evaluate_record(self, record: ParsedRecord) -> list[Finding]:
        """Check parsed record fields (IP addresses, remote hosts) against threat intel."""
        findings: list[Finding] = []

        # Check IP in details
        ip_candidate = record.details.get("ip") or record.details.get("host")
        if isinstance(ip_candidate, str) and ip_candidate:
            match = self.db.check_ip(ip_candidate)
            if match:
                findings.append(
                    Finding(
                        finding_id=f"INTEL-IP-{ip_candidate.replace('.', '_')}",
                        rule_id="intel.malicious_network_ip",
                        title=f"Connection to Known Threat IP: {ip_candidate}",
                        severity=Severity.HIGH,
                        description=(
                            f"Host communicated with known malicious address [{ip_candidate}]. "
                            f"Threat name: {match.threat_name}. {match.description}"
                        ),
                        timestamp_utc=record.timestamp_utc,
                        source_artefact=record.source_file,
                        summary=f"Threat IP {ip_candidate} ({match.threat_name})",
                        mitre=MitreAttack(
                            tactic="Command and Control",
                            technique_id="T1071.001",
                            technique_name="Web Protocols",
                        ),
                        details={
                            "ip": ip_candidate,
                            "threat_type": match.threat_type,
                            "threat_name": match.threat_name,
                            "source_summary": record.summary,
                        },
                    )
                )

        return findings
