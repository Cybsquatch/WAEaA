"""Core detection engine orchestrating rules and threat intelligence evaluation."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from typing import IO

from waeaa_ingestor.archive.reader import ManifestEntry
from waeaa_ingestor.detection.models import Finding, Severity
from waeaa_ingestor.detection.rules import BaseRule, get_default_detection_rules
from waeaa_ingestor.intel.matcher import ThreatIntelMatcher
from waeaa_ingestor.parsers.base import ParsedRecord


class DetectionEngine:
    """Executes rule-based and threat intelligence analysis over evidence."""

    def __init__(
        self,
        rules: list[BaseRule] | None = None,
        intel_matcher: ThreatIntelMatcher | None = None,
    ) -> None:
        """Initialize engine with detection rules and threat intelligence matcher."""
        self.rules = rules or get_default_detection_rules()
        self.intel_matcher = intel_matcher or ThreatIntelMatcher()

    def analyze(
        self,
        records: Iterable[ParsedRecord],
        manifest: Iterable[ManifestEntry] | None = None,
    ) -> list[Finding]:
        """Evaluate records and manifest entries against all detection mechanisms."""
        findings: list[Finding] = []
        seen_keys: set[str] = set()

        # 1. Evaluate threat intel on manifest entries (file hashes, known vulnerable drivers)
        if manifest:
            for entry in manifest:
                entry_findings = self.intel_matcher.evaluate_manifest_entry(entry)
                for f in entry_findings:
                    key = f"{f.rule_id}:{f.source_artefact}:{f.summary}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append(f)

        # 2. Evaluate rules and network intel on parsed records
        for record in records:
            # Threat intel checks (IPs, domains)
            for intel_finding in self.intel_matcher.evaluate_record(record):
                key = (
                    f"{intel_finding.rule_id}:{intel_finding.source_artefact}:"
                    f"{intel_finding.summary}"
                )
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(intel_finding)

            # Heuristic & behavioral rules
            for rule in self.rules:
                match = rule.evaluate(record)
                if match:
                    key = f"{match.rule_id}:{match.source_artefact}:{match.summary}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        findings.append(match)

        # Sort findings: Critical -> High -> Medium -> Low -> Info, then by timestamp
        findings.sort(
            key=lambda f: (-f.severity.rank, f.timestamp_utc or ""),
        )
        return findings

    @staticmethod
    def get_severity_counts(findings: list[Finding]) -> dict[str, int]:
        """Calculate counts per severity level."""
        counts = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    @staticmethod
    def get_mitre_summary(findings: list[Finding]) -> dict[str, list[dict[str, str]]]:
        """Aggregate findings grouped by MITRE ATT&CK tactic."""
        tactics: dict[str, list[dict[str, str]]] = {}
        for f in findings:
            if not f.mitre:
                continue
            tactic = f.mitre.tactic
            if tactic not in tactics:
                tactics[tactic] = []
            tactics[tactic].append({
                "technique_id": f.mitre.technique_id,
                "technique_name": f.mitre.technique_name,
                "title": f.title,
                "severity": f.severity.value,
            })
        return tactics

    @staticmethod
    def write_json(findings: list[Finding], stream: IO[str]) -> None:
        """Serialize findings into formatted JSON stream."""
        data = [f.to_dict() for f in findings]
        json.dump(data, stream, indent=2)

    @staticmethod
    def write_csv(findings: list[Finding], stream: IO[str]) -> None:
        """Export findings to CSV format."""
        writer = csv.writer(stream)
        writer.writerow([
            "finding_id",
            "rule_id",
            "title",
            "severity",
            "timestamp_utc",
            "tactic",
            "technique_id",
            "technique_name",
            "source_artefact",
            "summary",
            "description",
        ])
        for f in findings:
            tactic = f.mitre.tactic if f.mitre else ""
            t_id = f.mitre.technique_id if f.mitre else ""
            t_name = f.mitre.technique_name if f.mitre else ""
            writer.writerow([
                f.finding_id,
                f.rule_id,
                f.title,
                f.severity.value,
                f.timestamp_utc,
                tactic,
                t_id,
                t_name,
                f.source_artefact,
                f.summary,
                f.description,
            ])
