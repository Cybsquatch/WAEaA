"""Unit tests for offline threat intelligence database and matcher."""

from __future__ import annotations

import json
from pathlib import Path

from waeaa_ingestor.archive.reader import ManifestEntry
from waeaa_ingestor.detection.models import Severity
from waeaa_ingestor.intel.database import ThreatIntelDB
from waeaa_ingestor.intel.matcher import ThreatIntelMatcher
from waeaa_ingestor.parsers.base import ParsedRecord


def test_threat_intel_hash_matching() -> None:
    db = ThreatIntelDB()
    matcher = ThreatIntelMatcher(db)

    # Mimikatz known hash match
    bad_hash = "9d5bf1f98bc9bc9a6ae4f36ae06456f4d22166a014a601bb816007ec25b2f42a"
    entry = ManifestEntry(
        source_path=r"C:\Windows\Temp\mimikatz.exe",
        archive_path="temp/mimikatz.exe",
        size=123456,
        sha256=bad_hash,
        modified_utc="2026-10-22T10:00:00Z",
        acquired_utc="2026-10-22T10:05:00Z",
        rule_id="windows.temp",
    )
    findings = matcher.evaluate_manifest_entry(entry)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "Mimikatz" in findings[0].title
    assert findings[0].mitre is not None
    assert findings[0].mitre.technique_id == "T1204.002"


def test_vulnerable_driver_matching() -> None:
    matcher = ThreatIntelMatcher()
    entry = ManifestEntry(
        source_path=r"C:\Windows\System32\drivers\gdrv.sys",
        archive_path="drivers/gdrv.sys",
        size=30000,
        sha256="ffff111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
        modified_utc="2026-10-22T10:00:00Z",
        acquired_utc="2026-10-22T10:05:00Z",
        rule_id="windows.drivers",
    )
    findings = matcher.evaluate_manifest_entry(entry)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "gdrv.sys" in findings[0].title


def test_ip_indicator_matching() -> None:
    matcher = ThreatIntelMatcher()
    record = ParsedRecord(
        artefact_type="Syslog",
        source_file="/var/log/auth.log",
        timestamp_utc="2026-10-22T10:15:00Z",
        action="SSHFailedLogon",
        summary="Failed password for root from 198.51.100.200 port 44321",
        details={"ip": "198.51.100.200", "user": "root"},
    )
    findings = matcher.evaluate_record(record)
    assert len(findings) == 1
    assert "198.51.100.200" in findings[0].title
    assert findings[0].severity == Severity.HIGH


def test_custom_indicators_loading(tmp_path: Path) -> None:
    custom_file = tmp_path / "custom_intel.json"
    custom_data = {
        "hashes": [
            {
                "hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "name": "Custom Impacket Sample",
                "type": "HackTool",
                "description": "Internal test sample",
            }
        ],
        "ips": [
            {
                "ip": "192.0.2.123",
                "name": "Custom Malicious Proxy",
                "type": "Proxy",
                "description": "Suspicious proxy",
            }
        ],
    }
    custom_file.write_text(json.dumps(custom_data), encoding="utf-8")

    db = ThreatIntelDB()
    count = db.load_custom_indicators(custom_file)
    assert count == 2
    test_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    assert db.check_hash(test_hash) is not None
    assert db.check_ip("192.0.2.123") is not None
