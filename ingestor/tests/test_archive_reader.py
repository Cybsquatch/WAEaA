"""Tests for the EvidenceArchive reader and hash verification."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from waeaa_ingestor.archive.reader import EvidenceArchive


def test_archive_reader(tmp_path: Path) -> None:
    zip_path = tmp_path / "TESTHOST.zip"
    file1_content = b"EVTX-BINARY-CONTENT-42"
    file1_hash = hashlib.sha256(file1_content).hexdigest()

    manifest_data = [
        {
            "source_path": r"C:\Windows\System32\winevt\Logs\Security.evtx",
            "archive_path": "C/Windows/System32/winevt/Logs/Security.evtx",
            "size": len(file1_content),
            "sha256": file1_hash,
            "modified_utc": "2026-10-22T10:00:00Z",
            "acquired_utc": "2026-10-22T10:05:00Z",
            "rule_id": "win.eventlogs",
            "deduplicated": False,
        }
    ]

    custody_data = {
        "hostname": "TESTHOST",
        "case_id": "IR-2026-001",
        "os": "windows",
        "total_items": 1,
    }

    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("C/Windows/System32/winevt/Logs/Security.evtx", file1_content)
        z.writestr("_meta/manifest.json", json.dumps(manifest_data))
        z.writestr("_meta/chain_of_custody.json", json.dumps(custody_data))

    with EvidenceArchive(zip_path) as archive:
        assert archive.hostname == "TESTHOST"
        assert archive.target_os == "windows"
        assert len(archive.manifest) == 1
        assert len(archive.list_files()) == 1
        assert len(archive.find_files("*.evtx")) == 1

        entry = archive.manifest[0]
        assert archive.verify_file_hash(entry) is True

        stream = archive.open_stream(entry.archive_path)
        assert stream.read() == file1_content
