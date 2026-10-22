"""End-to-end integration tests for IngestionPipeline and SuperTimeline."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from waeaa_ingestor.pipeline import IngestionPipeline


def test_ingestion_pipeline_end_to_end(tmp_path: Path) -> None:
    archive_file = tmp_path / "SRV-LINUX.zip"
    out_dir = tmp_path / "analysis_output"

    auth_log_content = (
        b"Oct 22 11:00:00 srv sshd[999]: Failed password for invalid user root"
        b" from 10.10.10.1 port 55442 ssh2\n"
        b"Oct 22 11:01:00 srv sshd[1000]: Accepted password for root"
        b" from 10.10.10.1 port 55444 ssh2\n"
    )

    bash_history_content = b"#1729600000\nwhoami\n#1729600005\nid\n"

    manifest_data = [
        {
            "source_path": "/var/log/auth.log",
            "archive_path": "var/log/auth.log",
            "size": len(auth_log_content),
            "sha256": "abc123",
            "modified_utc": "2026-10-22T11:01:00Z",
            "acquired_utc": "2026-10-22T11:05:00Z",
            "rule_id": "linux.debian.logs",
        }
    ]

    custody_data = {
        "hostname": "SRV-LINUX",
        "os": "linux",
        "case_id": "CASE-TEST",
    }

    with zipfile.ZipFile(archive_file, "w") as z:
        z.writestr("var/log/auth.log", auth_log_content)
        z.writestr("root/.bash_history", bash_history_content)
        z.writestr("_meta/manifest.json", json.dumps(manifest_data))
        z.writestr("_meta/chain_of_custody.json", json.dumps(custody_data))

    progress_updates: list[tuple[float, str]] = []

    def on_progress(pct: float, msg: str) -> None:
        progress_updates.append((pct, msg))

    pipeline = IngestionPipeline(archive_file, out_dir, progress_callback=on_progress)
    result = pipeline.run()

    assert result.hostname == "SRV-LINUX"
    assert result.total_files_inspected == 2
    assert result.total_records_parsed >= 3
    assert result.timeline_event_count >= 3
    assert len(progress_updates) > 0

    # Verify generated files
    timeline_csv = out_dir / "timeline" / "super_timeline.csv"
    timeline_json = out_dir / "timeline" / "super_timeline.json"
    parsed_syslog_csv = out_dir / "parsed" / "syslog_records.csv"

    assert timeline_csv.is_file()
    assert timeline_json.is_file()
    assert parsed_syslog_csv.is_file()

    with timeline_csv.open("r", encoding="utf-8") as f:
        content = f.read()
        assert "SSHFailedLogon" in content
        assert "SSHLogonSuccess" in content
