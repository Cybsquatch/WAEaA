"""End-to-end ingestion and parsing execution pipeline."""

from __future__ import annotations

import csv
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from waeaa_ingestor.archive.reader import EvidenceArchive
from waeaa_ingestor.parsers.base import ParsedRecord
from waeaa_ingestor.parsers.registry import find_parser, get_default_parsers
from waeaa_ingestor.timeline.builder import SuperTimeline


@dataclass
class PipelineResult:
    """Summary of the completed ingestion and parsing run."""

    archive_path: Path
    output_dir: Path
    hostname: str
    target_os: str
    total_files_inspected: int = 0
    total_records_parsed: int = 0
    timeline_event_count: int = 0
    parsed_by_type: dict[str, int] = field(default_factory=dict)
    records: list[ParsedRecord] = field(default_factory=list)
    timeline: SuperTimeline = field(default_factory=SuperTimeline)


class IngestionPipeline:
    """Executes the extraction, parsing, and timeline generation pipeline."""

    def __init__(
        self,
        archive_path: Path | str,
        output_dir: Path | str,
        progress_callback: Callable[[float, str], None] | None = None,
    ) -> None:
        """Initialize the pipeline with source archive and destination folder."""
        self.archive_path = Path(archive_path)
        self.output_dir = Path(output_dir)
        self.progress_callback = progress_callback
        self.parsers = get_default_parsers()

    def run(self) -> PipelineResult:
        """Execute the ingestion pipeline."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        parsed_dir = self.output_dir / "parsed"
        timeline_dir = self.output_dir / "timeline"
        parsed_dir.mkdir(exist_ok=True)
        timeline_dir.mkdir(exist_ok=True)

        with EvidenceArchive(self.archive_path) as archive:
            hostname = archive.hostname
            target_os = archive.target_os

            result = PipelineResult(
                archive_path=self.archive_path,
                output_dir=self.output_dir,
                hostname=hostname,
                target_os=target_os,
            )

            file_list = archive.list_files()
            total_files = len(file_list)
            records_by_type: dict[str, list[ParsedRecord]] = {}

            for idx, entry_name in enumerate(file_list):
                if self.progress_callback and total_files > 0:
                    pct = (idx / total_files) * 0.8
                    self.progress_callback(pct, f"Parsing {Path(entry_name).name}...")

                result.total_files_inspected += 1
                parser = find_parser(entry_name, self.parsers)
                if not parser:
                    continue

                try:
                    with archive.open_stream(entry_name) as stream:
                        for rec in parser.parse(stream, entry_name):
                            result.records.append(rec)
                            result.timeline.add_record(rec)
                            result.total_records_parsed += 1

                            t = rec.artefact_type
                            if t not in records_by_type:
                                records_by_type[t] = []
                            records_by_type[t].append(rec)
                            result.parsed_by_type[t] = result.parsed_by_type.get(t, 0) + 1
                except (ValueError, OSError, KeyError):
                    # Forensic parser isolation: an error in one file must not crash others
                    continue

            # Also add filesystem metadata timestamps (MACB) from the manifest
            for m_entry in archive.manifest:
                if m_entry.modified_utc:
                    result.timeline.add_record(
                        ParsedRecord(
                            artefact_type="FileSystem",
                            source_file=m_entry.source_path,
                            timestamp_utc=m_entry.modified_utc,
                            action="FileModified",
                            summary=f"File modified: {Path(m_entry.source_path).name}",
                            details={"size": m_entry.size, "sha256": m_entry.sha256},
                        )
                    )

            # Export parsed CSVs per artefact type
            if self.progress_callback:
                self.progress_callback(0.85, "Exporting parsed artefact tables...")

            for t, recs in records_by_type.items():
                csv_path = parsed_dir / f"{t.lower()}_records.csv"
                self._write_records_csv(csv_path, recs)

            # Build and sort super-timeline
            if self.progress_callback:
                self.progress_callback(0.95, "Sorting and finalizing super-timeline...")

            result.timeline.sort()
            result.timeline_event_count = result.timeline.count()

            with (timeline_dir / "super_timeline.csv").open("w", encoding="utf-8", newline="") as f:
                result.timeline.write_csv(f)

            with (timeline_dir / "super_timeline.json").open("w", encoding="utf-8") as f:
                result.timeline.write_json(f)

            if self.progress_callback:
                self.progress_callback(1.0, "Parsing and timeline generation complete.")

            return result

    def _write_records_csv(self, path: Path, recs: list[ParsedRecord]) -> None:
        """Write a list of parsed records to CSV."""
        if not recs:
            return

        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp_utc",
                "action",
                "summary",
                "user",
                "computer",
                "process_name",
                "source_file",
            ])
            for r in recs:
                writer.writerow([
                    r.timestamp_utc,
                    r.action,
                    r.summary,
                    r.user,
                    r.computer,
                    r.process_name,
                    r.source_file,
                ])
