"""Forensic super-timeline builder and normalizer.

Aggregates parsed events across all forensic artefacts (Event Logs, Registry,
Prefetch, Syslog, Web Browsers, Filesystem MACB) into a unified chronologically
sorted timeline in CSV and JSON formats.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from typing import IO

from waeaa_ingestor.parsers.base import ParsedRecord, TimelineEvent


class SuperTimeline:
    """Super-timeline container sorting and exporting events."""

    def __init__(self) -> None:
        """Create an empty timeline."""
        self._events: list[TimelineEvent] = []

    def add_event(self, event: TimelineEvent) -> None:
        """Add a timeline event."""
        if event.timestamp_utc:
            self._events.append(event)

    def add_record(self, rec: ParsedRecord) -> None:
        """Convert a ParsedRecord into a TimelineEvent and add it."""
        if rec.timestamp_utc:
            self.add_event(
                TimelineEvent(
                    timestamp_utc=rec.timestamp_utc,
                    artefact_type=rec.artefact_type,
                    source_file=rec.source_file,
                    action=rec.action,
                    summary=rec.summary,
                    user=rec.user,
                    computer=rec.computer,
                    details=rec.details,
                )
            )

    def sort(self) -> None:
        """Sort all events in ascending chronological order."""
        self._events.sort(key=lambda e: e.timestamp_utc)

    @property
    def events(self) -> list[TimelineEvent]:
        """Return the sorted list of timeline events."""
        return self._events

    def count(self) -> int:
        """Return total number of events."""
        return len(self._events)

    def write_csv(self, stream: IO[str]) -> None:
        """Export timeline to standard CSV format."""
        writer = csv.writer(stream)
        writer.writerow([
            "timestamp_utc",
            "artefact_type",
            "action",
            "summary",
            "user",
            "computer",
            "source_file",
            "details_json",
        ])

        for ev in self._events:
            writer.writerow([
                ev.timestamp_utc,
                ev.artefact_type,
                ev.action,
                ev.summary,
                ev.user,
                ev.computer,
                ev.source_file,
                json.dumps(ev.details, ensure_ascii=False) if ev.details else "",
            ])

    def write_json(self, stream: IO[str]) -> None:
        """Export timeline to JSON."""
        json.dump([asdict(e) for e in self._events], stream, indent=2, ensure_ascii=False)
