"""Linux cron and scheduled job proprietary parser.

Parses system crontabs (/etc/crontab, /etc/cron.*) and user spools (/var/spool/cron),
extracting persistent scheduled commands, users, and execution frequencies.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import IO

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord


class CronParser(BaseParser):
    """Parser for Linux cron tables and scheduled tasks."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file matches cron patterns."""
        p = file_path.lower()
        return "cron" in p or "anacron" in p or "atjobs" in p

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse cron lines."""
        for raw_line in stream:
            line = raw_line.decode("utf-8", errors="replace").strip()

            if not line or line.startswith("#"):
                continue

            parts = re.split(r"\s+", line)
            if len(parts) < 6:
                continue

            # Standard crontab has 5 time fields + user + command
            if len(parts) >= 7 and not parts[0].startswith("@"):
                schedule = " ".join(parts[:5])
                user = parts[5]
                command = " ".join(parts[6:])
            else:
                schedule = parts[0]
                user = "root"
                command = " ".join(parts[1:])

            summary = f"Cron Job [{user}]: {command} ({schedule})"
            yield ParsedRecord(
                artefact_type="CronJob",
                source_file=file_path,
                timestamp_utc="",  # Cron entries are scheduled expressions
                action="ScheduledPersistence",
                summary=summary,
                user=user,
                details={
                    "schedule": schedule,
                    "command": command,
                },
            )
