"""Linux shell history proprietary parser (bash and zsh).

Decodes bash timestamp comments (#<epoch>) and zsh extended history formats,
extracting interactive operator commands and execution timestamps.
"""

from __future__ import annotations

import datetime
import re
from collections.abc import Iterator
from typing import IO

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord

ZSH_HISTORY_RE = re.compile(r"^:\s*(\d+):\d+;(.*)$")


class ShellHistoryParser(BaseParser):
    """Parser for user bash and zsh command line history files."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file matches shell history naming."""
        p = file_path.lower()
        return "bash_history" in p or "zsh_history" in p or "history" in p

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse shell history stream."""
        pending_timestamp: str = ""
        user = "root" if "/root" in file_path else "user"
        if "/home/" in file_path:
            parts = file_path.split("/home/")[1].split("/")
            if parts:
                user = parts[0]

        for raw_line in stream:
            line = raw_line.decode("utf-8", errors="replace").strip()

            if not line:
                continue

            # Check for bash epoch timestamp line: #1729600000
            if line.startswith("#") and line[1:].isdigit() and len(line) >= 10:
                epoch_sec = int(line[1:])
                try:
                    dt = datetime.datetime.fromtimestamp(epoch_sec, tz=datetime.UTC)
                    pending_timestamp = dt.isoformat()
                except (ValueError, OSError):
                    pending_timestamp = ""
                continue

            # Check for zsh extended format: : 1729600000:0;command
            zsh_match = ZSH_HISTORY_RE.match(line)
            if zsh_match:
                epoch_sec = int(zsh_match.group(1))
                command = zsh_match.group(2)
                try:
                    dt = datetime.datetime.fromtimestamp(epoch_sec, tz=datetime.UTC)
                    timestamp_utc = dt.isoformat()
                except (ValueError, OSError):
                    timestamp_utc = ""
            else:
                command = line
                timestamp_utc = pending_timestamp
                pending_timestamp = ""

            yield ParsedRecord(
                artefact_type="ShellHistory",
                source_file=file_path,
                timestamp_utc=timestamp_utc,
                action="ShellCommand",
                summary=f"[{user}] {command}",
                user=user,
                details={"command": command},
            )
