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

# Ignored path components that should never be matched as shell history
_IGNORED_PATH_FRAGMENTS = ("defender", "browser", "terminal server", "quick", "scans", "results")

# Exact shell history base filenames
_VALID_FILENAMES = {
    ".bash_history",
    "bash_history",
    ".zsh_history",
    "zsh_history",
    ".sh_history",
    "sh_history",
    ".ash_history",
    "ash_history",
    ".history",
    "history.txt",
}


class ShellHistoryParser(BaseParser):
    """Parser for user bash and zsh command line history files."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file matches shell history naming."""
        lower = file_path.lower().replace("\\", "/")
        if any(ignored in lower for ignored in _IGNORED_PATH_FRAGMENTS):
            return False

        filename = lower.rsplit("/", 1)[-1]
        if filename in _VALID_FILENAMES:
            return True
        return filename.startswith((".bash_history", ".zsh_history", ".sh_history"))

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse shell history stream."""
        raw_data = stream.read()
        if not raw_data:
            return

        # Skip binary files containing NULL bytes in header
        if b"\x00" in raw_data[:2048]:
            return

        # Multi-encoding support: UTF-8 with BOM, UTF-8, Latin-1, CP1252
        text = ""
        for enc in ("utf-8-sig", "utf-8", "latin-1", "cp1252"):
            try:
                text = raw_data.decode(enc)
                break
            except UnicodeDecodeError:
                continue

        if not text:
            text = raw_data.decode("utf-8", errors="replace")

        pending_timestamp: str = ""
        normalized_path = file_path.replace("\\", "/")
        user = "root" if "/root" in normalized_path else "user"
        if "/home/" in normalized_path:
            parts = normalized_path.split("/home/")[1].split("/")
            if parts:
                user = parts[0]

        for raw_line in text.splitlines():
            line = raw_line.strip()
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
