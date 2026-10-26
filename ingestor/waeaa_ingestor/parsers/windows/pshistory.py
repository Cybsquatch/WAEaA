"""PowerShell console history proprietary parser (PSReadLine).

Parses ConsoleHost_history.txt across user profiles, extracting interactive
operator command lines, downloads, and obfuscated execution traces.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import IO, Any

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord

USER_FROM_PATH_RE = re.compile(r"users[/\\]([^/\\]+)[/\\]appdata", re.IGNORECASE)


class PowerShellHistoryParser(BaseParser):
    """Parser for PowerShell PSReadLine console command history."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file_path is ConsoleHost_history.txt."""
        lower = file_path.lower().replace("\\", "/")
        return "consolehost_history" in lower

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse command history stream and yield ParsedRecords."""
        raw_data = stream.read()
        if not raw_data:
            return

        user = ""
        u_match = USER_FROM_PATH_RE.search(file_path)
        if u_match:
            user = u_match.group(1)

        text = ""
        # Multi-encoding support: BOM detection, UTF-16LE, UTF-8-sig, UTF-8, ANSI/CP1252
        if raw_data.startswith(b"\xff\xfe"):
            text = raw_data.decode("utf-16le", errors="replace")
        elif raw_data.startswith(b"\xfe\xff"):
            text = raw_data.decode("utf-16be", errors="replace")
        elif raw_data.startswith(b"\xef\xbb\xbf"):
            text = raw_data.decode("utf-8-sig", errors="replace")
        elif b"\x00" in raw_data[:512]:
            text = raw_data.decode("utf-16le", errors="replace")
        else:
            for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
                try:
                    text = raw_data.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            if not text:
                text = raw_data.decode("utf-8", errors="replace")

        line_num = 1
        for line in text.splitlines():
            line = line.strip().replace("\x00", "")
            if not line:
                continue

            details: dict[str, Any] = {
                "command": line,
                "line_number": line_num,
                "user": user,
            }

            summary = f"PowerShell Command: {line[:120]}"
            if user:
                summary = f"PowerShell [{user}]: {line[:110]}"

            yield ParsedRecord(
                artefact_type="PowerShellHistory",
                source_file=file_path,
                timestamp_utc="",
                action="PowerShellCommand",
                summary=summary,
                user=user,
                computer="",
                details=details,
            )
            line_num += 1
