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
        for enc in ("utf-8", "utf-16le", "latin-1"):
            try:
                text = raw_data.decode(enc)
                if text:
                    break
            except UnicodeDecodeError:
                continue

        line_num = 1
        for line in text.splitlines():
            line = line.strip()
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
