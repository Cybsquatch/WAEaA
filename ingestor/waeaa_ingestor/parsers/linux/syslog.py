"""Linux syslog, auth.log and secure proprietary log parser.

Extracts authentication attempts (SSH, sudo, su, pam), daemon activities,
and translates syslog timestamps into normalized UTC ISO strings.
"""

from __future__ import annotations

import datetime
import re
from collections.abc import Iterator
from typing import IO

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord

# RFC 3164 Syslog: Oct 22 09:30:15 hostname daemon[pid]: message
SYSLOG_LINE_RE = re.compile(
    r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s+(.*)$"
)


class SyslogParser(BaseParser):
    """Parser for Linux text logs (auth.log, secure, syslog, messages)."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file matches Linux log names."""
        p = file_path.lower()
        return (
            p.endswith("auth.log")
            or "auth.log" in p
            or p.endswith("secure")
            or "secure" in p
            or p.endswith("syslog")
            or "syslog" in p
            or p.endswith("messages")
            or "messages" in p
        )

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse text log stream line by line."""
        current_year = datetime.datetime.now(datetime.UTC).year

        for raw_line in stream:
            line = raw_line.decode("utf-8", errors="replace").strip()

            if not line:
                continue

            match = SYSLOG_LINE_RE.match(line)
            if not match:
                continue

            date_str, host, daemon, pid_str, message = match.groups()

            # Parse timestamp: e.g. "Oct 22 09:30:15"
            try:
                dt = datetime.datetime.strptime(f"{current_year} {date_str}", "%Y %b %d %H:%M:%S")
                dt = dt.replace(tzinfo=datetime.UTC)
                timestamp_utc = dt.isoformat()
            except ValueError:
                timestamp_utc = ""

            action = f"{daemon}_event"
            user = ""
            details: dict[str, str] = {
                "daemon": daemon,
                "message": message,
            }
            if pid_str:
                details["pid"] = pid_str

            # Identify notable IR events
            lower_msg = message.lower()
            if "failed password" in lower_msg:
                action = "SSHFailedLogon"
                # Extract user
                if " for " in message:
                    user = message.split(" for ")[1].split(" from ")[0].replace("invalid user ", "")
            elif "accepted password" in lower_msg or "accepted publickey" in lower_msg:
                action = "SSHLogonSuccess"
                if " for " in message:
                    user = message.split(" for ")[1].split(" from ")[0]
            elif "sudo:" in line or daemon == "sudo":
                action = "SudoExecution"
                if " : TTY=" in message:
                    user = message.split(" : TTY=")[0].strip()

            yield ParsedRecord(
                artefact_type="Syslog",
                source_file=file_path,
                timestamp_utc=timestamp_utc,
                action=action,
                summary=f"[{daemon}] {message}",
                user=user,
                computer=host,
                process_name=daemon,
                process_id=int(pid_str) if pid_str else None,
                details=details,
            )
