"""Linux wtmp and btmp binary session record parser.

Decodes Linux 384-byte utmp/wtmp structures, extracting user logins,
logouts, remote hosts, and failed authentication attempts (btmp).
"""

from __future__ import annotations

import datetime
import struct
from collections.abc import Iterator
from typing import IO

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord

UTMP_RECORD_SIZE = 384

UT_TYPE_MAP = {
    1: "RunLevel",
    2: "BootTime",
    5: "InitProcess",
    6: "LoginProcess",
    7: "UserLogon",
    8: "UserLogout",
}


class WtmpParser(BaseParser):
    """Parser for Linux wtmp and btmp binary accounting records."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file matches wtmp or btmp naming."""
        p = file_path.lower()
        return "wtmp" in p or "btmp" in p

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Read 384-byte binary records and yield session events."""
        is_failed = "btmp" in file_path.lower()

        while chunk := stream.read(UTMP_RECORD_SIZE):
            if len(chunk) < UTMP_RECORD_SIZE:
                break

            ut_type = struct.unpack_from("<h", chunk, 0)[0]
            ut_pid = struct.unpack_from("<i", chunk, 4)[0]
            line_bytes = chunk[8:40]
            user_bytes = chunk[44:76]
            host_bytes = chunk[76:332]
            tv_sec = struct.unpack_from("<i", chunk, 340)[0]

            if tv_sec <= 0:
                continue

            try:
                dt = datetime.datetime.fromtimestamp(tv_sec, tz=datetime.UTC)
                timestamp_utc = dt.isoformat()
            except (ValueError, OSError):
                continue

            line = line_bytes.decode("latin1", errors="ignore").split("\x00")[0].strip()
            user = user_bytes.decode("latin1", errors="ignore").split("\x00")[0].strip()
            host = host_bytes.decode("latin1", errors="ignore").split("\x00")[0].strip()

            if is_failed:
                action = "FailedLogon"
                target_user = user or "unknown"
                target_tty = line or "tty"
                target_host = host or "local"
                summary = f"Failed logon for {target_user} on {target_tty} from {target_host}"
            else:
                action = UT_TYPE_MAP.get(ut_type, f"UtmpType_{ut_type}")
                summary = f"Session {action}: {user or 'system'} on {line}"
                if host:
                    summary += f" from {host}"

            # Only yield significant user sessions
            if ut_type in (7, 8, 2) or is_failed:
                yield ParsedRecord(
                    artefact_type="LoginAccounting",
                    source_file=file_path,
                    timestamp_utc=timestamp_utc,
                    action=action,
                    summary=summary,
                    user=user,
                    process_id=ut_pid if ut_pid > 0 else None,
                    details={
                        "ut_type": ut_type,
                        "line": line,
                        "remote_host": host,
                    },
                )
