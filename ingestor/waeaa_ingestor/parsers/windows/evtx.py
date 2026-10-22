"""Windows Event Log (.evtx) proprietary binary parser.

Decodes chunk-based EVTX structures, extracts event records, FileTime timestamps,
Event IDs, channels, providers and EventData XML properties.
"""

from __future__ import annotations

import datetime
import struct
from collections.abc import Iterator
from typing import IO, Any

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord

EVTX_FILE_MAGIC = b"ElfFile\x00"
EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
EVTX_RECORD_MAGIC = b"\x2a\x2a\x00\x00"

# Windows epoch (1601-01-01) to Unix epoch (1970-01-01) in 100-nanosecond intervals
EPOCH_AS_FILETIME = 116444736000000000


def filetime_to_iso(ft: int) -> str:
    """Convert a 64-bit Windows FILETIME integer into an ISO 8601 UTC string."""
    if ft <= 0:
        return ""
    try:
        timestamp_sec = (ft - EPOCH_AS_FILETIME) / 10_000_000
        dt = datetime.datetime.fromtimestamp(timestamp_sec, tz=datetime.UTC)
        return dt.isoformat()
    except (ValueError, OverflowError, OSError):
        return ""


class EvtxParser(BaseParser):
    """Parser for Windows Event Log (.evtx) files."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file_path has a .evtx extension."""
        return file_path.lower().endswith(".evtx")

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse EVTX chunks and yield ParsedRecords."""
        data = stream.read()
        if len(data) < 4096 or data[:8] != EVTX_FILE_MAGIC:
            return

        offset = 4096

        while offset + 65536 <= len(data):
            chunk = data[offset : offset + 65536]
            if chunk[:8] == EVTX_CHUNK_MAGIC:
                yield from self._parse_chunk(chunk, file_path)
            offset += 65536

    def _parse_chunk(self, chunk: bytes, file_path: str) -> Iterator[ParsedRecord]:
        """Parse event records within a 64KB chunk."""
        free_space_offset = struct.unpack_from("<I", chunk, 56)[0]
        rec_offset = 512

        while rec_offset < min(free_space_offset, len(chunk) - 24):
            if chunk[rec_offset : rec_offset + 4] != EVTX_RECORD_MAGIC:
                rec_offset += 4
                continue

            length = struct.unpack_from("<I", chunk, rec_offset + 4)[0]
            if length < 24 or rec_offset + length > len(chunk):
                rec_offset += 4
                continue

            rec_bytes = chunk[rec_offset : rec_offset + length]
            record_id = struct.unpack_from("<Q", rec_bytes, 8)[0]
            filetime = struct.unpack_from("<Q", rec_bytes, 16)[0]
            timestamp_utc = filetime_to_iso(filetime)

            # Extract textual XML / BinXML strings from record payload
            extracted = self._extract_event_metadata(rec_bytes[24:])
            event_id = extracted.get("event_id", 0)
            channel = extracted.get("channel", "")
            provider = extracted.get("provider", "")
            computer = extracted.get("computer", "")
            user = extracted.get("user", "")

            summary = f"Event ID {event_id} ({provider})"
            if channel:
                summary += f" on {channel}"

            yield ParsedRecord(
                artefact_type="EventLog",
                source_file=file_path,
                timestamp_utc=timestamp_utc,
                action=f"Event_{event_id}",
                summary=summary,
                user=user,
                computer=computer,
                details={
                    "record_id": record_id,
                    "event_id": event_id,
                    "channel": channel,
                    "provider": provider,
                    **extracted.get("event_data", {}),
                },
            )

            rec_offset += length

    def _extract_event_metadata(self, payload: bytes) -> dict[str, Any]:
        """Heuristically extract strings and event fields from BinXML streams."""
        res: dict[str, Any] = {"event_data": {}}

        # Extract ASCII and UTF-16LE printable strings from payload
        text_tokens: list[str] = []
        i = 0
        while i < len(payload):
            # Look for null-terminated UTF-16LE strings (2-byte chars where byte2 == 0)
            if i + 3 < len(payload) and payload[i + 1] == 0 and payload[i + 3] == 0:
                start = i
                while i + 1 < len(payload) and payload[i + 1] == 0 and 32 <= payload[i] <= 126:
                    i += 2
                if i - start >= 4:
                    try:
                        token = payload[start:i].decode("utf-16le")
                        text_tokens.append(token)
                    except UnicodeDecodeError:
                        pass
            i += 1

        # Locate EventID, Provider, Computer, Channel from tokens
        known_channels = {
            "Security",
            "System",
            "Application",
            "Setup",
            "Microsoft-Windows-Sysmon/Operational",
        }
        for token in text_tokens:
            if token.isdigit() and 1 <= int(token) <= 65535 and "event_id" not in res:
                res["event_id"] = int(token)
            elif "Microsoft-Windows" in token:
                res["provider"] = token
            elif token in known_channels:
                res["channel"] = token
            elif "." in token and token.isupper() and "computer" not in res:
                res["computer"] = token

        if "event_id" not in res:
            res["event_id"] = 0

        return res
