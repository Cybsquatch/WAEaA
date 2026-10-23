"""Windows Event Log (.evtx) proprietary binary parser.

Decodes chunk-based EVTX structures, extracts event records, FileTime timestamps,
Event IDs, channels, providers, and BinXML event properties.
"""

from __future__ import annotations

import datetime
import re
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
        # Offset 48 in EVTX chunk header is next_record_offset (free space start)
        free_space_offset = struct.unpack_from("<I", chunk, 48)[0]
        max_offset = free_space_offset if 512 < free_space_offset <= len(chunk) else len(chunk)
        rec_offset = 512

        while rec_offset + 24 <= max_offset:
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

            # Extract event metadata from BinXML payload
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
        """Extract event fields from BinXML template instances and string tokens."""
        res: dict[str, Any] = {"event_data": {}}

        # 1. Attempt BinXML Template Instance parsing (token 0x0C)
        if len(payload) >= 22 and payload[4] == 0x0C:
            try:
                num_vals = struct.unpack_from("<I", payload, 14)[0]
                if 0 < num_vals < 500:
                    desc_off = 18
                    data_off = 18 + num_vals * 4
                    if data_off <= len(payload):
                        curr = data_off
                        vals: list[tuple[int, int, bytes]] = []
                        for i in range(num_vals):
                            v_size, v_type = struct.unpack_from("<HH", payload, desc_off + i * 4)
                            v_bytes = payload[curr : curr + v_size]
                            curr += v_size
                            vals.append((v_type, v_size, v_bytes))

                        str_idx = 0
                        for v_type, v_size, b in vals:
                            if v_type == 0x01 and v_size > 2:
                                s = b.decode("utf-16le", errors="ignore").rstrip("\x00")
                                if "Microsoft-Windows" in s or "Service Control Manager" in s:
                                    res["provider"] = s
                                elif s in {"Security", "System", "Application", "Setup"} or "Operational" in s:
                                    res["channel"] = s
                                elif "." in s and s.isupper() and "computer" not in res:
                                    res["computer"] = s
                                else:
                                    res["event_data"][f"param_{str_idx}"] = s
                                    str_idx += 1
                            elif v_type in (0x06, 0x08) and "event_id" not in res:
                                eid = struct.unpack_from("<H" if v_type == 0x06 else "<I", b)[0]
                                if 1 <= eid <= 65535:
                                    res["event_id"] = eid
                            elif v_type == 0x21 or v_size > 8:
                                # Embedded XML / BinXML fragment: search for printable strings
                                u_strs = re.findall(rb"(?:[\x20-\x7e]\x00){3,}", b)
                                for us in u_strs:
                                    s = us.decode("utf-16le", errors="ignore").rstrip("\x00")
                                    if s and len(s) > 2 and s not in res["event_data"].values():
                                        res["event_data"][f"param_{str_idx}"] = s
                                        str_idx += 1
            except Exception:
                pass

        # 2. Fallback heuristic: Extract text tokens if fields are missing
        if "event_id" not in res or not res.get("channel") or not res.get("provider"):
            u_strs = re.findall(rb"(?:[\x20-\x7e]\x00){3,}", payload)
            tokens = [us.decode("utf-16le", errors="ignore").rstrip("\x00") for us in u_strs]

            for token in tokens:
                if token.isdigit() and 1 <= int(token) <= 65535 and "event_id" not in res:
                    res["event_id"] = int(token)
                elif "Microsoft-Windows" in token and "provider" not in res:
                    res["provider"] = token
                elif token in {"Security", "System", "Application", "Setup"} and "channel" not in res:
                    res["channel"] = token
                elif "." in token and token.isupper() and "computer" not in res:
                    res["computer"] = token

        if "event_id" not in res:
            res["event_id"] = 0

        return res
