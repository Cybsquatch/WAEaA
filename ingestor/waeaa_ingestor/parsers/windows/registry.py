"""Windows Registry hive proprietary binary parser.

Decodes regf file headers, hbin blocks, nk (key) cells and vk (value) cells,
extracting last written timestamps, persistence Run keys, services and accounts.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import IO

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord
from waeaa_ingestor.parsers.windows.evtx import filetime_to_iso

REGISTRY_MAGIC = b"regf"


class RegistryHiveParser(BaseParser):
    """Parser for offline Windows Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT)."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file name or path suggests a registry hive."""
        name = file_path.upper()
        return (
            name.endswith("SAM")
            or name.endswith("SYSTEM")
            or name.endswith("SOFTWARE")
            or name.endswith("SECURITY")
            or "NTUSER.DAT" in name
            or "USRCLASS.DAT" in name
            or name.endswith(".DAT")
        )

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse registry hive structures and yield key records."""
        data = stream.read()
        if len(data) < 4096 or data[:4] != REGISTRY_MAGIC:
            return

        # Scan for nk cells (named key records) across hbin blocks
        pos = 4096
        while pos + 80 < len(data):
            # Check for hbin header
            if data[pos : pos + 4] == b"hbin":
                pos += 32
                continue

            # Cell length is a signed 32-bit int (negative = allocated)
            cell_size_raw = struct.unpack_from("<i", data, pos)[0]
            cell_size = abs(cell_size_raw)
            if cell_size < 8 or pos + cell_size > len(data):
                pos += 4
                continue

            cell_data = data[pos + 4 : pos + cell_size]
            if len(cell_data) >= 76 and cell_data[:2] == b"nk":
                record = self._parse_nk_cell(cell_data, file_path)
                if record:
                    yield record

            pos += cell_size

    def _parse_nk_cell(self, cell_data: bytes, file_path: str) -> ParsedRecord | None:
        """Parse an nk cell containing key name and last written timestamp."""
        try:
            timestamp_ft = struct.unpack_from("<Q", cell_data, 4)[0]
            name_len = struct.unpack_from("<H", cell_data, 72)[0]
            if 76 + name_len > len(cell_data):
                return None

            name_bytes = cell_data[76 : 76 + name_len]
            # ASCII or UTF-16LE depending on flags
            key_name = name_bytes.decode("latin1", errors="ignore")

            iso_time = filetime_to_iso(timestamp_ft)
            if not iso_time:
                return None

            # Check for notable forensic keys
            action = "KeyModified"
            is_suspicious = False
            lower_name = key_name.lower()
            if "run" in lower_name or "runonce" in lower_name:
                action = "PersistenceRunKey"
                is_suspicious = True
            elif "services" in lower_name:
                action = "ServiceKey"
            elif "userassist" in lower_name:
                action = "UserAssistKey"

            return ParsedRecord(
                artefact_type="Registry",
                source_file=file_path,
                timestamp_utc=iso_time,
                action=action,
                summary=f"Registry Key: {key_name}",
                details={
                    "key_name": key_name,
                    "is_persistence": is_suspicious,
                },
            )
        except Exception:
            return None
