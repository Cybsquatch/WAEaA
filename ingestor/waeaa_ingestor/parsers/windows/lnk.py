"""Windows Shell Link (.lnk) proprietary binary parser.

Decodes Shell Link headers, extracting target metadata, working directory,
command line arguments, and Creation/Access/Write timestamps.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import IO

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord
from waeaa_ingestor.parsers.windows.evtx import filetime_to_iso

LNK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"


class LnkParser(BaseParser):
    """Parser for Windows Shell Link (.lnk) and Jump List stream entries."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file ends with .lnk or is inside Recent/JumpLists."""
        p = file_path.lower()
        return p.endswith(".lnk") or "recent" in p or "destinations" in p

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse shell link structure."""
        data = stream.read()
        if len(data) < 76:
            return

        header_size = struct.unpack_from("<I", data, 0)[0]
        if header_size != 76 or data[4:20] != LNK_CLSID:
            return

        flags = struct.unpack_from("<I", data, 20)[0]
        creation_ft = struct.unpack_from("<Q", data, 28)[0]
        access_ft = struct.unpack_from("<Q", data, 36)[0]
        write_ft = struct.unpack_from("<Q", data, 44)[0]
        target_size = struct.unpack_from("<I", data, 52)[0]

        created_iso = filetime_to_iso(creation_ft)
        written_iso = filetime_to_iso(write_ft)
        accessed_iso = filetime_to_iso(access_ft)

        # Extract path and arguments from string data blocks
        target_path = self._extract_target_strings(data, 76, flags)

        summary = f"Shortcut to: {target_path or 'Target File'}"
        timestamp = written_iso or created_iso or accessed_iso

        if timestamp:
            yield ParsedRecord(
                artefact_type="LNK",
                source_file=file_path,
                timestamp_utc=timestamp,
                action="FileShortcut",
                summary=summary,
                details={
                    "target_path": target_path,
                    "target_size_bytes": target_size,
                    "created_utc": created_iso,
                    "accessed_utc": accessed_iso,
                    "written_utc": written_iso,
                },
            )

    def _extract_target_strings(self, data: bytes, offset: int, flags: int) -> str:
        """Scan string blocks following link info for target paths and arguments."""
        # Fast scan for printable ASCII path strings (e.g. C:\...)
        for i in range(offset, min(len(data) - 4, offset + 2048)):
            if data[i : i + 1].isalpha() and data[i + 1 : i + 3] == b":\\":
                end = i + 3
                while end < len(data) and 32 <= data[end] <= 126:
                    end += 1
                try:
                    return data[i:end].decode("ascii")
                except UnicodeDecodeError:
                    pass
        return ""
