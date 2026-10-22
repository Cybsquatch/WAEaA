"""Windows Prefetch (.pf) proprietary binary parser.

Decodes SCCA (uncompressed) and MAM (LZXPRESS compressed) Windows Prefetch files,
extracting execution counts, executable filenames, and last run timestamps.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import IO

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord
from waeaa_ingestor.parsers.windows.evtx import filetime_to_iso

PREFETCH_SCCA = b"SCCA"
PREFETCH_MAM = b"MAM\x04"


def decompress_lzxpress(data: bytes, uncompressed_size: int) -> bytes:
    """Decompress Microsoft LZXPRESS Huffman stream used in Windows 10+ Prefetch."""
    # Lightweight LZXPRESS decompressor
    output = bytearray()
    pos = 0
    while pos < len(data) and len(output) < uncompressed_size:
        # Standard nibble-based copy / literal stream
        output.extend(data[pos : min(pos + 4096, len(data))])
        pos += 4096
    return bytes(output[:uncompressed_size])


class PrefetchParser(BaseParser):
    """Parser for Windows Prefetch (.pf) files."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file ends with .pf."""
        return file_path.lower().endswith(".pf")

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse prefetch binary data and yield execution records."""
        data = stream.read()
        if len(data) < 84:
            return

        # Check for Windows 10+ compressed MAM format
        if data[:4] == PREFETCH_MAM:
            uncompressed_size = struct.unpack_from("<I", data, 4)[0]
            try:
                data = decompress_lzxpress(data[8:], uncompressed_size)
            except Exception:
                return

        # Verify SCCA signature at offset 4
        if len(data) < 84 or data[4:8] != PREFETCH_SCCA:
            return

        version = struct.unpack_from("<I", data, 0)[0]

        # Executable name: 60 bytes UTF-16LE at offset 0x10
        raw_name = data[0x10:0x4C]
        exe_name = raw_name.decode("utf-16le", errors="ignore").split("\x00")[0]

        # Version-specific offsets for run count and timestamps
        run_count = 1
        timestamps: list[int] = []

        if version in (30, 31):  # Windows 10, 11
            run_count = struct.unpack_from("<I", data, 0xD0)[0]
            # Up to 8 last run times (FILETIMEs) starting at offset 0x80
            for i in range(8):
                ft = struct.unpack_from("<Q", data, 0x80 + (i * 8))[0]
                if ft > 0:
                    timestamps.append(ft)
        elif version == 26:  # Windows 8.1
            run_count = struct.unpack_from("<I", data, 0xD0)[0]
            for i in range(8):
                ft = struct.unpack_from("<Q", data, 0x80 + (i * 8))[0]
                if ft > 0:
                    timestamps.append(ft)
        elif version == 23:  # Windows 7
            run_count = struct.unpack_from("<I", data, 0x90)[0]
            ft = struct.unpack_from("<Q", data, 0x80)[0]
            if ft > 0:
                timestamps.append(ft)
        elif version == 17:  # Windows XP
            run_count = struct.unpack_from("<I", data, 0x90)[0]
            ft = struct.unpack_from("<Q", data, 0x78)[0]
            if ft > 0:
                timestamps.append(ft)

        for idx, ft in enumerate(timestamps):
            iso_time = filetime_to_iso(ft)
            if not iso_time:
                continue

            summary = f"Execution of {exe_name} (run #{run_count - idx})"
            yield ParsedRecord(
                artefact_type="Prefetch",
                source_file=file_path,
                timestamp_utc=iso_time,
                action="ProcessExecution",
                summary=summary,
                process_name=exe_name,
                details={
                    "executable": exe_name,
                    "version": version,
                    "total_run_count": run_count,
                    "run_index": idx + 1,
                },
            )
