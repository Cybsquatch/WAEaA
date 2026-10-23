"""NTFS Master File Table ($MFT) proprietary binary parser.

Parses 1024-byte MFT file records, decodes Fixup / Update Sequence Arrays,
extracts $STANDARD_INFORMATION (0x10) and $FILE_NAME (0x30) attributes,
reconstructs file names, MACB timestamps, file sizes, directory flags,
and identifies deleted or wiped files for forensic timeline analysis.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from typing import IO, Any

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord
from waeaa_ingestor.parsers.windows.evtx import filetime_to_iso

MFT_RECORD_MAGIC = b"FILE"
MFT_RECORD_SIZE = 1024

# NTFS Attribute Types
ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END = 0xFFFFFFFF


def _apply_fixup(record_bytes: bytearray) -> bool:
    """Apply NTFS fixup array to restore sector ends."""
    if len(record_bytes) < MFT_RECORD_SIZE:
        return False
    try:
        usa_offset = struct.unpack_from("<H", record_bytes, 0x14)[0]
        usa_count = struct.unpack_from("<H", record_bytes, 0x16)[0]
        if usa_offset + usa_count * 2 > len(record_bytes) or usa_count < 2:
            return False

        usn = record_bytes[usa_offset : usa_offset + 2]
        sector_size = 512
        for i in range(1, usa_count):
            sector_end = i * sector_size - 2
            if sector_end + 2 > len(record_bytes):
                break
            # If sector end matches USN, replace with fixup byte
            if record_bytes[sector_end : sector_end + 2] == usn:
                fixup_val = record_bytes[usa_offset + i * 2 : usa_offset + i * 2 + 2]
                record_bytes[sector_end : sector_end + 2] = fixup_val
        return True
    except Exception:
        return False


class MftParser(BaseParser):
    """Forensic parser for NTFS $MFT binary files."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file_path is an $MFT artefact."""
        lower = file_path.lower().replace("\\", "/")
        return lower.endswith("$mft") or "/$mft" in lower or lower == "$mft"

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse MFT records from stream and yield ParsedRecords."""
        record_idx = 0
        while True:
            raw_chunk = stream.read(MFT_RECORD_SIZE)
            if len(raw_chunk) < MFT_RECORD_SIZE:
                break

            record_bytes = bytearray(raw_chunk)
            magic = bytes(record_bytes[:4])
            if magic != MFT_RECORD_MAGIC:
                record_idx += 1
                continue

            _apply_fixup(record_bytes)

            flags = struct.unpack_from("<H", record_bytes, 0x16)[0]
            in_use = bool(flags & 0x01)
            is_dir = bool(flags & 0x02)

            first_attr_offset = struct.unpack_from("<H", record_bytes, 0x14)[0]
            attr_offset = struct.unpack_from("<H", record_bytes, 0x14)[0] if first_attr_offset > 0x30 else 0x38

            # Scan attributes
            si_created_iso = ""
            si_modified_iso = ""
            si_mft_iso = ""
            si_access_iso = ""

            fn_name = ""
            fn_size = 0
            fn_parent_ref = 0
            fn_modified_iso = ""
            fn_created_iso = ""

            curr = attr_offset
            while curr + 8 <= len(record_bytes):
                attr_type = struct.unpack_from("<I", record_bytes, curr)[0]
                if attr_type == ATTR_END or attr_type == 0:
                    break

                attr_len = struct.unpack_from("<I", record_bytes, curr + 4)[0]
                if attr_len < 16 or curr + attr_len > len(record_bytes):
                    break

                non_resident = record_bytes[curr + 8] != 0
                if not non_resident:
                    content_offset = struct.unpack_from("<H", record_bytes, curr + 20)[0]
                    content_len = struct.unpack_from("<I", record_bytes, curr + 16)[0]
                    content_start = curr + content_offset
                    content = record_bytes[content_start : content_start + content_len]

                    if attr_type == ATTR_STANDARD_INFORMATION and len(content) >= 32:
                        cr_ft = struct.unpack_from("<Q", content, 0)[0]
                        mod_ft = struct.unpack_from("<Q", content, 8)[0]
                        mft_ft = struct.unpack_from("<Q", content, 16)[0]
                        acc_ft = struct.unpack_from("<Q", content, 24)[0]
                        si_created_iso = filetime_to_iso(cr_ft)
                        si_modified_iso = filetime_to_iso(mod_ft)
                        si_mft_iso = filetime_to_iso(mft_ft)
                        si_access_iso = filetime_to_iso(acc_ft)

                    elif attr_type == ATTR_FILE_NAME and len(content) >= 66:
                        # Parent dir ref (6 bytes entry + 2 bytes seq)
                        fn_parent_ref = struct.unpack_from("<Q", content, 0)[0] & 0x0000FFFFFFFFFFFF
                        fn_cr_ft = struct.unpack_from("<Q", content, 8)[0]
                        fn_mod_ft = struct.unpack_from("<Q", content, 16)[0]
                        fn_alloc_size = struct.unpack_from("<Q", content, 40)[0]
                        fn_real_size = struct.unpack_from("<Q", content, 48)[0]
                        name_len = content[64]
                        namespace = content[65]

                        # Favor Win32 / POSIX namespace (0, 1, 3) over DOS 8.3 (2)
                        if name_len > 0 and len(content) >= 66 + name_len * 2:
                            name_str = content[66 : 66 + name_len * 2].decode("utf-16le", errors="ignore")
                            if namespace != 2 or not fn_name:
                                fn_name = name_str
                                fn_size = fn_real_size or fn_alloc_size
                                fn_created_iso = filetime_to_iso(fn_cr_ft)
                                fn_modified_iso = filetime_to_iso(fn_mod_ft)

                curr += attr_len

            if fn_name and not fn_name.startswith("$"):
                action = "FileActive" if in_use else "FileDeleted"
                status_desc = "Directory" if is_dir else "File"
                deleted_flag = "" if in_use else " [DELETED]"

                timestamp = si_modified_iso or fn_modified_iso or si_created_iso

                details: dict[str, Any] = {
                    "record_index": record_idx,
                    "filename": fn_name,
                    "is_directory": is_dir,
                    "is_active": in_use,
                    "file_size": fn_size,
                    "parent_record": fn_parent_ref,
                    "created_utc": si_created_iso or fn_created_iso,
                    "modified_utc": si_modified_iso or fn_modified_iso,
                    "mft_changed_utc": si_mft_iso,
                    "accessed_utc": si_access_iso,
                }

                summary = (
                    f"MFT {status_desc}: '{fn_name}'{deleted_flag} "
                    f"(Size: {fn_size:,} bytes, Record: {record_idx})"
                )

                yield ParsedRecord(
                    artefact_type="MFT",
                    source_file=file_path,
                    timestamp_utc=timestamp,
                    action=action,
                    summary=summary,
                    user="",
                    computer="",
                    details=details,
                )

            record_idx += 1
