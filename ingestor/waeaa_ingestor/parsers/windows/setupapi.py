"""Windows SetupAPI device installation log proprietary parser.

Parses setupapi.dev*.log and setupapi.setup*.log to extract USB storage device insertions,
vendor IDs, product IDs, revision numbers, serial numbers, and installation timestamps
for unauthorized external storage device investigations.
"""

from __future__ import annotations

import datetime
import re
from collections.abc import Iterator
from typing import IO, Any

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord

# Format: >>>  [Device Install (DiShowUpdateDevice) - USB\VID_0781&PID_5583\123456789]
# Format: >>>  Section start 2024/02/06 14:22:10.123
SECTION_START_RE = re.compile(
    r"^>>>\s+\[(Device Install[^\-\]]*)\s*-\s*([^\]]+)\]", re.IGNORECASE
)
TIMESTAMP_RE = re.compile(
    r"^>>>\s+Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)", re.IGNORECASE
)
USB_ID_RE = re.compile(
    r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})(?:\\([^\s\]]+))?", re.IGNORECASE
)


class SetupApiParser(BaseParser):
    """Parser for Windows SetupAPI device installation logs (setupapi.dev*.log)."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file_path is a setupapi log."""
        lower = file_path.lower().replace("\\", "/")
        return "setupapi.dev" in lower or "setupapi.setup" in lower

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse SetupAPI stream and yield ParsedRecords."""
        content = stream.read()
        if not content:
            return

        # SetupAPI logs are typically UTF-16LE or UTF-8/ANSI
        text = ""
        for enc in ("utf-16le", "utf-8", "latin-1"):
            try:
                text = content.decode(enc)
                if "Section start" in text or "Device Install" in text:
                    break
            except UnicodeDecodeError:
                continue

        if not text:
            return

        current_device = ""
        current_section = ""
        current_time_iso = ""

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue

            sec_match = SECTION_START_RE.search(line)
            if sec_match:
                current_section = sec_match.group(1).strip()
                current_device = sec_match.group(2).strip()
                continue

            time_match = TIMESTAMP_RE.search(line)
            if time_match:
                raw_time = time_match.group(1).strip()
                try:
                    # Format: 2024/02/06 14:22:10.123
                    dt = datetime.datetime.strptime(
                        raw_time.split(".")[0], "%Y/%m/%d %H:%M:%S"
                    ).replace(tzinfo=datetime.UTC)
                    current_time_iso = dt.isoformat()
                except ValueError:
                    current_time_iso = ""

                if current_device:
                    vid = ""
                    pid = ""
                    serial = ""
                    usb_match = USB_ID_RE.search(current_device)
                    if usb_match:
                        vid = usb_match.group(1).upper()
                        pid = usb_match.group(2).upper()
                        serial = usb_match.group(3) or ""

                    details: dict[str, Any] = {
                        "device_id": current_device,
                        "section": current_section,
                        "vendor_id": vid,
                        "product_id": pid,
                        "serial_number": serial,
                        "raw_timestamp": raw_time,
                    }

                    summary = f"USB/Device Installation: '{current_device}'"
                    if vid and pid:
                        summary += f" (VID: {vid}, PID: {pid}"
                        if serial:
                            summary += f", Serial: {serial}"
                        summary += ")"

                    yield ParsedRecord(
                        artefact_type="USBDevice",
                        source_file=file_path,
                        timestamp_utc=current_time_iso,
                        action="UsbDeviceInstalled",
                        summary=summary,
                        user="",
                        computer="",
                        details=details,
                    )
                    current_device = ""
