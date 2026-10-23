r"""Windows Error Reporting (WER) crash report proprietary parser.

Parses .wer files from %ProgramData%\\Microsoft\\Windows\\WER\\ReportArchive and ReportQueue
to extract application crashes, faulting modules, exception codes, process paths,
and incident timestamps for DFIR exploit and stability analysis.
"""

from __future__ import annotations

import datetime
from collections.abc import Iterator
from typing import IO, Any

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord


def _filetime_to_iso(ft_val: int) -> str:
    """Convert Windows 64-bit FILETIME (100-ns intervals since 1601-01-01) to ISO-8601 UTC string."""
    if ft_val <= 0:
        return ""
    try:
        epoch_diff = 116444736000000000
        if ft_val < epoch_diff:
            return ""
        us = (ft_val - epoch_diff) // 10
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.UTC) + datetime.timedelta(
            microseconds=us
        )
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


class WerParser(BaseParser):
    """Parser for Windows Error Reporting (.wer) files."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file_path is a Windows Error Reporting report."""
        lower = file_path.lower().replace("\\", "/")
        return lower.endswith(".wer") or "report.wer" in lower

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse WER file and yield ParsedRecords."""
        raw = stream.read()
        if not raw:
            return

        text = ""
        for enc in ("utf-16le", "utf-8", "latin-1"):
            try:
                decoded = raw.decode(enc)
                if "EventType=" in decoded or "ReportIdentifier=" in decoded or "Version=" in decoded:
                    text = decoded
                    break
            except UnicodeDecodeError:
                continue

        if not text:
            return

        metadata: dict[str, str] = {}
        sigs: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip()
            if k.startswith("Sig["):
                # E.g. Sig[0].Name or Sig[0].Value
                sigs[k] = v
            else:
                metadata[k] = v

        event_type = metadata.get("EventType", "UnknownCrash")
        app_name = metadata.get("AppName", "")
        app_path = metadata.get("AppPath", "")
        report_id = metadata.get("ReportIdentifier", "")

        # Look up indexed signatures (Sig[0] to Sig[9])
        fault_module = ""
        exception_code = ""
        sig_app_name = ""

        # Map Sig[i].Name -> Sig[i].Value
        sig_map: dict[str, str] = {}
        for i in range(15):
            name_key = f"Sig[{i}].Name"
            val_key = f"Sig[{i}].Value"
            if name_key in sigs and val_key in sigs:
                sig_map[sigs[name_key].lower()] = sigs[val_key]

        if "application name" in sig_map:
            sig_app_name = sig_map["application name"]
        if "fault module name" in sig_map:
            fault_module = sig_map["fault module name"]
        if "exception code" in sig_map:
            exception_code = sig_map["exception code"]

        final_app = app_name or sig_app_name or (app_path.split("\\")[-1] if app_path else "Unknown")

        # Convert EventTime if present
        timestamp_utc = ""
        event_time_str = metadata.get("EventTime", "")
        if event_time_str.isdigit():
            timestamp_utc = _filetime_to_iso(int(event_time_str))

        if not timestamp_utc:
            timestamp_utc = datetime.datetime.now(datetime.UTC).isoformat()

        summary_parts = [f"Application crash detected: {final_app} ({event_type})"]
        if fault_module:
            summary_parts.append(f"in module {fault_module}")
        if exception_code:
            summary_parts.append(f"code {exception_code}")

        details: dict[str, Any] = {
            "event_type": event_type,
            "application": final_app,
            "app_path": app_path,
            "fault_module": fault_module,
            "exception_code": exception_code,
            "report_id": report_id,
            "sig_map": sig_map,
        }

        yield ParsedRecord(
            artefact_type="wer_crash",
            source_file=file_path,
            timestamp_utc=timestamp_utc,
            action="PROCESS_CRASH",
            summary=" ".join(summary_parts),
            process_name=final_app,
            details=details,
        )
