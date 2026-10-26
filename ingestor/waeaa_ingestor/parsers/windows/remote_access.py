"""Windows Remote Access and RMM (Remote Monitoring and Management) software log parser.

Parses configuration, connection traces, and session logs from AnyDesk, Atera,
TeamViewer, ScreenConnect, RustDesk, Splashtop, and VNC utilities commonly utilized
for unauthorized remote persistence, command staging, or lateral movement.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import IO, Any

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord

# AnyDesk connection_trace.txt regex:
# e.g.: 2024-03-12 10:15:33 incoming 987654321 remote_user local_admin 198.51.100.25:49152
ANYDESK_TRACE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(incoming|outgoing|\-\->|<\-\-)\s+(\d+)\s+([^\s]+)\s+([^\s]+)(?:\s+([0-9a-fA-F\.\:]+))?"
)

# TeamViewer Connections_incoming.txt format:
# ID  Start Date  Start Time  End Date  End Time  User  Type  UUID
TV_INCOMING_RE = re.compile(
    r"^(\d+)\s+(\d{2}-\d{2}-\d{4})\s+(\d{2}:\d{2}:\d{2})\s+(\d{2}-\d{2}-\d{4})\s+(\d{2}:\d{2}:\d{2})\s+(.*?)\s+([^\s]+)\s+([\{\}a-fA-F0-9\-]+)"
)

# Atera log timestamp: [YYYY-MM-DD HH:MM:SS] or YYYY-MM-DD HH:MM:SS
ATERA_TS_RE = re.compile(r"^\[?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]?")


class RemoteAccessParser(BaseParser):
    """Proprietary zero-dependency parser for Remote Access & RMM tools."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file_path matches known remote access / RMM software artifacts."""
        lower = file_path.lower().replace("\\", "/")
        filename = Path(lower).name

        # AnyDesk
        if "anydesk" in lower and (
            filename in ("connection_trace.txt", "system.conf", "user.conf")
            or filename.endswith(".trace")
            or ("chat" in lower and filename.endswith(".txt"))
        ):
            return True

        # TeamViewer
        if "teamviewer" in lower and (filename == "connections_incoming.txt" or filename.endswith(".log")):
            return True

        # Atera Networks
        if ("atera networks" in lower or "ateraagent" in lower) and filename.endswith((".log", ".txt", ".cfg", ".ini")):
            return True

        # ConnectWise / ScreenConnect
        if "screenconnect" in lower and filename.endswith((".log", ".xml", ".config")):
            return True

        # RustDesk
        if "rustdesk" in lower and filename.endswith((".log", ".toml", ".json")):
            return True

        # Splashtop
        if "splashtop" in lower and filename.endswith((".log", ".txt")):
            return True

        # UltraVNC / TightVNC / RealVNC
        return bool(("ultravnc" in lower or "tightvnc" in lower or "realvnc" in lower) and filename.endswith((".log", ".ini")))

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse remote access stream and yield ParsedRecords."""
        raw_data = stream.read()
        if not raw_data:
            return

        text = raw_data.decode("utf-8", errors="replace")
        lower = file_path.lower().replace("\\", "/")
        filename = Path(lower).name

        if "anydesk" in lower or filename in ("connection_trace.txt", "system.conf", "user.conf") or filename.endswith(".trace"):
            yield from self._parse_anydesk(text, filename, file_path)
        elif "teamviewer" in lower or filename == "connections_incoming.txt":
            yield from self._parse_teamviewer(text, filename, file_path)
        elif "atera" in lower or "ateraagent" in lower:
            yield from self._parse_atera(text, filename, file_path)
        elif "screenconnect" in lower:
            yield from self._parse_screenconnect(text, filename, file_path)
        elif "rustdesk" in lower:
            yield from self._parse_rustdesk(text, filename, file_path)
        else:
            yield from self._parse_generic_vnc(text, filename, file_path)

    def _parse_anydesk(self, text: str, filename: str, file_path: str) -> Iterator[ParsedRecord]:
        """Parse AnyDesk configuration, connection_trace and .trace logs."""
        if filename == "connection_trace.txt":
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                match = ANYDESK_TRACE_RE.match(line)
                if match:
                    ts_str, direction, remote_id, alias, username, endpoint = match.groups()
                    iso_ts = ts_str.replace(" ", "T") + "Z"
                    dir_label = "Incoming" if "in" in direction.lower() or "<" in direction else "Outgoing"
                    ip_addr = ""
                    port = ""
                    if endpoint:
                        if ":" in endpoint:
                            ip_addr, port = endpoint.split(":", 1)
                        else:
                            ip_addr = endpoint

                    details: dict[str, Any] = {
                        "software": "AnyDesk",
                        "direction": dir_label,
                        "remote_anydesk_id": remote_id,
                        "alias": alias,
                        "username": username,
                        "endpoint": endpoint or "",
                        "ip_address": ip_addr,
                        "port": port,
                    }

                    summary = (
                        f"AnyDesk {dir_label} Session: ID {remote_id} ({alias}) "
                        f"User '{username}'" + (f" from {ip_addr}" if ip_addr else "")
                    )

                    yield ParsedRecord(
                        artefact_type="RemoteAccess",
                        source_file=file_path,
                        timestamp_utc=iso_ts,
                        action=f"AnyDesk{dir_label}Session",
                        summary=summary,
                        user=username,
                        computer="",
                        details=details,
                    )
        elif filename.endswith(".trace"):
            # Parse ad.trace / ad_svc.trace session request entries
            for line in text.splitlines():
                line = line.strip()
                if not line or len(line) < 20:
                    continue
                if any(k in line.lower() for k in ("incoming session", "accepted", "logged in as", "connecting to", "session closed")):
                    parts = line.split(" ", 2)
                    iso_ts = ""
                    if len(parts) >= 2 and re.match(r"^\d{4}-\d{2}-\d{2}$", parts[0]):
                        iso_ts = f"{parts[0]}T{parts[1][:8]}Z"

                    summary = f"AnyDesk Activity: {line[:140]}"
                    yield ParsedRecord(
                        artefact_type="RemoteAccess",
                        source_file=file_path,
                        timestamp_utc=iso_ts,
                        action="AnyDeskActivity",
                        summary=summary,
                        user="",
                        computer="",
                        details={"software": "AnyDesk", "raw_line": line},
                    )
        elif filename in ("system.conf", "user.conf"):
            # Extract AnyDesk Client ID
            anynet_id = ""
            alias = ""
            for line in text.splitlines():
                if line.startswith("ad.anynet.id="):
                    anynet_id = line.split("=", 1)[1].strip()
                elif line.startswith("ad.anynet.alias="):
                    alias = line.split("=", 1)[1].strip()

            if anynet_id or alias:
                yield ParsedRecord(
                    artefact_type="RemoteAccess",
                    source_file=file_path,
                    timestamp_utc="",
                    action="AnyDeskConfiguration",
                    summary=f"AnyDesk Client Configured: ID {anynet_id} (Alias: '{alias}')",
                    user="",
                    computer="",
                    details={"software": "AnyDesk", "client_id": anynet_id, "alias": alias},
                )

    def _parse_teamviewer(self, text: str, filename: str, file_path: str) -> Iterator[ParsedRecord]:
        """Parse TeamViewer Connections_incoming.txt and Logfile.log."""
        if filename.lower() == "connections_incoming.txt":
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                match = TV_INCOMING_RE.match(line)
                if match:
                    tv_id, start_d, start_t, end_d, end_t, user_str, conn_type, uuid_str = match.groups()
                    # Convert DD-MM-YYYY to YYYY-MM-DD
                    d_parts = start_d.split("-")
                    iso_ts = f"{d_parts[2]}-{d_parts[1]}-{d_parts[0]}T{start_t}Z" if len(d_parts) == 3 else ""

                    details: dict[str, Any] = {
                        "software": "TeamViewer",
                        "remote_teamviewer_id": tv_id,
                        "user": user_str.strip(),
                        "connection_type": conn_type,
                        "session_uuid": uuid_str,
                    }
                    summary = f"TeamViewer Incoming Session: ID {tv_id} User '{user_str.strip()}' ({conn_type})"
                    yield ParsedRecord(
                        artefact_type="RemoteAccess",
                        source_file=file_path,
                        timestamp_utc=iso_ts,
                        action="TeamViewerIncomingSession",
                        summary=summary,
                        user=user_str.strip(),
                        computer="",
                        details=details,
                    )
        elif filename.lower().endswith(".log"):
            for line in text.splitlines():
                line = line.strip()
                if not line or len(line) < 20:
                    continue
                if any(k in line.lower() for k in ("connection established", "session started", "participant", "incoming connection")):
                    iso_ts = ""
                    ts_match = re.search(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})", line)
                    if ts_match:
                        iso_ts = ts_match.group(1).replace("/", "-").replace(" ", "T") + "Z"

                    summary = f"TeamViewer Activity: {line[:140]}"
                    yield ParsedRecord(
                        artefact_type="RemoteAccess",
                        source_file=file_path,
                        timestamp_utc=iso_ts,
                        action="TeamViewerActivity",
                        summary=summary,
                        user="",
                        computer="",
                        details={"software": "TeamViewer", "raw_line": line},
                    )

    def _parse_atera(self, text: str, filename: str, file_path: str) -> Iterator[ParsedRecord]:
        """Parse Atera RMM Agent execution and communication logs."""
        for line in text.splitlines():
            line = line.strip()
            if not line or len(line) < 20:
                continue

            # Check for significant RMM operations: script execution, commands, account connections
            if any(k in line.lower() for k in ("script", "powershell", "execute", "command", "customer", "agent started", "heartbeat")):
                iso_ts = ""
                m = ATERA_TS_RE.search(line)
                if m:
                    iso_ts = m.group(1).replace(" ", "T") + "Z"

                summary = f"Atera RMM Agent Event: {line[:140]}"
                yield ParsedRecord(
                    artefact_type="RemoteAccess",
                    source_file=file_path,
                    timestamp_utc=iso_ts,
                    action="AteraAgentActivity",
                    summary=summary,
                    user="",
                    computer="",
                    details={"software": "Atera", "raw_line": line},
                )

    def _parse_screenconnect(self, text: str, filename: str, file_path: str) -> Iterator[ParsedRecord]:
        """Parse ConnectWise ScreenConnect client logs."""
        for line in text.splitlines():
            line = line.strip()
            if not line or len(line) < 20:
                continue
            if any(k in line.lower() for k in ("relay", "connect", "session", "user", "channel")):
                iso_ts = ""
                m = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
                if m:
                    iso_ts = m.group(1).replace(" ", "T") + "Z"

                summary = f"ScreenConnect Remote Access: {line[:140]}"
                yield ParsedRecord(
                    artefact_type="RemoteAccess",
                    source_file=file_path,
                    timestamp_utc=iso_ts,
                    action="ScreenConnectActivity",
                    summary=summary,
                    user="",
                    computer="",
                    details={"software": "ScreenConnect", "raw_line": line},
                )

    def _parse_rustdesk(self, text: str, filename: str, file_path: str) -> Iterator[ParsedRecord]:
        """Parse RustDesk configuration and peer logs."""
        for line in text.splitlines():
            line = line.strip()
            if not line or len(line) < 20:
                continue
            if any(k in line.lower() for k in ("peer", "login", "connecting", "established", "relay")):
                iso_ts = ""
                m = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
                if m:
                    iso_ts = m.group(1).replace(" ", "T") + "Z"

                summary = f"RustDesk Remote Session: {line[:140]}"
                yield ParsedRecord(
                    artefact_type="RemoteAccess",
                    source_file=file_path,
                    timestamp_utc=iso_ts,
                    action="RustDeskActivity",
                    summary=summary,
                    user="",
                    computer="",
                    details={"software": "RustDesk", "raw_line": line},
                )

    def _parse_generic_vnc(self, text: str, filename: str, file_path: str) -> Iterator[ParsedRecord]:
        """Parse VNC connection logs."""
        for line in text.splitlines():
            line = line.strip()
            if not line or len(line) < 15:
                continue
            if any(k in line.lower() for k in ("connection from", "accepted connection", "client connected", "client disconnected")):
                iso_ts = ""
                m = re.search(r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
                if m:
                    iso_ts = m.group(1).replace(" ", "T") + "Z"

                summary = f"VNC Remote Connection: {line[:140]}"
                yield ParsedRecord(
                    artefact_type="RemoteAccess",
                    source_file=file_path,
                    timestamp_utc=iso_ts,
                    action="VncConnectionActivity",
                    summary=summary,
                    user="",
                    computer="",
                    details={"software": "VNC", "raw_line": line},
                )
