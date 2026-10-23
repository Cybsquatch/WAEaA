"""Windows Event Log (.evtx) proprietary binary parser.

Decodes chunk-based EVTX structures, parses BinXML templates and substitution tables,
extracts first-class forensic metadata (Event IDs, Channels, Providers, Usernames,
Source/Destination IPs, Ports, Workstations, Logon Types, Processes, Commands, and Shares),
and performs high-fidelity forensic event enrichment for security investigations.
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

LOGON_TYPE_DESCRIPTIONS: dict[int, str] = {
    0: "0 (System)",
    2: "2 (Interactive)",
    3: "3 (Network)",
    4: "4 (Batch)",
    5: "5 (Service)",
    7: "7 (Unlock)",
    8: "8 (NetworkCleartext)",
    9: "9 (NewCredentials)",
    10: "10 (RemoteInteractive/RDP)",
    11: "11 (CachedInteractive)",
    12: "12 (CachedRemoteInteractive)",
    13: "13 (CachedUnlock)",
}

STATUS_DESCRIPTIONS: dict[int, str] = {
    0x0: "Success",
    0xC0000064: "User does not exist",
    0xC000006A: "Bad password",
    0xC000006D: "Bad username or auth info",
    0xC000006E: "User workstation restriction",
    0xC000006F: "Logon time restriction",
    0xC0000070: "Invalid Workstation",
    0xC0000071: "Password expired",
    0xC0000072: "Account disabled",
    0xC0000193: "Account expired",
    0xC0000224: "Password must change",
    0xC0000234: "Account locked out",
}

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


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


def _decode_binxml_val(v_type: int, v_size: int, vb: bytes) -> Any:
    """Decode a BinXML value based on its type token."""
    if v_size == 0 or not vb:
        return ""
    try:
        if v_type == 0x01:  # WString (UTF-16LE)
            return vb.decode("utf-16le", errors="ignore").rstrip("\x00")
        elif v_type == 0x02:  # AnsiString
            return vb.decode("latin-1", errors="ignore").rstrip("\x00")
        elif v_type in (0x03, 0x04):  # Int8 / UInt8
            return struct.unpack_from("<b" if v_type == 0x03 else "<B", vb)[0]
        elif v_type in (0x05, 0x06):  # Int16 / UInt16
            return struct.unpack_from("<h" if v_type == 0x05 else "<H", vb)[0]
        elif v_type in (0x07, 0x08):  # Int32 / UInt32
            return struct.unpack_from("<i" if v_type == 0x07 else "<I", vb)[0]
        elif v_type in (0x09, 0x0A):  # Int64 / UInt64
            return struct.unpack_from("<q" if v_type == 0x09 else "<Q", vb)[0]
        elif v_type == 0x0E:  # Boolean
            return struct.unpack_from("<I", vb)[0] != 0
        elif v_type == 0x0F and len(vb) >= 16:  # GUID
            d1, d2, d3 = struct.unpack_from("<IHH", vb)
            return f"{d1:08x}-{d2:04x}-{d3:04x}-{vb[8:10].hex()}-{vb[10:16].hex()}"
        elif v_type == 0x11 and len(vb) >= 8:  # FILETIME
            ft = struct.unpack_from("<Q", vb)[0]
            return filetime_to_iso(ft)
        elif v_type == 0x13 and len(vb) >= 8:  # SID
            rev = vb[0]
            num_auth = vb[1]
            id_auth = int.from_bytes(vb[2:8], "big")
            sub_count = min(num_auth, (len(vb) - 8) // 4)
            sub_auths = [struct.unpack_from("<I", vb, 8 + i * 4)[0] for i in range(sub_count)]
            return f"S-{rev}-{id_auth}" + ("-" + "-".join(str(s) for s in sub_auths) if sub_auths else "")
        elif v_type == 0x14 and len(vb) >= 4:  # Hex32
            return f"0x{struct.unpack_from('<I', vb)[0]:x}"
        elif v_type == 0x15 and len(vb) >= 8:  # Hex64
            return f"0x{struct.unpack_from('<Q', vb)[0]:x}"
    except (ValueError, struct.error, OSError, UnicodeDecodeError):
        pass

    # Heuristic fallback for strings
    if len(vb) >= 2 and len(vb) % 2 == 0:
        try:
            s = vb.decode("utf-16le").rstrip("\x00")
            if s.isprintable() and len(s) > 0:
                return s
        except UnicodeDecodeError:
            pass

    return ""


def _parse_template_definition(chunk: bytes, t_off: int) -> tuple[int, dict[int, str]]:
    """Parse a BinXML template definition and extract substitution index-to-name mapping."""
    if t_off + 24 > len(chunk):
        return 0, {}
    d_size = struct.unpack_from("<I", chunk, t_off + 20)[0]
    if d_size <= 0 or t_off + 24 + d_size > len(chunk):
        return 0, {}
    t_bytes = chunk[t_off + 24 : t_off + 24 + d_size]

    mapping: dict[int, str] = {}
    idx = 0
    t_len = len(t_bytes)
    while idx < t_len - 4:
        tok = t_bytes[idx]
        if tok in (0x0D, 0x0E):  # Substitution / Optional Substitution
            sub_id = struct.unpack_from("<H", t_bytes, idx + 1)[0]
            idx += 4
            if sub_id < 256:
                before = t_bytes[max(0, idx - 84) : idx - 4]
                names = re.findall(rb"(?:[\x20-\x7e]\x00){2,}", before)
                if names:
                    valid = [n.decode("utf-16le", errors="ignore").rstrip("\x00") for n in names]
                    tag = None
                    for v in reversed(valid):
                        if v not in (
                            "Data",
                            "xmlns",
                            "EventData",
                            "System",
                            "UserData",
                            "Event",
                            "http://schemas.microsoft.com/win/2004/08/events/event",
                        ):
                            tag = v
                            break
                    if tag:
                        mapping[sub_id] = tag
        else:
            idx += 1
    return d_size, mapping


def _parse_template_instance(
    chunk: bytes, start_in_chunk: int, tmpl_cache: dict[int, tuple[int, dict[int, str]]]
) -> tuple[list[tuple[int, int, bytes]] | None, dict[int, str], int]:
    """Parse a BinXML template instance (0x0C) and return (values, mapping, next_offset)."""
    if start_in_chunk + 10 > len(chunk) or chunk[start_in_chunk] != 0x0C:
        return None, {}, start_in_chunk

    tmpl_off = struct.unpack_from("<I", chunk, start_in_chunk + 6)[0]
    curr = start_in_chunk + 10

    if tmpl_off not in tmpl_cache:
        d_size, mapping = _parse_template_definition(chunk, tmpl_off)
        tmpl_cache[tmpl_off] = (d_size, mapping)
    else:
        d_size, mapping = tmpl_cache[tmpl_off]

    # If defined inline, advance past the template definition header (24 bytes) + data
    if tmpl_off == curr or tmpl_off == start_in_chunk + 6 or (start_in_chunk <= tmpl_off < start_in_chunk + 20):
        curr = tmpl_off + 24 + d_size

    if curr + 4 > len(chunk):
        return None, mapping, curr

    num_vals = struct.unpack_from("<I", chunk, curr)[0]
    if num_vals > 500:
        return None, mapping, curr

    curr += 4
    descs: list[tuple[int, int]] = []
    for _ in range(num_vals):
        if curr + 4 > len(chunk):
            return None, mapping, curr
        s, t = struct.unpack_from("<HH", chunk, curr)
        descs.append((s, t))
        curr += 4

    vals: list[tuple[int, int, bytes]] = []
    for s, t in descs:
        if curr + s > len(chunk):
            break
        vb = chunk[curr : curr + s]
        curr += s
        vals.append((t, s, vb))

    return vals, mapping, curr


class EvtxParser(BaseParser):
    """Forensic-grade parser for Windows Event Log (.evtx) files."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file_path has a .evtx extension."""
        return file_path.lower().endswith(".evtx")

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse EVTX chunks and yield forensic ParsedRecords."""
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
        """Parse event records within a 64KB chunk using template resolution and forensic enrichment."""
        free_space_offset = struct.unpack_from("<I", chunk, 48)[0]
        max_offset = free_space_offset if 512 < free_space_offset <= len(chunk) else len(chunk)
        rec_offset = 512

        tmpl_cache: dict[int, tuple[int, dict[int, str]]] = {}

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

            record = self._parse_record(chunk, rec_offset, length, record_id, timestamp_utc, file_path, tmpl_cache)
            if record:
                yield record

            rec_offset += length

    def _parse_record(
        self,
        chunk: bytes,
        rec_offset: int,
        length: int,
        record_id: int,
        timestamp_utc: str,
        file_path: str,
        tmpl_cache: dict[int, tuple[int, dict[int, str]]],
    ) -> ParsedRecord | None:
        """Parse a single EVTX record and perform forensic enrichment."""
        payload_start = rec_offset + 24
        payload = chunk[payload_start : rec_offset + length]

        # Locate root token (0x0F) and template instance (0x0C)
        inst_offset = payload_start
        while inst_offset < rec_offset + length and chunk[inst_offset] != 0x0C:
            inst_offset += 1

        event_id = 0
        provider = ""
        channel = ""
        computer = ""
        user_sid = ""
        event_data: dict[str, Any] = {}
        all_strings: list[str] = []

        if inst_offset + 10 <= rec_offset + length and chunk[inst_offset] == 0x0C:
            sys_vals, sys_map, sys_end = _parse_template_instance(chunk, inst_offset, tmpl_cache)
            if sys_vals:
                # System header fields
                if len(sys_vals) >= 4 and sys_vals[3][0] in (0x05, 0x06, 0x07, 0x08):
                    event_id = _decode_binxml_val(sys_vals[3][0], sys_vals[3][1], sys_vals[3][2])
                elif len(sys_vals) >= 3 and sys_vals[2][0] in (0x05, 0x06, 0x07, 0x08):
                    event_id = _decode_binxml_val(sys_vals[2][0], sys_vals[2][1], sys_vals[2][2])

                # Extract provider, channel, computer, SID from System values
                for vt, vs, vb in sys_vals:
                    val = _decode_binxml_val(vt, vs, vb)
                    if isinstance(val, str) and val:
                        all_strings.append(val)
                        if "Microsoft-Windows" in val or "Service Control Manager" in val or "PowerShell" in val:
                            if not provider:
                                provider = val
                        elif (
                            val in ("Security", "System", "Application", "Setup") or "Operational" in val
                        ) and not channel:
                            channel = val
                        elif "." in val and val.isupper() and not computer:
                            computer = val
                    elif vt == 0x13 and isinstance(val, str) and val.startswith("S-1-"):
                        if not user_sid or user_sid == "S-1-0-0":
                            user_sid = val

                # EventData / UserData: usually in sys_vals[17] (0x21) or any value with vt == 0x21
                for idx, (vt, _vs, vb) in enumerate(sys_vals):
                    if vt == 0x21 and len(vb) >= 10:
                        # Offset in chunk of this value
                        val_chunk_offset = (
                            sys_end - sum(s for _, s, _ in sys_vals[idx:]) if sys_end <= len(chunk) else None
                        )
                        if val_chunk_offset and val_chunk_offset + 10 <= len(chunk):
                            ud_vals, ud_map, _ = _parse_template_instance(chunk, val_chunk_offset, tmpl_cache)
                            if ud_vals:
                                for j, (nvt, nvs, nvb) in enumerate(ud_vals):
                                    dec_val = _decode_binxml_val(nvt, nvs, nvb)
                                    prop_name = ud_map.get(j, f"param_{j}")
                                    event_data[prop_name] = dec_val
                                    # Also keep param_j for legacy/rule compatibility
                                    event_data[f"param_{j}"] = dec_val
                                    if isinstance(dec_val, str) and dec_val:
                                        all_strings.append(dec_val)

        # Fallback / Supplemental heuristics if EventID or core fields are missing
        if event_id == 0 or not provider or not channel or not event_data:
            u_strs = re.findall(rb"(?:[\x20-\x7e]\x00){2,}", payload)
            tokens = [us.decode("utf-16le", errors="ignore").rstrip("\x00") for us in u_strs]
            for t in tokens:
                if t and t not in all_strings:
                    all_strings.append(t)
                if event_id == 0 and t.isdigit() and 1 <= int(t) <= 65535:
                    event_id = int(t)
                elif "Microsoft-Windows" in t and not provider:
                    provider = t
                elif t in ("Security", "System", "Application", "Setup") and not channel:
                    channel = t
                elif "." in t and t.isupper() and not computer:
                    computer = t

            if not event_data:
                for idx, t in enumerate(tokens):
                    event_data[f"param_{idx}"] = t

        return self._enrich_event(
            record_id=record_id,
            timestamp_utc=timestamp_utc,
            file_path=file_path,
            event_id=event_id,
            provider=provider,
            channel=channel,
            computer=computer,
            user_sid=user_sid,
            event_data=event_data,
            all_strings=all_strings,
        )

    def _enrich_event(
        self,
        record_id: int,
        timestamp_utc: str,
        file_path: str,
        event_id: int,
        provider: str,
        channel: str,
        computer: str,
        user_sid: str,
        event_data: dict[str, Any],
        all_strings: list[str],
    ) -> ParsedRecord:
        """Apply DFIR intelligence to normalize fields, extract IPs, users, and format executive summaries."""
        # 1. Normalize IP address
        ip_address = ""
        candidate_ip_keys = [
            "IpAddress",
            "ClientIP",
            "SourceAddress",
            "SourceNetworkAddress",
            "IPAddress",
            "IP",
            "param_3",  # Event 1149 Param3
            "param_5",  # Legacy 1149 param_5
            "param_18",  # Event 4624 IpAddress
        ]
        for k in candidate_ip_keys:
            val = str(event_data.get(k, "")).strip()
            if val and val not in ("-", "::1", "127.0.0.1", "0.0.0.0") and IPV4_PATTERN.match(val):  # noqa: S104
                ip_address = val
                break

        if not ip_address:
            # Fallback scan across all string tokens
            for s in all_strings:
                if s not in ("-", "::1", "127.0.0.1", "0.0.0.0"):  # noqa: S104
                    match = IPV4_PATTERN.search(s)
                    if match:
                        cand = match.group(0)
                        # Exclude version strings like 10.0.19041.1
                        if not any(v in s for v in ("version", "Version", ".dll", ".exe")):
                            ip_address = cand
                            break

        # 2. Normalize User and Domain
        user = ""
        domain = ""
        candidate_user_keys = [
            "TargetUserName",
            "SubjectUserName",
            "User",
            "AccountName",
            "MemberName",
            "param_0",  # Event 1149 Param1 or first param
            "param_1",
            "param_4",  # Legacy 1149 admin
            "param_5",  # Event 4624 TargetUserName
        ]
        for k in candidate_user_keys:
            val = str(event_data.get(k, "")).strip()
            if (
                val
                and val not in ("-", "ANONYMOUS LOGON", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
                and not val.startswith("S-1-")
                and not (len(val) == 36 and "-" in val)
            ):
                user = val
                break

        if not user:
            # Check for SYSTEM or machine accounts if no human user found
            for k in ["TargetUserName", "SubjectUserName", "User", "AccountName"]:
                val = str(event_data.get(k, "")).strip()
                if val and val != "-":
                    user = val
                    break

        candidate_domain_keys = ["TargetDomainName", "SubjectDomainName", "Domain", "param_1", "param_2", "param_6"]
        for k in candidate_domain_keys:
            val = str(event_data.get(k, "")).strip()
            if val and val not in ("-", "NT AUTHORITY") and not IPV4_PATTERN.match(val):
                domain = val
                break

        full_user = f"{domain}\\{user}" if domain and user and not user.startswith(f"{domain}\\") else user

        # 3. Normalize Workstation / Computer
        workstation = str(event_data.get("WorkstationName", event_data.get("Workstation", ""))).strip()
        if workstation == "-":
            workstation = ""
        if not computer and workstation:
            computer = workstation

        # 4. Normalize Logon Type
        logon_type_raw = event_data.get("LogonType")
        logon_type_desc = ""
        if logon_type_raw is not None:
            try:
                lt_int = int(logon_type_raw)
                logon_type_desc = LOGON_TYPE_DESCRIPTIONS.get(lt_int, f"{lt_int}")
            except (ValueError, TypeError):
                logon_type_desc = str(logon_type_raw)

        # 5. Normalize Process, Command Line, Service, Share
        process_name = str(
            event_data.get("NewProcessName", event_data.get("ProcessName", event_data.get("Image", "")))
        ).strip()
        command_line = str(event_data.get("CommandLine", "")).strip()
        service_name = str(event_data.get("ServiceName", "")).strip()
        image_path = str(event_data.get("ImagePath", "")).strip()
        share_name = str(event_data.get("ShareName", "")).strip()
        relative_target = str(event_data.get("RelativeTargetName", "")).strip()

        # Build details dictionary with promoted first-class fields
        details: dict[str, Any] = {
            "record_id": record_id,
            "event_id": event_id,
            "channel": channel,
            "provider": provider,
            **event_data,
        }
        if ip_address:
            details["ip_address"] = ip_address
        if user:
            details["user"] = user
        if domain:
            details["domain"] = domain
        if workstation:
            details["workstation"] = workstation
        if logon_type_desc:
            details["logon_type"] = logon_type_desc
        if process_name and process_name != "-":
            details["process_name"] = process_name
        if command_line:
            details["command_line"] = command_line
        if service_name:
            details["service_name"] = service_name
        if image_path:
            details["image_path"] = image_path
        if share_name:
            details["share_name"] = share_name
        if user_sid:
            details["user_sid"] = user_sid

        # 6. Generate forensic Action and Summary
        action = f"Event_{event_id}"
        summary = f"Event ID {event_id} ({provider})"
        if channel:
            summary += f" on {channel}"

        # Event-specific forensic enrichment
        if event_id == 1149:
            action = "RdpAuth_1149"
            user_disp = user or event_data.get("Param1", event_data.get("param_4", "Unknown"))
            src_disp = ip_address or event_data.get("Param3", event_data.get("param_5", "Unknown"))
            summary = f"RDP User Authentication Succeeded: user='{user_disp}' from source IP: {src_disp}"
            if not user and user_disp != "Unknown":
                user = str(user_disp)

        elif event_id == 21:
            action = "RdpSession_21"
            sess_id = event_data.get("SessionID", event_data.get("param_0", ""))
            summary = (
                f"RDP Session Logon Succeeded: user='{user}' from IP: {ip_address or 'Local'} (Session: {sess_id})"
            )

        elif event_id == 22:
            action = "RdpShell_22"
            summary = f"RDP Shell Started: user='{user}' from IP: {ip_address or 'Local'}"

        elif event_id == 24:
            action = "RdpDisconnect_24"
            sess_id = event_data.get("SessionID", event_data.get("param_0", ""))
            summary = f"RDP Session Disconnected: user='{user}' (Session: {sess_id})"

        elif event_id == 25:
            action = "RdpReconnect_25"
            sess_id = event_data.get("SessionID", event_data.get("param_0", ""))
            summary = (
                f"RDP Session Reconnected: user='{user}' from IP: {ip_address or 'Local'} (Session: {sess_id})"
            )

        elif event_id == 4624:
            action = "Logon_4624"
            src_part = f" from IP: {ip_address}" if ip_address else ""
            ws_part = f" (Workstation: {workstation})" if workstation else ""
            lt_part = f" via LogonType {logon_type_desc}" if logon_type_desc else ""
            summary = f"Successful Logon: user='{full_user or user or 'SYSTEM'}'{lt_part}{src_part}{ws_part}"

        elif event_id == 4625:
            action = "FailedLogon_4625"
            status_raw = event_data.get("Status", 0)
            status_code = 0
            if isinstance(status_raw, str) and status_raw.startswith("0x"):
                try:
                    status_code = int(status_raw, 16)
                except ValueError:
                    status_code = 0
            elif isinstance(status_raw, int):
                status_code = status_raw
            reason = STATUS_DESCRIPTIONS.get(status_code, f"Status: {status_raw}")
            src_part = f" from IP: {ip_address}" if ip_address else ""
            summary = f"Failed Logon: user='{full_user or user}'{src_part} (Reason: {reason})"

        elif event_id in (4688, 1):  # Security 4688 or Sysmon 1
            action = f"ProcessCreate_{event_id}"
            cli_part = f" | CLI: {command_line[:120]}" if command_line else ""
            user_part = f" | User: {user}" if user else ""
            summary = f"Process Created: {process_name or 'Process'}{cli_part}{user_part}"

        elif event_id == 4672:
            action = "SpecialPrivileges_4672"
            summary = f"Special Privileges Assigned to user='{full_user or user}'"

        elif event_id == 7045:
            action = "ServiceInstall_7045"
            svc_disp = service_name or event_data.get("param_0", "Unknown")
            bin_disp = image_path or event_data.get("param_1", "")
            summary = f"New Service Installed: '{svc_disp}' (Binary: {bin_disp})"

        elif event_id in (31010, 31001):
            action = f"SmbConnect_{event_id}"
            share_disp = share_name or event_data.get("param_0", "")
            summary = f"SMB Connection Established to '{share_disp}'"

        elif event_id == 5140:
            action = "ShareAccess_5140"
            src_part = f" from IP: {ip_address}" if ip_address else ""
            summary = f"Network Share Accessed: '{share_name}' by user='{user}'{src_part}"

        elif event_id == 5145:
            action = "ShareFileAccess_5145"
            target_disp = f"\\{relative_target}" if relative_target else ""
            src_part = f" from IP: {ip_address}" if ip_address else ""
            summary = f"Network Share File Checked: '{share_name}{target_disp}' by user='{user}'{src_part}"

        elif event_id in (1102, 104):
            action = "AuditLogCleared"
            summary = f"Event Log Cleared: '{channel or provider}' by user='{user or 'Unknown'}'"

        elif event_id == 4720:
            action = "UserCreated_4720"
            target_user = event_data.get("TargetUserName", "Unknown")
            summary = f"User Account Created: '{target_user}' by user='{user}'"

        elif event_id == 4726:
            action = "UserDeleted_4726"
            target_user = event_data.get("TargetUserName", "Unknown")
            summary = f"User Account Deleted: '{target_user}' by user='{user}'"

        elif event_id in (4728, 4732, 4756):
            action = f"GroupMemberAdd_{event_id}"
            member = event_data.get("MemberName", event_data.get("param_0", "Unknown"))
            target_grp = event_data.get("TargetUserName", "SecurityGroup")
            summary = f"Member '{member}' Added to Security Group '{target_grp}' by user='{user}'"

        elif event_id in (4768, 4769):
            action = f"KerberosTicket_{event_id}"
            svc = event_data.get("ServiceName", "")
            src_part = f" from IP: {ip_address}" if ip_address else ""
            summary = f"Kerberos Ticket Request: user='{user}' service='{svc}'{src_part}"

        elif event_id == 4776:
            action = "NtlmAuth_4776"
            ws_part = f" from Workstation: {workstation}" if workstation else ""
            summary = f"NTLM Credential Validation: user='{user}'{ws_part}"

        elif event_id in (1000, 1116, 1117):
            action = f"DefenderDetection_{event_id}"
            threat = event_data.get("Threat Name", event_data.get("ThreatName", "Malware"))
            path = event_data.get("Path", event_data.get("Resources", ""))
            summary = f"Defender Malware Detected: '{threat}' at {path}"

        return ParsedRecord(
            artefact_type="EventLog",
            source_file=file_path,
            timestamp_utc=timestamp_utc,
            action=action,
            summary=summary,
            user=user,
            computer=computer,
            details=details,
        )
