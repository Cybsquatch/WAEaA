"""Windows and Linux hosts file proprietary parser.

Parses drivers/etc/hosts and /etc/hosts to extract static DNS overrides,
identifying malicious domain sinkholing or redirecting security update servers.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import IO, Any

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord

HOSTS_LINE_RE = re.compile(r"^([0-9a-fA-F\.\:]+)\s+([a-zA-Z0-9\.\-\_]+)")


class HostsFileParser(BaseParser):
    """Parser for static hosts resolution files."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file_path is a hosts file."""
        lower = file_path.lower().replace("\\", "/")
        return lower.endswith("/hosts") or lower == "hosts" or "drivers/etc/hosts" in lower

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse hosts file stream and yield ParsedRecords for custom overrides."""
        raw_data = stream.read()
        if not raw_data:
            return

        text = raw_data.decode("utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            match = HOSTS_LINE_RE.match(line)
            if match:
                ip = match.group(1).strip()
                hostname = match.group(2).strip()

                # Ignore standard loopback defaults
                if hostname.lower() in ("localhost", "localhost.localdomain", "broadcasthost", "ip6-localhost", "ip6-loopback"):
                    continue

                details: dict[str, Any] = {
                    "ip_address": ip,
                    "hostname": hostname,
                    "raw_line": line,
                }

                summary = f"Custom Hosts File Mapping: '{hostname}' -> {ip}"

                yield ParsedRecord(
                    artefact_type="NetworkConfig",
                    source_file=file_path,
                    timestamp_utc="",
                    action="DnsHostOverride",
                    summary=summary,
                    user="",
                    computer="",
                    details=details,
                )
