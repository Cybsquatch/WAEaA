"""Offline threat intelligence indicator database.

Maintains curated sets of known malicious file hashes (SHA-256), suspicious C2
IPs, and vulnerable driver signatures (BYOVD) with offline matching.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ThreatIndicator:
    """A threat intelligence indicator record."""

    indicator: str
    threat_type: str
    threat_name: str
    description: str
    confidence: str = "High"


# Curated offline reference signatures (lowercase SHA-256)
DEFAULT_MALICIOUS_HASHES: dict[str, ThreatIndicator] = {
    # Publicly documented Mimikatz / credential dumpers
    "9d5bf1f98bc9bc9a6ae4f36ae06456f4d22166a014a601bb816007ec25b2f42a": ThreatIndicator(
        indicator="9d5bf1f98bc9bc9a6ae4f36ae06456f4d22166a014a601bb816007ec25b2f42a",
        threat_type="CredentialTheft",
        threat_name="Mimikatz Executable",
        description="Publicly known credential extraction binary.",
    ),
    # Publicly documented China Chopper webshell sample
    "b8915b8004f145ad573dd80fbe58f6a310bbdddf2a06180327f1c1f3efd2bc7d": ThreatIndicator(
        indicator="b8915b8004f145ad573dd80fbe58f6a310bbdddf2a06180327f1c1f3efd2bc7d",
        threat_type="Webshell",
        threat_name="China Chopper Variant",
        description="Single-line server side script backdoor.",
    ),
    # Publicly documented WannaCry ransomware sample
    "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c": ThreatIndicator(
        indicator="24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
        threat_type="Ransomware",
        threat_name="WannaCry Encryptor",
        description="Known ransomware payload variant.",
    ),
}

# Known vulnerable drivers frequently abused in BYOVD attacks
VULNERABLE_DRIVERS: dict[str, str] = {
    "gdrv.sys": "GIGABYTE GDRV driver (CVE-2018-19320 / arbitrary kernel read/write)",
    "procexp.sys": "Outdated Process Explorer driver abused to terminate EDR processes",
    "mhyprot2.sys": "Genshin Impact anti-cheat driver abused for kernel-level termination",
    "rtcore64.sys": "Micro-Star MSI Afterburner RTCore driver (CVE-2019-16098)",
    "dbutil_2_3.sys": "Dell BIOS verification driver (CVE-2021-21551)",
}

# Test and malicious C2 IP indicators
DEFAULT_MALICIOUS_IPS: dict[str, ThreatIndicator] = {
    "198.51.100.200": ThreatIndicator(
        indicator="198.51.100.200",
        threat_type="C2Server",
        threat_name="Known Cobalt Strike Team Server",
        description="Reported command and control server IP.",
    ),
    "203.0.113.199": ThreatIndicator(
        indicator="203.0.113.199",
        threat_type="Botnet",
        threat_name="Mirai Scanner Node",
        description="Reported brute-force source IP.",
    ),
}


@dataclass
class ThreatIntelDB:
    """In-memory database of curated and custom threat intelligence indicators."""

    hashes: dict[str, ThreatIndicator] = field(
        default_factory=lambda: dict(DEFAULT_MALICIOUS_HASHES)
    )
    ips: dict[str, ThreatIndicator] = field(default_factory=lambda: dict(DEFAULT_MALICIOUS_IPS))
    vulnerable_drivers: dict[str, str] = field(default_factory=lambda: dict(VULNERABLE_DRIVERS))

    def load_custom_indicators(self, file_path: Path | str) -> int:
        """Load optional custom indicator file (JSON format) and return count added."""
        p = Path(file_path)
        if not p.is_file():
            return 0

        added = 0
        try:
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)

            for item in data.get("hashes", []):
                h = item.get("hash", "").strip().lower()
                if h:
                    self.hashes[h] = ThreatIndicator(
                        indicator=h,
                        threat_type=item.get("type", "CustomMalware"),
                        threat_name=item.get("name", "Custom Threat"),
                        description=item.get("description", "User-provided hash indicator"),
                    )
                    added += 1

            for item in data.get("ips", []):
                ip = item.get("ip", "").strip()
                if ip:
                    self.ips[ip] = ThreatIndicator(
                        indicator=ip,
                        threat_type=item.get("type", "CustomIP"),
                        threat_name=item.get("name", "Custom C2"),
                        description=item.get("description", "User-provided IP indicator"),
                    )
                    added += 1
        except (json.JSONDecodeError, OSError):
            return added

        return added

    def check_hash(self, sha256: str) -> ThreatIndicator | None:
        """Query SHA-256 against known malicious database."""
        return self.hashes.get(sha256.strip().lower())

    def check_ip(self, ip: str) -> ThreatIndicator | None:
        """Query IP address against malicious network indicator database."""
        return self.ips.get(ip.strip())

    def check_driver_name(self, filename: str) -> str | None:
        """Query filename against known vulnerable driver list."""
        return self.vulnerable_drivers.get(filename.strip().lower())
