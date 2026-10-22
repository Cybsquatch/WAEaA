"""Data structures for security findings, severities, and MITRE ATT&CK mapping."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Detection finding severity rating."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting severity (higher is more critical)."""
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks.get(self, 0)


@dataclass(frozen=True)
class MitreAttack:
    """MITRE ATT&CK framework technique and tactic alignment."""

    tactic: str
    technique_id: str
    technique_name: str

    def to_dict(self) -> dict[str, str]:
        """Convert MITRE mapping to serializable dictionary."""
        return {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
        }


@dataclass
class Finding:
    """A detected threat or anomaly identified across parsed evidence."""

    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    description: str
    timestamp_utc: str
    source_artefact: str
    summary: str
    mitre: MitreAttack | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert finding into dictionary for JSON reporting."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["mitre"] = self.mitre.to_dict() if self.mitre else None
        return data
