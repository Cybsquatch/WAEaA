"""Base abstractions for forensic artefact parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import IO, Any


@dataclass
class ParsedRecord:
    """A single parsed forensic record from an acquired artefact."""

    artefact_type: str
    source_file: str
    timestamp_utc: str
    action: str
    summary: str
    user: str = ""
    computer: str = ""
    process_name: str = ""
    process_id: int | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert record to a flat dictionary for tabular reporting."""
        d = {
            "timestamp_utc": self.timestamp_utc,
            "artefact_type": self.artefact_type,
            "action": self.action,
            "summary": self.summary,
            "user": self.user,
            "computer": self.computer,
            "process_name": self.process_name,
            "source_file": self.source_file,
        }
        for k, v in self.details.items():
            if k not in d:
                d[k] = v
        return d


@dataclass
class TimelineEvent:
    """Normalized forensic timeline event with standard timestamp."""

    timestamp_utc: str
    artefact_type: str
    source_file: str
    action: str
    summary: str
    user: str = ""
    computer: str = ""
    details: dict[str, Any] = field(default_factory=dict)


class BaseParser(ABC):
    """Abstract base class for all proprietary artefact parsers."""

    @abstractmethod
    def can_parse(self, file_path: str) -> bool:
        """Report whether this parser can handle the specified file."""
        ...

    @abstractmethod
    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse artefact binary or text data, yielding structured records."""
        ...
