"""Evidence archive reader and integrity verification.

Inspects WAEaA evidence archives (.zip), parses embedded forensic manifests
and chain of custody records, and streams archived artefacts to the parsing
pipeline.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any


@dataclass
class ManifestEntry:
    """Represents a single acquired artefact recorded in the manifest."""

    source_path: str
    archive_path: str
    size: int
    sha256: str
    modified_utc: str
    acquired_utc: str
    rule_id: str
    deduplicated: bool = False
    original_archive_path: str = ""
    sha1: str = ""
    md5: str = ""


class EvidenceArchive:
    """Reader and integrity validator for WAEaA evidence ZIP archives."""

    def __init__(self, path: Path | str) -> None:
        """Open the evidence archive at ``path``."""
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(f"Archive not found: {self.path}")

        self._zip = zipfile.ZipFile(self.path, "r")
        self.manifest: list[ManifestEntry] = []
        self.custody: dict[str, Any] = {}
        self._load_metadata()

    def _load_metadata(self) -> None:
        """Load manifest and chain-of-custody from the _meta folder."""
        # Load manifest
        try:
            with self._zip.open("_meta/manifest.json") as f:
                raw_manifest = json.load(f)
                self.manifest = [
                    ManifestEntry(
                        source_path=item.get("source_path", ""),
                        archive_path=item.get("archive_path", ""),
                        size=item.get("size", 0),
                        sha256=item.get("sha256", ""),
                        modified_utc=item.get("modified_utc", ""),
                        acquired_utc=item.get("acquired_utc", ""),
                        rule_id=item.get("rule_id", ""),
                        deduplicated=item.get("deduplicated", False),
                        original_archive_path=item.get("original_archive_path", ""),
                        sha1=item.get("sha1", ""),
                        md5=item.get("md5", ""),
                    )
                    for item in raw_manifest
                ]
        except KeyError:
            # Archive without JSON manifest (e.g. ad-hoc zip)
            self.manifest = []

        # Load chain of custody
        try:
            with self._zip.open("_meta/chain_of_custody.json") as f:
                self.custody = json.load(f)
        except KeyError:
            self.custody = {}

    @property
    def hostname(self) -> str:
        """Return target hostname from custody record or archive filename."""
        return str(self.custody.get("hostname") or self.path.stem.split("_")[0])

    @property
    def target_os(self) -> str:
        """Return detected operating system of the acquired host."""
        return str(self.custody.get("os", "unknown")).lower()

    def list_files(self) -> list[str]:
        """Return names of all non-metadata files in the archive."""
        return [
            n for n in self._zip.namelist() if not n.startswith("_meta/") and not n.endswith("/")
        ]

    def find_files(self, pattern: str) -> list[str]:
        """Find archive entries matching a glob pattern (e.g. ``*.evtx``)."""
        pattern_lower = pattern.lower()
        return [
            name
            for name in self._zip.namelist()
            if not name.startswith("_meta/") and fnmatch.fnmatch(name.lower(), pattern_lower)
        ]

    def open_stream(self, entry_name: str) -> IO[bytes]:
        """Open a readable binary stream for the given archive entry."""
        return self._zip.open(entry_name, "r")

    def read_bytes(self, entry_name: str) -> bytes:
        """Read complete bytes of an entry."""
        with self.open_stream(entry_name) as f:
            return f.read()

    def verify_file_hash(self, entry: ManifestEntry) -> bool:
        """Verify the cryptographic SHA-256 integrity of an archived file."""
        target_path = (
            entry.original_archive_path or entry.archive_path
            if entry.deduplicated
            else entry.archive_path
        )

        if not target_path or target_path not in self._zip.namelist():
            return False

        h = hashlib.sha256()
        with self.open_stream(target_path) as f:
            while chunk := f.read(65536):
                h.update(chunk)

        return h.hexdigest().lower() == entry.sha256.lower()

    def close(self) -> None:
        """Close the underlying ZIP file."""
        self._zip.close()

    def __enter__(self) -> EvidenceArchive:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()
