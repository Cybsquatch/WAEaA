"""Web Browser history and downloads SQLite proprietary parser.

Decodes Chromium (Chrome, Edge, Brave) and Firefox SQLite history databases,
extracting visited URLs, page titles, download targets, and timestamps.
"""

from __future__ import annotations

import contextlib
import datetime
import os
import sqlite3
import tempfile
from collections.abc import Iterator
from typing import IO

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord

CHROMIUM_EPOCH_DELTA = 11644473600000000  # microseconds between 1601 and 1970


def chromium_time_to_iso(microseconds: int) -> str:
    """Convert Chromium timestamp (microseconds since 1601-01-01) to ISO 8601 UTC."""
    if microseconds <= 0:
        return ""
    try:
        unix_sec = (microseconds - CHROMIUM_EPOCH_DELTA) / 1_000_000
        dt = datetime.datetime.fromtimestamp(unix_sec, tz=datetime.UTC)
        return dt.isoformat()
    except (ValueError, OverflowError, OSError):
        return ""


def firefox_time_to_iso(microseconds: int) -> str:
    """Convert Firefox timestamp (microseconds since 1970-01-01) to ISO 8601 UTC."""
    if microseconds <= 0:
        return ""
    try:
        dt = datetime.datetime.fromtimestamp(microseconds / 1_000_000, tz=datetime.UTC)
        return dt.isoformat()
    except (ValueError, OverflowError, OSError):
        return ""


class BrowserHistoryParser(BaseParser):
    """Parser for browser SQLite history and download databases."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file matches browser database patterns."""
        p = file_path.lower().replace("\\", "/")
        if "bash_history" in p or "zsh_history" in p or p.endswith(".history"):
            return False
        base = p.rsplit("/", 1)[-1]
        return base in ("history", "history.db", "places.sqlite") or "places.sqlite" in base

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Write stream to a temp file and parse using SQLite engine."""
        data = stream.read()
        if not data.startswith(b"SQLite format 3\x00"):
            return

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            conn = sqlite3.connect(tmp_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Check for Chromium tables (urls / downloads)
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row["name"] for row in cursor.fetchall()}

            if "urls" in tables:
                yield from self._parse_chromium_urls(cursor, file_path)
            if "downloads" in tables:
                yield from self._parse_chromium_downloads(cursor, file_path)
            if "moz_places" in tables:
                yield from self._parse_firefox_places(cursor, file_path)

            conn.close()
        except sqlite3.Error:
            pass
        finally:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)

    def _parse_chromium_urls(
        self, cursor: sqlite3.Cursor, file_path: str
    ) -> Iterator[ParsedRecord]:
        """Parse visited URLs from Chromium urls table."""
        cursor.execute(
            "SELECT url, title, visit_count, last_visit_time FROM urls "
            "ORDER BY last_visit_time DESC LIMIT 1000"
        )
        for row in cursor.fetchall():
            time_iso = chromium_time_to_iso(row["last_visit_time"])
            if not time_iso:
                continue
            url = row["url"] or ""
            title = row["title"] or ""
            yield ParsedRecord(
                artefact_type="BrowserHistory",
                source_file=file_path,
                timestamp_utc=time_iso,
                action="UrlVisit",
                summary=f"Visited: {title or url}",
                details={
                    "url": url,
                    "title": title,
                    "visit_count": row["visit_count"],
                    "browser": "Chromium",
                },
            )

    def _parse_chromium_downloads(
        self, cursor: sqlite3.Cursor, file_path: str
    ) -> Iterator[ParsedRecord]:
        """Parse downloads from Chromium downloads table."""
        cursor.execute(
            "SELECT target_path, start_time, end_time, received_bytes, total_bytes "
            "FROM downloads LIMIT 500"
        )
        for row in cursor.fetchall():
            time_iso = chromium_time_to_iso(row["start_time"])
            if not time_iso:
                continue
            path = row["target_path"] or "Downloaded File"
            yield ParsedRecord(
                artefact_type="BrowserDownload",
                source_file=file_path,
                timestamp_utc=time_iso,
                action="FileDownload",
                summary=f"Downloaded: {path}",
                details={
                    "target_path": path,
                    "total_bytes": row["total_bytes"],
                    "browser": "Chromium",
                },
            )

    def _parse_firefox_places(
        self, cursor: sqlite3.Cursor, file_path: str
    ) -> Iterator[ParsedRecord]:
        """Parse history from Firefox moz_places table."""
        cursor.execute(
            "SELECT url, title, visit_count, last_visit_date FROM moz_places "
            "WHERE last_visit_date IS NOT NULL LIMIT 1000"
        )
        for row in cursor.fetchall():
            time_iso = firefox_time_to_iso(row["last_visit_date"])
            if not time_iso:
                continue
            url = row["url"] or ""
            title = row["title"] or ""
            yield ParsedRecord(
                artefact_type="BrowserHistory",
                source_file=file_path,
                timestamp_utc=time_iso,
                action="UrlVisit",
                summary=f"Visited: {title or url}",
                details={
                    "url": url,
                    "title": title,
                    "visit_count": row["visit_count"],
                    "browser": "Firefox",
                },
            )
