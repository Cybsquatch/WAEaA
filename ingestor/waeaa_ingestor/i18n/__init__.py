"""Translation catalogs of the ingestor (GUI and HTML report).

Catalogs are flat JSON objects stored in ``locales/<code>.json``. English is
the reference catalog and the fallback for missing keys. The test-suite
checks that every language defines exactly the same keys and the same
``str.format`` placeholders.
"""

from __future__ import annotations

import contextlib
import json
import locale
import os
import string
from functools import cache
from importlib import resources

DEFAULT_LANGUAGE = "en"
SUPPORTED: tuple[str, ...] = ("it", "en", "es", "fr", "de")

# Human readable names shown in the language selector, in their own language.
LANGUAGE_NAMES: dict[str, str] = {
    "it": "Italiano",
    "en": "English",
    "es": "Español",
    "fr": "Français",
    "de": "Deutsch",
}


def normalize(tag: str | None) -> str:
    """Convert a locale tag (``it_IT.UTF-8``, ``de-DE``) to ``it`` / ``de``."""
    if not tag:
        return ""
    tag = tag.strip().split(".", 1)[0].split("@", 1)[0]
    tag = tag.replace("-", "_").split("_", 1)[0].lower()
    return "" if tag in ("c", "posix") else tag


def detect() -> str:
    """Return the best supported language for the current user."""
    candidates = [os.environ.get(v) for v in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG")]
    with contextlib.suppress(ValueError):  # platform dependent
        candidates.append(locale.getlocale()[0])
    for cand in candidates:
        for part in (cand or "").split(":"):
            code = normalize(part)
            if code in SUPPORTED:
                return code
    return DEFAULT_LANGUAGE


@cache
def load_catalog(code: str) -> dict[str, str]:
    """Load and cache the catalog for ``code``."""
    data = resources.files(__package__).joinpath("locales", f"{code}.json").read_text("utf-8")
    catalog: dict[str, str] = json.loads(data)
    return catalog


def placeholders(message: str) -> list[str]:
    """Return the sorted ``str.format`` field names used by ``message``."""
    return sorted(f for _, f, _, _ in string.Formatter().parse(message) if f is not None)


class Translator:
    """Resolve message keys for one language with English fallback."""

    def __init__(self, lang: str | None = None) -> None:
        """Create a translator; unsupported or empty languages fall back to English."""
        code = normalize(lang) if lang else detect()
        self.lang = code if code in SUPPORTED else DEFAULT_LANGUAGE
        self._messages = load_catalog(self.lang)
        self._fallback = load_catalog(DEFAULT_LANGUAGE)

    def t(self, key: str, **kwargs: object) -> str:
        """Return the translated message for ``key`` formatted with ``kwargs``.

        Unknown keys are returned verbatim so a missing translation is visible
        in the UI but never raises.
        """
        msg = self._messages.get(key) or self._fallback.get(key) or key
        return msg.format(**kwargs) if kwargs else msg
