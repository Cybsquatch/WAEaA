"""Tests for the translation catalogs and the Translator class."""

from __future__ import annotations

import pytest

from waeaa_ingestor.i18n import (
    DEFAULT_LANGUAGE,
    LANGUAGE_NAMES,
    SUPPORTED,
    Translator,
    load_catalog,
    normalize,
    placeholders,
)


@pytest.mark.parametrize("code", SUPPORTED)
def test_catalog_has_same_keys_as_english(code: str) -> None:
    ref = load_catalog(DEFAULT_LANGUAGE)
    cat = load_catalog(code)
    assert set(cat) == set(ref), f"{code}: key mismatch {set(cat) ^ set(ref)}"


@pytest.mark.parametrize("code", SUPPORTED)
def test_catalog_has_same_placeholders(code: str) -> None:
    ref = load_catalog(DEFAULT_LANGUAGE)
    cat = load_catalog(code)
    for key, msg in ref.items():
        assert placeholders(cat[key]) == placeholders(msg), f"{code}/{key}"


def test_every_language_has_a_display_name() -> None:
    assert set(LANGUAGE_NAMES) == set(SUPPORTED)


@pytest.mark.parametrize(
    ("tag", "expected"),
    [
        ("it_IT.UTF-8", "it"),
        ("de-DE", "de"),
        ("FR", "fr"),
        ("es_ES@euro", "es"),
        ("C", ""),
        ("POSIX", ""),
        ("", ""),
        (None, ""),
    ],
)
def test_normalize(tag: str | None, expected: str) -> None:
    assert normalize(tag) == expected


def test_unsupported_language_falls_back_to_english() -> None:
    assert Translator("ja_JP").lang == DEFAULT_LANGUAGE


def test_translate_with_placeholder() -> None:
    assert Translator("it").t("status.selected", path="x.zip") == "Selezionato: x.zip"


def test_unknown_key_is_returned_verbatim() -> None:
    assert Translator("de").t("does.not.exist") == "does.not.exist"
