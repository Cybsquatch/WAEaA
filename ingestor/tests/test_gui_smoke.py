"""Smoke tests for the GUI shell, run with Qt's offscreen platform."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

from waeaa_ingestor.gui.main_window import MainWindow  # noqa: E402
from waeaa_ingestor.i18n import SUPPORTED, Translator  # noqa: E402


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    app = QApplication.instance() or QApplication([])
    assert isinstance(app, QApplication)
    return app


@pytest.mark.parametrize("code", SUPPORTED)
def test_window_builds_in_every_language(qapp: QApplication, code: str) -> None:
    w = MainWindow(Translator(code))
    assert "WAEaA Ingestor" in w.windowTitle()
    w.close()


def test_language_switch_and_archive_selection(qapp: QApplication) -> None:
    w = MainWindow(Translator("en"))
    w.set_archive(Path("HOST01.zip"))
    assert w._start_btn.isEnabled()
    w.set_language("it")
    assert w._start_btn.text() == "Avvia analisi"
    assert "HOST01.zip" in w.statusBar().currentMessage()

    # Test worker callbacks without starting background thread
    w._on_worker_progress(0.5, "Parsing logs...")
    assert w._progress_bar.value() == 50
    assert w._status_label.text() == "Parsing logs..."

    class DummyResult:
        timeline_event_count = 42

    w._on_worker_finished(DummyResult())
    assert w._progress_bar.value() == 100
    assert "42" in w._status_label.text()

    w._on_worker_failed("Disk error")
    assert "Disk error" in w._status_label.text()

    w.close()
