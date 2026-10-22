"""Main window of the ingestor.

Milestone M1 provides the application shell: language selection, archive
selection and the "about" dialog. The analysis pipeline is connected to the
"Start analysis" button in milestones M6-M8.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QAction, QActionGroup
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from waeaa_ingestor import APP_NAME, __version__
from waeaa_ingestor.i18n import LANGUAGE_NAMES, SUPPORTED, Translator
from waeaa_ingestor.pipeline import IngestionPipeline


class AnalysisWorker(QThread):
    """Background worker executing the ingestion pipeline."""

    progress = Signal(float, str)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, archive_path: Path, output_dir: Path) -> None:
        """Initialize worker with input archive and output path."""
        super().__init__()
        self.archive_path = archive_path
        self.output_dir = output_dir

    def run(self) -> None:
        """Run extraction and parsing pipeline in background."""
        try:
            pipeline = IngestionPipeline(
                self.archive_path,
                self.output_dir,
                progress_callback=self._on_progress,
            )
            result = pipeline.run()
            self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))

    def _on_progress(self, pct: float, msg: str) -> None:
        self.progress.emit(pct, msg)


class MainWindow(QMainWindow):
    """Top-level window. All texts are rebuilt when the language changes."""

    def __init__(self, translator: Translator | None = None) -> None:
        """Build the window using ``translator`` (system language by default)."""
        super().__init__()
        self.tr_ = translator or Translator()
        self.archive: Path | None = None
        self._worker: AnalysisWorker | None = None

        # Widgets are created once; their texts are (re)applied by _retranslate.
        self._subtitle = QLabel()
        self._hint = QLabel()
        self._hint.setWordWrap(True)
        self._open_btn = QPushButton()
        self._open_btn.clicked.connect(self.choose_archive)
        self._start_btn = QPushButton()
        self._start_btn.setEnabled(False)
        self._start_btn.clicked.connect(self.start_analysis)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setVisible(False)

        self._status_label = QLabel()
        self._status_label.setVisible(False)

        layout = QVBoxLayout()
        for w in (
            self._subtitle,
            self._hint,
            self._open_btn,
            self._start_btn,
            self._progress_bar,
            self._status_label,
        ):
            layout.addWidget(w)
        layout.addStretch(1)
        central = QWidget()
        central.setLayout(layout)
        self.setCentralWidget(central)
        self.resize(900, 600)

        self._build_menus()
        self._retranslate()

    # ------------------------------------------------------------------ menus
    def _build_menus(self) -> None:
        """Create menu actions; texts are assigned in _retranslate."""
        bar = self.menuBar()
        self._file_menu = bar.addMenu("")
        self._open_action = QAction(self)
        self._open_action.triggered.connect(self.choose_archive)
        self._quit_action = QAction(self)
        self._quit_action.triggered.connect(self.close)
        self._file_menu.addAction(self._open_action)
        self._file_menu.addSeparator()
        self._file_menu.addAction(self._quit_action)

        # Language menu: exclusive, checkable entries in their own language.
        self._lang_menu = bar.addMenu("")
        group = QActionGroup(self)
        group.setExclusive(True)
        for code in SUPPORTED:
            action = QAction(LANGUAGE_NAMES[code], self, checkable=True)
            action.setChecked(code == self.tr_.lang)
            action.triggered.connect(lambda _=False, c=code: self.set_language(c))
            group.addAction(action)
            self._lang_menu.addAction(action)

        self._help_menu = bar.addMenu("")
        self._about_action = QAction(self)
        self._about_action.triggered.connect(self.show_about)
        self._help_menu.addAction(self._about_action)

    def _retranslate(self) -> None:
        """Apply the current language to every visible text."""
        t = self.tr_.t
        self.setWindowTitle(f"{t('app.title')} {__version__}")
        self._file_menu.setTitle(t("menu.file"))
        self._open_action.setText(t("menu.open"))
        self._quit_action.setText(t("menu.quit"))
        self._lang_menu.setTitle(t("menu.language"))
        self._help_menu.setTitle(t("menu.help"))
        self._about_action.setText(t("menu.about"))
        self._subtitle.setText(f"<h2>{t('app.title')}</h2>{t('app.subtitle')}")
        self._hint.setText(t("main.select_archive"))
        self._open_btn.setText(t("main.open_button"))
        self._start_btn.setText(t("main.start"))
        if self.archive:
            self.statusBar().showMessage(t("status.selected", path=str(self.archive)))
        else:
            self.statusBar().showMessage(t("status.ready"))

    # ---------------------------------------------------------------- actions
    def set_language(self, code: str) -> None:
        """Switch the UI language at runtime."""
        self.tr_ = Translator(code)
        self._retranslate()

    def choose_archive(self) -> None:
        """Ask the analyst for an evidence archive."""
        t = self.tr_.t
        path, _ = QFileDialog.getOpenFileName(
            self, t("dialog.open_title"), "", t("dialog.zip_filter")
        )
        if path:
            self.set_archive(Path(path))

    def set_archive(self, path: Path) -> None:
        """Record the selected archive and enable the analysis button."""
        self.archive = path
        self._start_btn.setEnabled(True)
        self._retranslate()

    def show_about(self) -> None:
        """Display product and licensing information."""
        QMessageBox.about(
            self,
            self.tr_.t("menu.about").replace("&", ""),
            self.tr_.t("about.text", name=APP_NAME, version=__version__),
        )

    def start_analysis(self) -> None:
        """Start the extraction, parsing, and timeline pipeline."""
        if not self.archive:
            return

        out_dir = self.archive.parent / f"{self.archive.stem}_analysis"
        self._open_btn.setEnabled(False)
        self._start_btn.setEnabled(False)
        self._progress_bar.setVisible(True)
        self._progress_bar.setValue(0)
        self._status_label.setVisible(True)
        self._status_label.setText(self.tr_.t("status.processing"))
        self.statusBar().showMessage(self.tr_.t("status.processing"))

        self._worker = AnalysisWorker(self.archive, out_dir)
        self._worker.progress.connect(self._on_worker_progress)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.failed.connect(self._on_worker_failed)
        self._worker.start()

    def _on_worker_progress(self, pct: float, msg: str) -> None:
        """Handle progress updates from the analysis worker."""
        val = int(pct * 100)
        self._progress_bar.setValue(val)
        self._status_label.setText(msg)
        self.statusBar().showMessage(msg)

    def _on_worker_finished(self, result: object) -> None:
        """Handle completion of the analysis worker."""
        self._open_btn.setEnabled(True)
        self._start_btn.setEnabled(True)
        self._progress_bar.setValue(100)
        count = getattr(result, "timeline_event_count", 0)
        done_msg = self.tr_.t("status.completed", count=count)
        self._status_label.setText(done_msg)
        self.statusBar().showMessage(done_msg)

    def _on_worker_failed(self, err: str) -> None:
        """Handle analysis failure."""
        self._open_btn.setEnabled(True)
        self._start_btn.setEnabled(True)
        err_msg = self.tr_.t("status.error", error=err)
        self._status_label.setText(err_msg)
        self.statusBar().showMessage(err_msg)


def run_gui(argv: list[str]) -> int:
    """Create the Qt application, show the main window and run the event loop."""
    app = QApplication.instance() or QApplication(argv)
    window = MainWindow()
    window.show()
    return int(app.exec())
