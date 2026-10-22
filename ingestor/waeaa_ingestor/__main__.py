"""Entry point of the WAEaA Ingestor.

The ingestor is a graphical application only: command-line arguments are
ignored on purpose and the packaged executable is built in windowed mode
(no console). The GUI module is imported lazily so that the rest of the
package (parsers, detection engine, report) stays importable and testable
without a display.
"""

from __future__ import annotations

import sys


def main() -> int:
    """Start the graphical user interface and return its exit code."""
    from waeaa_ingestor.gui.main_window import run_gui

    return run_gui(sys.argv[:1])


if __name__ == "__main__":
    sys.exit(main())
