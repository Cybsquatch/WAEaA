# WAEaA Ingestor

Analyst-side, **GUI-only** application. It opens an evidence archive produced
by the WAEaA collector, parses every artefact, runs the detection engine and
produces `<HOSTNAME>_analysis_<timestamp>.zip` with parsed data and an HTML
report.

## Development

```powershell
cd ingestor
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest        # tests (GUI tests run offscreen)
.\.venv\Scripts\ruff check .            # lint
.\.venv\Scripts\mypy                    # static typing
.\.venv\Scripts\python -m waeaa_ingestor  # start the GUI
```
