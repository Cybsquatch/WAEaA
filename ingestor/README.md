# WAEaA Ingestor

**WAEaA Ingestor** is the analyst-side graphical workstation component of the WAEaA digital forensics and incident response suite. It parses evidence archives produced by WAEaA Windows and Linux collectors, runs multi-layered detection rules and offline threat intelligence, normalizes a unified super-timeline, and outputs an interactive, standalone single-file offline HTML report alongside `<HOSTNAME>_analysis_<timestamp>.zip`.

---

## Architectural Features

* **Zero External Dependencies:** Built with pure Python 3.11+ and Qt (PySide6-Essentials) without spawning external command-line utilities.
* **Proprietary Binary Parsers:** Clean-room decoders for:
  * **EVTX:** Windows Event Log chunks (`ElfChnk`), record structures, and event schema extraction.
  * **Prefetch:** SCCA versions (Win7/8/10/11) and proprietary LZXPRESS MAM decompression.
  * **Registry Hives:** `regf` root keys, `nk` key nodes, and `vk` value nodes for Run keys, services, and user accounts.
  * **LNK Files:** Shell Link binary structures and resolved target paths.
  * **Web Browsers:** SQLite histories and download logs for Chromium family and Mozilla Firefox.
  * **Linux Logs:** `syslog`, `auth.log`, 384-byte `utmp`/`wtmp`/`btmp` login structures.
  * **Shell History:** Bash and Zsh timestamped execution histories.
  * **Scheduled Tasks:** System and user crontabs and systemd timer units.
* **Super-Timeline Engine:** Aggregates and normalizes events with standard ISO 8601 UTC timestamps, filesystem MACB timestamps, and action classification.
* **Proprietary Detection Engine & MITRE ATT&CK:** Correlates credential access, persistence, privilege escalation, anti-forensics, and LOLBins execution directly into actionable security findings.
* **Offline Threat Intelligence:** Matches file hashes (SHA-256), suspicious C2 IP addresses, and known vulnerable drivers (BYOVD) without cloud telemetry.
* **Single-File Interactive HTML Report:** Generates `report.html` with embedded dark-themed responsive CSS and vanilla JavaScript for offline forensic analysis.

---

## Development Setup

```powershell
cd ingestor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

### Running Tests and Quality Checks

```powershell
# Run all unit and integration tests with coverage
pytest --cov=waeaa_ingestor --cov-report=term-missing

# Run code style and lint checks
ruff check .

# Run strict static type validation
mypy
```

### Launching the Graphical Interface

```powershell
python -m waeaa_ingestor
```

### Standalone Executable Packaging

WAEaA Ingestor can be compiled into a standalone, windowed executable (`waeaa-ingestor.exe`) that runs without a Python interpreter:

```powershell
pyinstaller waeaa_ingestor.spec
```

The resulting executable will be located in `ingestor/dist/waeaa-ingestor/` or `ingestor/dist/waeaa-ingestor.exe`.

---

## License

Proprietary software. See [LICENSE](../LICENSE) and [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) at the repository root.
