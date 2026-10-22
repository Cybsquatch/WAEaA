# WAEaA Release Notes &mdash; Version 1.0.0

**Release Date:** 2026-10-22  
**Repository:** `https://github.com/Cybsquatch/WAEaA`  
**License:** Proprietary Commercial (Permissive third-party runtime dependencies)

WAEaA (*Windows Artifacts Extractor and Analyzer*) version 1.0.0 represents the inaugural production release of our unified, legally sound digital forensics and incident response (DFIR) suite.

---

## 1. Major Highlights

### Windows Collector (`waeaa.exe` & `waeaa-legacy.exe`)
* **Unified Single Binary:** Serves both command-line workflows and a native Win32 graphical user interface in a single executable.
* **Auto-Elevation (UAC):** When launched via double-click, automatically requests administrator privileges without popping an extraneous console window.
* **Locked File Extraction via Raw NTFS:** Direct cluster-level access to master file tables (`$MFT`), active registry hives, and locked event logs using `SeBackupPrivilege`.
* **Volume Shadow Copy (VSS) Integration:** Automatic enumerated fallback to past snapshot states.
* **Legacy Windows 7 Support:** Dedicated `waeaa-legacy.exe` compiled with Go 1.20 toolchain, supporting Windows 7 SP1, Windows 8/8.1, and Windows Server 2008 R2 / 2012 R2.

### Linux Collector (`waeaa-linux-*`)
* **Distro-Aware Architecture:** Automatically identifies Debian, Ubuntu, RHEL, CentOS, Rocky, Alma, SUSE, Arch, and Amazon Linux, adjusting target log paths accordingly.
* **Interactive Terminal User Interface (TUI):** Built with pure Go terminal primitives, enabling rapid on-target rule selection and execution.
* **Static Binary:** Zero dynamic runtime dependencies; runs on any standard Linux kernel 3.10+.

### WAEaA Ingestor & Detection Engine
* **GUI-Only Forensic Workstation Application:** Built with Python 3.11+ and Qt (PySide6), windowed without a command prompt.
* **Proprietary Binary Decoders:**
  * Windows Event Logs (`.evtx`) chunk and record parser.
  * Windows Prefetch (`.pf`) supporting SCCA headers and proprietary LZXPRESS MAM decompression.
  * Registry Hive (`regf`/`nk`/`vk`) parser for Run keys, services, and accounts.
  * Shell Link (`.lnk`) binary structure decoder.
  * Chromium & Firefox SQLite history and downloads parser.
  * Linux `syslog`, `auth.log`, 384-byte `utmp`/`wtmp` records, user shell history, and cron tables.
* **Normalized Super-Timeline:** Generates chronological ISO 8601 UTC event timelines merging filesystem MACB metadata and parsed application records.
* **Security Detection Engine:**
  * Credential dumping (LSASS access, `sekurlsa`, `procdump`, `comsvcs.dll`).
  * Anti-forensics (Security event log clearing Event 1102 / 104).
  * Ransomware activity (Volume Shadow Copy deletion).
  * Living-off-the-land binaries (LOLBins: `certutil`, `bitsadmin`, `mshta`, `regsvr32`).
  * Persistence mechanisms (Registry Run/RunOnce, suspicious service creation Event 7045).
  * Interactive Linux reverse shells (`/dev/tcp`, `nc -e`, Python socket redirection).
* **Offline Threat Intelligence:** Integrated hash database (SHA-256), vulnerable driver blocklist (BYOVD), and malicious C2 IP indicators.
* **Interactive Single-File HTML Report (`report.html`):** Fully offline dashboard featuring executive metrics, MITRE ATT&CK tactic matrix, instant full-text search, severity filtering, super-timeline explorer, and client-side CSV export with zero CDN dependencies.
* **Automated Packaging:** Consolidates analysis results into `<HOSTNAME>_analysis_<timestamp>.zip`.

---

## 2. Supported Languages (i18n)
All user interfaces (Windows GUI, Linux TUI, Ingestor GUI) and reports support:
* English (`en`)
* Italian (`it`)
* Spanish (`es`)
* French (`fr`)
* German (`de`)

---

## 3. Forensic Integrity & Chain of Custody
Every acquisition produces:
* `_meta/manifest.json`: Cryptographic SHA-256, SHA-1, MD5 hashes, source paths, acquisition timestamps, and byte counts.
* `_meta/chain_of_custody.json`: Examiner details, case reference, explicit authorization confirmation, and UTC time spans.
* `_meta/collection.log`: Full chronological operational log.

---

## 4. Quality & Verification
* **Collector:** 100% test pass rate across all packages (`internal/ntfs`, `internal/vss`, `internal/engine`, `internal/evidence`, `internal/distro`, `internal/cli`, `internal/i18n`).
* **Ingestor:** 53 test cases passing with zero warnings or errors under `ruff` and strict `mypy`.
* **CI:** Multi-platform GitHub Actions covering Windows and Linux runners with race detector verification.
