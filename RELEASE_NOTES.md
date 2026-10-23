# WAEaA Release Notes &mdash; Version 1.1.0

**Release Date:** 2026-10-23  
**Repository:** `https://github.com/Cybsquatch/WAEaA`  
**License:** Proprietary Commercial (Permissive runtime dependencies)

Version 1.1.0 delivers major incident response capabilities: proprietary RDP Bitmap Cache extraction and edge pixel-matching screen reconstruction, Windows Scheduled Tasks analysis, an expanded MITRE ATT&CK detection engine generating deep threat coverage, and an advanced interactive single-file HTML report with composite filters and targeted exports.

---

## 1. Major Highlights in Version 1.1.0

### RDP Bitmap Cache & Desktop Screen Reconstructor
* **Targeted Artefact Collection:** Collector rule `win.rdp_cache` automatically extracts `.bmc` (legacy) and `.bin` (RDP 8+) bitmap cache files from all user profiles (`AppData\Local\Microsoft\Terminal Server Client\Cache\*`).
* **Proprietary Tile Parser (`rdp_cache.py`):** Decodes 16-bit, 24-bit, and 32-bit ARGB 64x64 pixel bitmap tiles without third-party dependencies.
* **Edge Pixel-Matching Reconstruction:** Proprietary algorithm analyzes boundary color gradients across adjacent horizontal and vertical edges to reconstruct panoramic and collage desktop screenshots.
* **Dual Output Mode:** Preserves all raw tiles in evidence folder `rdp_tiles/` and embeds reconstructed screen mosaics into the standalone HTML report.

### Windows Scheduled Tasks XML Parser (`tasks.py`)
* **Persistence & Lateral Movement Visibility:** Parses XML task definitions from `%SystemRoot%\System32\Tasks` and `SysWOW64\Tasks`.
* **Execution Profiling:** Extracts Task Name, Author, Principals, RunLevel (`HighestAvailable`), Triggers, and Exec commands with arguments.
* **Incident Detection:** Discovered the NIST dataset's core persistence and ransomware deployment task (`Enterpries backup` deploying `rename.exe` via `PsExec.exe -accept-eula` across `\\Desktop-001` through `\\Desktop-006`).

### Expanded Threat Detection Engine
* **Lateral Movement via SMB Admin Shares:** Flags connections to `\\*\ADMIN$`, `\\*\C$`, and `\\*\IPC$` (Event ID 31010 / 5140 / 5145).
* **RDP Intrusion & External Logons:** Flags inbound RDP authentications (Event ID 1149) with source IP extraction (e.g. `31.220.85.162`), session reconnects (Event 25), and logons (Event 21).
* **Ransomware & PsExec Staging:** Detects PsExec remote execution, hardcoded credentials (`-p letmein`), and ransomware executables (`rename.exe`, `petya`).
* **Antivirus & Malware Alerts:** Flags Windows Defender detection events (Event ID 1000, 1001, 1116, 1117, 5007).
* **Defense Evasion / Log Clearing:** Detects deliberate event log clearing (Event ID 104 and 1102).

### Advanced HTML Report v1.1
* **Composite Filtering:** Combined real-time multi-criteria filtering: free-text search + severity checkboxes + MITRE ATT&CK tactic dropdown + date range.
* **Row Flagging & Targeted Export:** Checkbox selection on findings and timeline events with one-click export of selected rows to **CSV**, **JSON**, or direct **Copy to Clipboard**.
* **Full-Page Export & Print:** Print-friendly styling with clean layout for PDF generation and executive reporting.
* **Interactive MITRE Matrix:** Clickable tactic columns dynamically filter the findings table.
* **Embedded RDP Screenshot Gallery:** Interactive visual canvas and tile strip.

### Collector Usability & Stability Fixes
* **Win32 GUI Thread Pinning:** Implemented `runtime.LockOSThread()` in the collector GUI to eliminate message pump desynchronization and Windows "(Not Responding)" states.
* **Automatic Drive Detection & Checkboxes:** Displays all detected logical drives (`C:\`, `D:\`, `E:\`, etc.) with filesystem and capacity; supports simultaneous multi-drive extraction into a single evidence archive.
* **Win64 Struct Alignment:** Corrected `MSG` struct padding and stdcall callback signature for x64 architecture.

---

## 2. Release Asset Packages
* `waeaa-v1.1.0-windows-amd64.zip` &mdash; Modern Windows 10/11, Server 2016-2025
* `waeaa-v1.1.0-windows-legacy-amd64.zip` &mdash; Windows 7 SP1, 8, 8.1, Server 2008 R2, 2012
* `waeaa-v1.1.0-windows-legacy-x86.zip` &mdash; 32-bit Windows 7 / 8 / 10
* `waeaa-v1.1.0-linux-amd64.tar.gz` &mdash; Linux x86_64 static binary
* `waeaa-v1.1.0-linux-arm64.tar.gz` &mdash; Linux aarch64 static binary
* `waeaa-ingestor-v1.1.0-windows-amd64.zip` &mdash; Standalone GUI Ingestor & Analyzer
