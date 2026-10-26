# WAEaA Release Notes &mdash; Version 1.2.0

**Release Date:** 2026-10-26  
**Repository:** `https://github.com/Cybsquatch/WAEaA`  
**License:** Proprietary Commercial (Permissive runtime dependencies)

Version 1.2.0 introduces comprehensive collection, parsing, and threat detection for Remote Access / RMM software, volatile user staging directories (`AppData` and `ProgramData`), an expanded 57-rule MITRE ATT&CK detection engine, and enhanced lossless bitmap tile rendering for RDP cache forensics.

---

## 1. Major Highlights in Version 1.2.0

### Remote Access & RMM Software Extraction (`win.remote_access`)
* **Dedicated Forensic Rule:** Automatically targets and extracts connection history, forensic trace logs, and configuration state for remote access tools and Remote Monitoring & Management (RMM) software across all user profiles and system directories:
  * **AnyDesk:** `AppData\Roaming\AnyDesk\connection_trace.txt`, `system.conf`, `user.conf`, and trace logs.
  * **Atera Networks:** `ProgramData\Atera Networks\AteraAgent\AteraAgent.log` and associated agent logs.
  * **TeamViewer:** `AppData\Roaming\TeamViewer\Connections_incoming.txt` and `TeamViewer*_Logfile.log`.
  * **ScreenConnect:** `ProgramData\ScreenConnect Client\*.log`.
  * **RustDesk, Splashtop, UltraVNC, TightVNC, LogMeIn:** Session logs, incoming connection records, and peer configurations.
* **Integrated into Triage Collection:** Automatically captured when running standard triage collection profiles.

### AppData & ProgramData Staged Script & Binary Extraction (`win.appdata`)
* **Targeted Volatile Staging Capture:** Specifically collects scripts (`.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.hta`), portable executables (`.exe`), dynamic link libraries (`.dll`), setup logs, and console transcripts residing in:
  * `Users\*\AppData\Local\Temp`
  * `Users\*\AppData\Roaming`
  * `Users\*\AppData\Local`
  * `ProgramData`
* **Intelligent File Filtering:** Focuses strictly on executable code, scripts, and logs while excluding bulk browser caches and multimedia data.

### Automated Forensic Parsers
* **`RemoteAccessParser` (`remote_access.py`):**
  * Decodes incoming/outgoing connection records from AnyDesk, TeamViewer, Atera, ScreenConnect, and RustDesk.
  * Extracts remote identifiers, remote IP addresses, target user accounts, timestamps, and session durations into structured `RemoteAccess` artefacts.
* **`AppDataStagingParser` (`appdata.py`):**
  * Performs in-depth inspection of staged scripts and portable executables found in volatile user paths.
  * Regex pattern engine scans scripts for 9 critical threat indicators: dynamic code execution (`IEX`/`Invoke-Expression`), download cradles (`certutil`, `bitsadmin`, `iwr`), shadow copy tampering / ransomware commands, encoded PowerShell commands, scriptlet proxy executions (`rundll32`, `mshta`), and credential dumping tool signatures.
  * Verifies PE binary headers (`MZ`) for executables staged outside standard Program Files.

### Expanded Threat Detection Engine (57 ATT&CK Rules)
* **AnyDesk Remote C2 / Intrusion Rule (`waeaa.command_and_control.anydesk_remote_session`, T1219):** Flags unauthorized incoming AnyDesk connections and external remote operator IDs.
* **Atera RMM Agent Rule (`waeaa.command_and_control.atera_rmm_activity`, T1219):** Detects script executions and commands dispatched via Atera RMM.
* **TeamViewer Incoming Session Rule (`waeaa.command_and_control.teamviewer_session`, T1219):** Flags remote control sessions established via TeamViewer.
* **ScreenConnect Remote Session Rule (`waeaa.command_and_control.screenconnect_session`, T1219):** Flags active ScreenConnect client sessions.
* **Suspicious AppData Script Staging Rule (`waeaa.execution.appdata_suspicious_script`, T1059):** Triggers on scripts staged in AppData containing download cradles, shadow copy deletion, or defense evasion logic.
* **Binary Staged in AppData Rule (`waeaa.execution.appdata_binary_staged`, T1204.002):** Identifies PE binaries staged in AppData or ProgramData without standard installer footprints.

### RDP Bitmap Cache Tile Rendering Compliance
* **Lossless 24bpp BMP Export:** Tile decoder conforms strictly to standard bottom-up 24bpp Windows DIB formatting with 4-byte stride padding, resolving preview rendering issues across standard image viewers.

---

## 2. Release Asset Packages
* `waeaa-v1.2.0-windows-amd64.zip` &mdash; Modern Windows 10/11, Server 2016-2025
* `waeaa-v1.2.0-windows-legacy-amd64.zip` &mdash; Windows 7 SP1, 8, 8.1, Server 2008 R2, 2012
* `waeaa-v1.2.0-windows-legacy-x86.zip` &mdash; 32-bit Windows 7 / 8 / 10
* `waeaa-v1.2.0-linux-amd64.tar.gz` &mdash; Linux x86_64 static binary
* `waeaa-v1.2.0-linux-arm64.tar.gz` &mdash; Linux aarch64 static binary
* `waeaa-ingestor-v1.2.0-windows-amd64.zip` &mdash; Standalone GUI Ingestor & Analyzer
