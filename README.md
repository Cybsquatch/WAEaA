# WAEaA

**Windows Artifacts Extractor and Analyzer**: a proprietary incident-response
toolkit made of three components.

| Component | Platform | Interface | Purpose |
|---|---|---|---|
| `waeaa.exe` / `waeaa-legacy.exe` | Windows 7 → 11, Server 2008R2 → 2025 | CLI + GUI (single executable) | triage collection of forensic artefacts into `<HOSTNAME>.zip` |
| `waeaa-linux-*` | Debian/Ubuntu, RHEL family, SUSE, Arch, Amazon Linux | CLI + terminal menu (single executable) | distro-aware triage collection into `<HOSTNAME>.zip` |
| WAEaA Ingestor | analyst workstation | GUI only | parses the archive, runs detections and builds an HTML report |

> **Authorised use only.** Run the collector only on systems for which you hold
> explicit, lawful authorisation. Collected artefacts may contain personal data
> (GDPR and similar regulations apply).

## Repository layout

```
collector/   Go module: Windows + Linux collector (single code base)
ingestor/    Python package: analyst GUI, parsers, detection engine, report
scripts/     build scripts
.github/     CI (lint, tests and builds for every toolchain)
```

## Building

Requirements: Go (latest) and Go 1.20.14 for the Windows 7 legacy build,
Python 3.11+ for the ingestor.

```powershell
go install golang.org/dl/go1.20.14@latest; go1.20.14 download
.\scripts\build.ps1 -Version 0.1.0
```

## Testing

```powershell
cd collector; go test ./...; go1.20.14 test ./...
cd ingestor;  .\.venv\Scripts\python -m pytest
```

## Collector usage (preview)

```text
waeaa -o E:\evidence -r triage --authorized --case-id IR-2026-001 --examiner "J. Doe"
waeaa --list-rules
waeaa --help
```

Run it without arguments to open the graphical interface (Windows) or the
interactive terminal menu (Linux).

## License

Proprietary. See [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
