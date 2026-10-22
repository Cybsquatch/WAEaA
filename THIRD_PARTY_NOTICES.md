# Third-Party Notices

WAEaA is proprietary software. It only depends on third-party components whose
licenses explicitly allow use in closed-source, commercial products.

## License policy

| Allowed | Conditions |
|---|---|
| MIT, BSD-2/3-Clause, ISC, Apache-2.0, Zlib, PSF, CC0 | keep copyright notice and license text here |
| MPL-2.0 | file-level copyleft: unmodified use only, or publish changes to those files |
| LGPL-2.1/3.0 | **dynamic linking only** (Python packages imported at runtime are fine) |
| Detection Rule License (DRL) 1.1 | rule attribution must be preserved in the rule and in the report |

| Forbidden | Reason |
|---|---|
| GPL, AGPL, SSPL, EUPL, CC-BY-NC, "non-commercial" licenses | would force disclosure of source code or forbid commercial use |
| Any code, rule or configuration file copied from third-party forensic tools or proprietary frameworks | WAEaA re-implements all behaviours independently, it never copies third-party code |

Every new dependency **must** be added to the table below in the same commit
that introduces it.

## Components

### Collector (Go)

| Component | Version | License | Usage |
|---|---|---|---|
| Go standard library | 1.20 / latest | BSD-3-Clause | runtime |

### Ingestor (Python)

| Component | Version | License | Usage |
|---|---|---|---|
| CPython runtime | 3.12 | PSF-2.0 | runtime |
| PySide6 (Qt for Python) | 6.x | LGPL-3.0 (dynamic linking) | GUI |

### Development only (not redistributed)

| Component | License |
|---|---|
| pytest | MIT |
| ruff | MIT |
| mypy | MIT |
| PyInstaller | GPL-2.0 with bootloader exception (explicitly allows proprietary bundling) |
