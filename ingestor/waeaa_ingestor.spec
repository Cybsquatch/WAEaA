# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build specification for standalone WAEaA Ingestor executable."""

import sys
from pathlib import Path

block_cipher = None

root_dir = Path.cwd()
locales_dir = root_dir / "waeaa_ingestor" / "i18n" / "locales"

datas = [
    (str(locales_dir / "*.json"), "waeaa_ingestor/i18n/locales"),
]

a = Analysis(
    ["waeaa_ingestor/__main__.py"],
    pathex=[str(root_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="waeaa-ingestor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Windowed GUI application, no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
