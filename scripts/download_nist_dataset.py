"""Download the Compromised Windows Server 2022 dataset from NIST/Figshare."""

from __future__ import annotations

import os
import sys
import time
import urllib.request
from pathlib import Path

DEST_DIR = Path(r"C:\Users\Riccardo\Desktop\NIST_Server2022")

FILES = [
    ("README.txt", "https://ndownloader.figshare.com/files/47197528", 2291),
    ("20240212-decrypted-Windows_Server_2022.E01", "https://ndownloader.figshare.com/files/47113612", 1572845047),
    ("20240212-decrypted-Windows_Server_2022.E02", "https://ndownloader.figshare.com/files/47113750", 1572840830),
    ("20240212-decrypted-Windows_Server_2022.E03", "https://ndownloader.figshare.com/files/47115655", 1572860609),
    ("20240212-decrypted-Windows_Server_2022.E04", "https://ndownloader.figshare.com/files/47115796", 1572844700),
    ("20240212-decrypted-Windows_Server_2022.E05", "https://ndownloader.figshare.com/files/47116210", 1572833361),
    ("20240212-decrypted-Windows_Server_2022.E06", "https://ndownloader.figshare.com/files/47116321", 1572855155),
    ("20240212-decrypted-Windows_Server_2022.E07", "https://ndownloader.figshare.com/files/47116462", 1416831850),
]


def download_file(name: str, url: str, expected_size: int) -> None:
    dest_path = DEST_DIR / name
    existing_size = dest_path.stat().st_size if dest_path.is_file() else 0

    if existing_size == expected_size:
        print(f"[SKIP] {name} already downloaded ({existing_size:,} bytes).")
        return

    headers = {"User-Agent": "Mozilla/5.0"}
    mode = "wb"
    if 0 < existing_size < expected_size:
        headers["Range"] = f"bytes={existing_size}-"
        mode = "ab"
        print(f"[RESUME] Resuming {name} from {existing_size:,} / {expected_size:,} bytes...")
    else:
        existing_size = 0
        print(f"[START] Downloading {name} ({expected_size / (1024*1024):.1f} MB)...")

    req = urllib.request.Request(url, headers=headers)
    start_time = time.time()
    downloaded = existing_size
    last_print = start_time

    try:
        with urllib.request.urlopen(req, timeout=60) as resp, dest_path.open(mode) as f:
            chunk_size = 1024 * 1024  # 1 MB chunk
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                now = time.time()
                if now - last_print >= 2.0 or downloaded == expected_size:
                    elapsed = now - start_time
                    speed = (downloaded - existing_size) / (elapsed if elapsed > 0 else 1) / (1024 * 1024)
                    pct = (downloaded / expected_size) * 100 if expected_size else 0
                    print(
                        f"  -> {name}: {pct:.1f}% ({downloaded / (1024*1024):.1f} / {expected_size / (1024*1024):.1f} MB) @ {speed:.2f} MB/s",
                        flush=True,
                    )
                    last_print = now
        print(f"[OK] Completed {name} ({dest_path.stat().st_size:,} bytes).", flush=True)
    except Exception as e:
        print(f"[ERROR] Failed downloading {name}: {e}", file=sys.stderr, flush=True)


def main() -> None:
    DEST_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Target directory: {DEST_DIR}", flush=True)
    for name, url, size in FILES:
        download_file(name, url, size)
    print("\nAll dataset files downloaded successfully!", flush=True)


if __name__ == "__main__":
    main()
