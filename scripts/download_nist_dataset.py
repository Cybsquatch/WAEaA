"""Download the Compromised Windows Server 2022 dataset from NIST/Figshare in parallel."""

from __future__ import annotations

import concurrent.futures
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


def download_single_file(name: str, url: str, expected_size: int, max_retries: int = 10) -> bool:
    dest_path = DEST_DIR / name

    for attempt in range(1, max_retries + 1):
        existing_size = dest_path.stat().st_size if dest_path.is_file() else 0
        if existing_size == expected_size:
            print(f"[OK] {name} already complete ({existing_size:,} bytes).", flush=True)
            return True
        elif existing_size > expected_size:
            print(f"[WARN] {name} size ({existing_size}) > expected ({expected_size}). Truncating...", flush=True)
            dest_path.unlink()
            existing_size = 0

        headers = {"User-Agent": "Mozilla/5.0"}
        mode = "wb"
        if existing_size > 0:
            headers["Range"] = f"bytes={existing_size}-"
            mode = "ab"
            print(f"[RESUME] {name} (Attempt {attempt}): resuming from {existing_size:,} / {expected_size:,} bytes...", flush=True)
        else:
            print(f"[START] {name} (Attempt {attempt}): starting ({expected_size / (1024*1024):.1f} MB)...", flush=True)

        req = urllib.request.Request(url, headers=headers)
        start_time = time.time()
        downloaded = existing_size
        last_print = start_time

        try:
            with urllib.request.urlopen(req, timeout=30) as resp, dest_path.open(mode) as f:
                chunk_size = 512 * 1024  # 512 KB
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    f.flush()
                    downloaded += len(chunk)
                    now = time.time()
                    if now - last_print >= 5.0 or downloaded >= expected_size:
                        elapsed = now - start_time
                        speed = (downloaded - existing_size) / (elapsed if elapsed > 0 else 1) / (1024 * 1024)
                        pct = (downloaded / expected_size) * 100 if expected_size else 0
                        print(
                            f"  [{name}] {pct:.1f}% ({downloaded / (1024*1024):.1f}/{expected_size / (1024*1024):.1f} MB) @ {speed:.2f} MB/s",
                            flush=True,
                        )
                        last_print = now

            final_size = dest_path.stat().st_size if dest_path.is_file() else 0
            if final_size == expected_size:
                print(f"[DONE] Completed {name} ({final_size:,} bytes)!", flush=True)
                return True
            else:
                print(f"[INCOMPLETE] {name} got {final_size:,} / {expected_size:,} bytes. Retrying...", flush=True)
                time.sleep(2)
        except Exception as e:
            print(f"[ERROR] {name} error on attempt {attempt}: {e}. Retrying in 3s...", flush=True)
            time.sleep(3)

    return False


def main() -> None:
    DEST_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Destination: {DEST_DIR}", flush=True)

    pending_files = []
    for name, url, size in FILES:
        p = DEST_DIR / name
        if not p.is_file() or p.stat().st_size != size:
            pending_files.append((name, url, size))
        else:
            print(f"[EXISTS] {name} is already verified complete ({size:,} bytes).")

    if not pending_files:
        print("\nAll files are already downloaded and verified!", flush=True)
        return

    print(f"\nDownloading {len(pending_files)} files in parallel (max 3 workers)...", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(download_single_file, name, url, size): name
            for name, url, size in pending_files
        }
        for future in concurrent.futures.as_completed(futures):
            fname = futures[future]
            try:
                success = future.result()
                if not success:
                    print(f"[FAIL] {fname} could not be completed.", file=sys.stderr, flush=True)
            except Exception as exc:
                print(f"[FAIL] {fname} generated an exception: {exc}", file=sys.stderr, flush=True)

    print("\nParallel download job finished. Checking final state...", flush=True)
    all_ok = True
    for name, _, size in FILES:
        p = DEST_DIR / name
        actual = p.stat().st_size if p.is_file() else 0
        if actual != size:
            all_ok = False
            print(f"  MISSING/INCOMPLETE: {name} (have {actual:,}, need {size:,})")
        else:
            print(f"  VERIFIED: {name} ({actual:,} bytes)")

    if all_ok:
        print("\nSUCCESS: All NIST dataset segments are downloaded and verified ready for mounting!", flush=True)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
