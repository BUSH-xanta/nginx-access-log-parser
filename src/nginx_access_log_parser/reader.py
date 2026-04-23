from __future__ import annotations

import gzip
import time
from pathlib import Path
from typing import Iterator


def open_log_file(path: Path) -> Iterator[str]:
    """
    Open plain text log files and gzipped log archives.
    """
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as file:
            for line in file:
                yield line
    else:
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                yield line


def follow_log_file(
    path: Path,
    interval: float = 1.0,
    from_start: bool = False,
) -> Iterator[str]:
    """
    Follow a plain text log file in a tail -f style.

    - If from_start is False, start from the end of the file.
    - If the file is rotated or truncated, reopen it automatically.
    """
    if path.suffix == ".gz":
        raise ValueError("Real-time monitoring does not support .gz files.")

    current_file = None
    current_signature = None
    first_open = True
    position = 0

    try:
        while True:
            if current_file is None:
                try:
                    current_file = path.open("r", encoding="utf-8", errors="replace")

                    if first_open and not from_start:
                        current_file.seek(0, 2)
                    else:
                        current_file.seek(0)

                    position = current_file.tell()

                    stat = path.stat()
                    current_signature = (stat.st_dev, stat.st_ino)
                    first_open = False
                except FileNotFoundError:
                    time.sleep(interval)
                    continue

            line = current_file.readline()

            if line:
                position = current_file.tell()
                yield line
                continue

            time.sleep(interval)

            try:
                latest_stat = path.stat()
            except FileNotFoundError:
                current_file.close()
                current_file = None
                current_signature = None
                position = 0
                continue

            latest_signature = (latest_stat.st_dev, latest_stat.st_ino)
            rotated = current_signature is not None and latest_signature != current_signature
            truncated = latest_stat.st_size < position

            if rotated or truncated:
                current_file.close()
                current_file = None
                current_signature = None
                position = 0
    finally:
        if current_file is not None:
            current_file.close()