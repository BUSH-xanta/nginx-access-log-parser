#!/usr/bin/env python3
"""
Nginx Access Log Parser

Basic version:
- reads a log file;
- counts total lines;
- prints a simple summary.

Usage:
    python src/nginx_access_log_parser.py --log examples/access.log
"""

from __future__ import annotations

import argparse
from pathlib import Path


def count_lines(path: Path) -> int:
    total_lines = 0

    with path.open("r", encoding="utf-8", errors="replace") as file:
        for _ in file:
            total_lines += 1

    return total_lines


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze Nginx access.log files."
    )

    parser.add_argument(
        "--log",
        required=True,
        help="Path to Nginx access.log file.",
    )

    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    log_path = Path(args.log)

    if not log_path.exists():
        print(f"Error: log file does not exist: {log_path}")
        return 1

    if not log_path.is_file():
        print(f"Error: path is not a file: {log_path}")
        return 1

    total_lines = count_lines(log_path)

    print()
    print("Nginx Access Log Parser")
    print("=" * 32)
    print(f"Log file: {log_path}")
    print(f"Total lines: {total_lines}")
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())