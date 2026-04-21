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
import re
from pathlib import Path
from typing import Optional

NGINX_COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) '
    r'(?P<ident>\S+) '
    r'(?P<user>\S+) '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+) '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"'
)

NGINX_COMMON_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) '
    r'(?P<ident>\S+) '
    r'(?P<user>\S+) '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) '
    r'(?P<size>\S+)'
)

def count_lines(path: Path) -> int:
    total_lines = 0

    with path.open("r", encoding="utf-8", errors="replace") as file:
        for _ in file:
            total_lines += 1

    return total_lines

def parse_line_raw(line: str) -> Optional[dict[str, str]]:
    line = line.rstrip("\n")

    match = NGINX_COMBINED_LOG_PATTERN.match(line)

    if not match:
        match = NGINX_COMMON_LOG_PATTERN.match(line)

    if not match:
        return None

    return match.groupdict()

def analyze_parsing(path: Path) -> dict[str, int]:
    total_lines = 0
    parsed_lines = 0
    failed_lines = 0

    with path.open("r", encoding="utf-8", errors="replace") as file:
        for line in file:
            total_lines += 1

            parsed = parse_line_raw(line)

            if parsed is None:
                failed_lines += 1
            else:
                parsed_lines += 1

    return {
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "failed_lines": failed_lines,
    }


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

    result = analyze_parsing(log_path)

    print()
    print("Nginx Access Log Parser")
    print("=" * 32)
    print(f"Log file: {log_path}")
    print(f"Total lines: {result['total_lines']}")
    print(f"Parsed lines: {result['parsed_lines']}")
    print(f"Failed lines: {result['failed_lines']}")
    print()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())