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
import gzip
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

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

@dataclass
class LogEntry:
    ip: str
    time_raw: str
    time_iso: Optional[str]
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referer: str
    user_agent: str
    raw_line: str

@dataclass
class SuspiciousEvent:
    ip: str
    time: Optional[str]
    method: str
    path: str
    status: int
    reason: str
    user_agent: str
    raw_line: str

SUSPICIOUS_PATH_KEYWORDS = [
    "/.env",
    "/.git",
    "/.svn",
    "/.hg",
    "/wp-login.php",
    "/wp-admin",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/pma",
    "/admin",
    "/administrator",
    "/login",
    "/config",
    "/backup",
    "/backups",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/server-status",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/debug",
    "/console",
    "/shell",
    "/cmd",
    "/vendor/phpunit",
    "/cgi-bin",
    "/boaform",
    "/HNAP1",
]

SUSPICIOUS_EXTENSIONS = [
    ".sql",
    ".bak",
    ".old",
    ".backup",
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".rar",
    ".7z",
    ".env",
    ".ini",
    ".conf",
    ".log",
]

SUSPICIOUS_USER_AGENT_KEYWORDS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "dirbuster",
    "gobuster",
    "ffuf",
    "acunetix",
    "nessus",
    "openvas",
    "wpscan",
    "python-requests",
    "curl",
    "wget",
]

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

def parse_line(line: str) -> Optional[LogEntry]:
    line = line.rstrip("\n")

    match = NGINX_COMBINED_LOG_PATTERN.match(line)

    if not match:
        match = NGINX_COMMON_LOG_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()

    method, path, protocol = parse_request(data.get("request", "-"))

    referer = data.get("referer") or "-"
    user_agent = data.get("user_agent") or "-"

    time_raw = data["time"]
    time_iso = parse_nginx_time(time_raw)

    return LogEntry(
        ip=data["ip"],
        time_raw=time_raw,
        time_iso=time_iso,
        method=method,
        path=path,
        protocol=protocol,
        status=int(data["status"]),
        size=parse_size(data["size"]),
        referer=referer,
        user_agent=user_agent,
        raw_line=line,
    )

def parse_nginx_time(value: str) -> Optional[str]:
    """
    Convert Nginx time format to ISO format.

    Example:
        21/Apr/2026:18:12:45 +0300
        2026-04-21T18:12:45+03:00
    """
    try:
        parsed = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
        return parsed.isoformat()
    except ValueError:
        return None


def parse_request(value: str) -> tuple[str, str, str]:
    """
    Parse HTTP request from Nginx access log.

    Examples:
        GET /index.html HTTP/1.1
        POST /login HTTP/2.0
        -
    """
    if not value or value == "-":
        return "-", "-", "-"

    parts = value.split()

    if len(parts) == 3:
        return parts[0], parts[1], parts[2]

    if len(parts) == 2:
        return parts[0], parts[1], "-"

    if len(parts) == 1:
        return parts[0], "-", "-"

    method = parts[0]
    protocol = parts[-1]
    path = " ".join(parts[1:-1])

    return method, path, protocol


def parse_size(value: str) -> int:
    """
    Convert response size to integer.

    Nginx can store empty size as "-".
    """
    if value == "-" or value == "":
        return 0

    try:
        return int(value)
    except ValueError:
        return 0

def open_log_file(path: Path) -> Iterable[str]:
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

def is_suspicious_path(path: str) -> Optional[str]:
    path_lower = path.lower()

    for keyword in SUSPICIOUS_PATH_KEYWORDS:
        if keyword.lower() in path_lower:
            return f"suspicious path keyword: {keyword}"

    for extension in SUSPICIOUS_EXTENSIONS:
        if path_lower.endswith(extension.lower()):
            return f"suspicious file extension: {extension}"

    return None


def is_suspicious_user_agent(user_agent: str) -> Optional[str]:
    user_agent_lower = user_agent.lower()

    for keyword in SUSPICIOUS_USER_AGENT_KEYWORDS:
        if keyword.lower() in user_agent_lower:
            return f"suspicious user-agent: {keyword}"

    return None

def analyze_parsing(path: Path) -> dict[str, int]:
    total_lines = 0
    parsed_lines = 0
    failed_lines = 0

    with path.open("r", encoding="utf-8", errors="replace") as file:
        for line in open_log_file(path):
            total_lines += 1

            parsed = parse_line(line)

            if parsed is None:
                failed_lines += 1
            else:
                parsed_lines += 1

    return {
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "failed_lines": failed_lines,
    }

def analyze_basic_stats(path: Path, top_limit: int = 10) -> dict[str, object]:
    total_lines = 0
    parsed_lines = 0
    failed_lines = 0

    status_counter: Counter[int] = Counter()
    method_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    path_counter: Counter[str] = Counter()
    user_agent_counter: Counter[str] = Counter()

    suspicious_events: list[SuspiciousEvent] = []
    suspicious_ip_counter: Counter[str] = Counter()

    for line in open_log_file(path):
        total_lines += 1

        entry = parse_line(line)

        if entry is None:
            failed_lines += 1
            continue

        parsed_lines += 1

        status_counter[entry.status] += 1
        method_counter[entry.method] += 1
        ip_counter[entry.ip] += 1
        path_counter[entry.path] += 1
        user_agent_counter[entry.user_agent] += 1

        path_reason = is_suspicious_path(entry.path)
        ua_reason = is_suspicious_user_agent(entry.user_agent)

        if path_reason:
            suspicious_ip_counter[entry.ip] += 1
            suspicious_events.append(
                SuspiciousEvent(
                    ip=entry.ip,
                    time=entry.time_iso,
                    method=entry.method,
                    path=entry.path,
                    status=entry.status,
                    reason=path_reason,
                    user_agent=entry.user_agent,
                    raw_line=entry.raw_line,
                )
            )

        if ua_reason:
            suspicious_ip_counter[entry.ip] += 1
            suspicious_events.append(
                SuspiciousEvent(
                    ip=entry.ip,
                    time=entry.time_iso,
                    method=entry.method,
                    path=entry.path,
                    status=entry.status,
                    reason=ua_reason,
                    user_agent=entry.user_agent,
                    raw_line=entry.raw_line,
                )
            )

    return {
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "failed_lines": failed_lines,
        "status_codes": status_counter,
        "methods": method_counter,
        "top_ips": ip_counter,
        "top_paths": path_counter,
        "top_user_agents": user_agent_counter,
        "suspicious_events": suspicious_events,
        "suspicious_ips": suspicious_ip_counter,
        "top_limit": top_limit,
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

    result = analyze_basic_stats(log_path)

    print()
    print("Nginx Access Log Parser")
    print("=" * 32)
    print(f"Log file: {log_path}")
    print(f"Total lines: {result['total_lines']}")
    print(f"Parsed lines: {result['parsed_lines']}")
    print(f"Failed lines: {result['failed_lines']}")

    print()
    print("Top IP addresses:")
    for ip, count in result["top_ips"].most_common(10):
        print(f"  {ip}: {count} requests")

    print()
    print("HTTP status codes:")
    for status, count in result["status_codes"].most_common():
        print(f"  {status}: {count}")

    print()
    print("HTTP methods:")
    for method, count in result["methods"].most_common():
        print(f"  {method}: {count}")

    print()
    print("Top requested paths:")
    for path, count in result["top_paths"].most_common(10):
        print(f"  {path}: {count} requests")

    print()

if __name__ == "__main__":
    raise SystemExit(main())