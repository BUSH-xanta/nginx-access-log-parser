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
import csv
import gzip
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
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

@dataclass
class AnalysisResult:
    log_file: str
    total_lines: int
    parsed_lines: int
    failed_lines: int
    time_start: Optional[str]
    time_end: Optional[str]
    total_requests: int
    status_codes: dict[str, int]
    methods: dict[str, int]
    top_ips: list[dict[str, int | str]]
    top_paths: list[dict[str, int | str]]
    top_user_agents: list[dict[str, int | str]]
    suspicious_events: list[dict[str, int | str | None]]
    suspicious_ips: list[dict[str, int | str]]
    not_found_ips: list[dict[str, int | str]]
    forbidden_ips: list[dict[str, int | str]]

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

def analyze_log(path: Path, top_limit: int = 10) -> AnalysisResult:
    total_lines = 0
    parsed_lines = 0
    failed_lines = 0

    entries: list[LogEntry] = []
    suspicious_events: list[SuspiciousEvent] = []

    status_counter: Counter[int] = Counter()
    method_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    path_counter: Counter[str] = Counter()
    user_agent_counter: Counter[str] = Counter()

    suspicious_ip_counter: Counter[str] = Counter()
    not_found_ip_counter: Counter[str] = Counter()
    forbidden_ip_counter: Counter[str] = Counter()

    ip_404_paths: dict[str, set[str]] = defaultdict(set)
    ip_403_paths: dict[str, set[str]] = defaultdict(set)

    for line in open_log_file(path):
        total_lines += 1

        entry = parse_line(line)

        if entry is None:
            failed_lines += 1
            continue

        parsed_lines += 1
        entries.append(entry)

        status_counter[entry.status] += 1
        method_counter[entry.method] += 1
        ip_counter[entry.ip] += 1
        path_counter[entry.path] += 1
        user_agent_counter[entry.user_agent] += 1

        if entry.status == 404:
            not_found_ip_counter[entry.ip] += 1
            ip_404_paths[entry.ip].add(entry.path)

        if entry.status == 403:
            forbidden_ip_counter[entry.ip] += 1
            ip_403_paths[entry.ip].add(entry.path)

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

    time_values = sorted(
        [entry.time_iso for entry in entries if entry.time_iso is not None]
    )

    time_start = time_values[0] if time_values else None
    time_end = time_values[-1] if time_values else None

    suspicious_ips = [
        {
            "ip": ip,
            "events": count,
            "total_requests": ip_counter[ip],
        }
        for ip, count in suspicious_ip_counter.most_common(top_limit)
    ]

    not_found_ips = [
        {
            "ip": ip,
            "not_found_count": count,
            "unique_404_paths": len(ip_404_paths[ip]),
            "total_requests": ip_counter[ip],
        }
        for ip, count in not_found_ip_counter.most_common(top_limit)
    ]

    forbidden_ips = [
        {
            "ip": ip,
            "forbidden_count": count,
            "unique_403_paths": len(ip_403_paths[ip]),
            "total_requests": ip_counter[ip],
        }
        for ip, count in forbidden_ip_counter.most_common(top_limit)
    ]

    return AnalysisResult(
        log_file=str(path),
        total_lines=total_lines,
        parsed_lines=parsed_lines,
        failed_lines=failed_lines,
        time_start=time_start,
        time_end=time_end,
        total_requests=parsed_lines,
        status_codes={str(key): value for key, value in status_counter.most_common()},
        methods={key: value for key, value in method_counter.most_common()},
        top_ips=[
            {"ip": ip, "requests": count}
            for ip, count in ip_counter.most_common(top_limit)
        ],
        top_paths=[
            {"path": item_path, "requests": count}
            for item_path, count in path_counter.most_common(top_limit)
        ],
        top_user_agents=[
            {"user_agent": user_agent, "requests": count}
            for user_agent, count in user_agent_counter.most_common(top_limit)
        ],
        suspicious_events=[
            asdict(event)
            for event in suspicious_events
        ],
        suspicious_ips=suspicious_ips,
        not_found_ips=not_found_ips,
        forbidden_ips=forbidden_ips,
    )

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze Nginx access.log files and generate security-oriented reports."
    )

    parser.add_argument(
        "--log",
        required=True,
        help="Path to Nginx access.log file. Supports plain .log and .gz files.",
    )

    return parser

def write_json_report(result: AnalysisResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(asdict(result), file, ensure_ascii=False, indent=2)

def write_csv_suspicious_events(result: AnalysisResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "ip",
        "time",
        "method",
        "path",
        "status",
        "reason",
        "user_agent",
        "raw_line",
    ]

    with output_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for event in result.suspicious_events:
            writer.writerow(event)

def markdown_escape(value: object) -> str:
    if value is None:
        return ""

    return str(value).replace("|", "\\|").replace("\n", " ")


def markdown_table(headers: list[str], rows: list[list[object]]) -> str:
    if not rows:
        return "_No data._\n"

    header_line = "| " + " | ".join(markdown_escape(header) for header in headers) + " |"
    separator_line = "| " + " | ".join(["---"] * len(headers)) + " |"

    row_lines = []
    for row in rows:
        row_lines.append("| " + " | ".join(markdown_escape(value) for value in row) + " |")

    return "\n".join([header_line, separator_line, *row_lines]) + "\n"


def write_markdown_report(result: AnalysisResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    suspicious_event_rows = [
        [
            event["ip"],
            event["time"],
            event["method"],
            event["path"],
            event["status"],
            event["reason"],
        ]
        for event in result.suspicious_events[:30]
    ]

    content = f"""# Nginx Access Log Report

## Summary

| Metric | Value |
|---|---|
| Log file | `{result.log_file}` |
| Total lines | {result.total_lines} |
| Parsed lines | {result.parsed_lines} |
| Failed lines | {result.failed_lines} |
| Time start | {result.time_start} |
| Time end | {result.time_end} |
| Total requests | {result.total_requests} |
| Suspicious events | {len(result.suspicious_events)} |

## HTTP Status Codes

{markdown_table(
    ["Status", "Count"],
    [[status, count] for status, count in result.status_codes.items()]
)}

## HTTP Methods

{markdown_table(
    ["Method", "Count"],
    [[method, count] for method, count in result.methods.items()]
)}

## Top IP Addresses

{markdown_table(
    ["IP", "Requests"],
    [[item["ip"], item["requests"]] for item in result.top_ips]
)}

## Top Requested Paths

{markdown_table(
    ["Path", "Requests"],
    [[item["path"], item["requests"]] for item in result.top_paths]
)}

## Top User-Agents

{markdown_table(
    ["User-Agent", "Requests"],
    [[item["user_agent"], item["requests"]] for item in result.top_user_agents]
)}

## Suspicious IP Addresses

{markdown_table(
    ["IP", "Suspicious Events", "Total Requests"],
    [
        [item["ip"], item["events"], item["total_requests"]]
        for item in result.suspicious_ips
    ]
)}

## IP Addresses With Many 404 Responses

{markdown_table(
    ["IP", "404 Count", "Unique 404 Paths", "Total Requests"],
    [
        [
            item["ip"],
            item["not_found_count"],
            item["unique_404_paths"],
            item["total_requests"],
        ]
        for item in result.not_found_ips
    ]
)}

## IP Addresses With Many 403 Responses

{markdown_table(
    ["IP", "403 Count", "Unique 403 Paths", "Total Requests"],
    [
        [
            item["ip"],
            item["forbidden_count"],
            item["unique_403_paths"],
            item["total_requests"],
        ]
        for item in result.forbidden_ips
    ]
)}

## Suspicious Events

Shown first 30 suspicious events.

{markdown_table(
    ["IP", "Time", "Method", "Path", "Status", "Reason"],
    suspicious_event_rows
)}

## Notes

This report is intended for defensive analysis of your own infrastructure logs.
"""

    with output_path.open("w", encoding="utf-8") as file:
        file.write(content)

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

    result = analyze_log(log_path)

    print()
    print("Nginx Access Log Parser")
    print("=" * 32)
    print(f"Log file: {result.log_file}")
    print(f"Total lines: {result.total_lines}")
    print(f"Parsed lines: {result.parsed_lines}")
    print(f"Failed lines: {result.failed_lines}")
    print(f"Time start: {result.time_start}")
    print(f"Time end: {result.time_end}")
    print(f"Total requests: {result.total_requests}")
    print(f"Suspicious events: {len(result.suspicious_events)}")

    print()
    print("Top IP addresses:")
    for item in result.top_ips[:10]:
        print(f"  {item['ip']}: {item['requests']} requests")

    print()
    print("HTTP status codes:")
    for status, count in result.status_codes.items():
        print(f"  {status}: {count}")

    print()
    print("HTTP methods:")
    for method, count in result.methods.items():
        print(f"  {method}: {count}")

    print()
    print("Top requested paths:")
    for item in result.top_paths[:10]:
        print(f"  {item['path']}: {item['requests']} requests")

    print()
    print("Top User-Agents:")
    for item in result.top_user_agents[:10]:
        print(f"  {item['user_agent']}: {item['requests']} requests")

    print()
    print("Suspicious IP addresses:")
    if not result.suspicious_ips:
        print("  No suspicious IPs found")
    else:
        for item in result.suspicious_ips[:10]:
            print(
                f"  {item['ip']}: "
                f"{item['events']} suspicious events, "
                f"{item['total_requests']} total requests"
            )

    print()
    print("IP addresses with many 404 responses:")
    if not result.not_found_ips:
        print("  No 404 responses found")
    else:
        for item in result.not_found_ips:
            print(
                f"  {item['ip']}: "
                f"{item['not_found_count']} 404 responses, "
                f"{item['unique_404_paths']} unique paths, "
                f"{item['total_requests']} total requests"
            )

    print()
    print("IP addresses with many 403 responses:")
    if not result.forbidden_ips:
        print("  No 403 responses found")
    else:
        for item in result.forbidden_ips:
            print(
                f"  {item['ip']}: "
                f"{item['forbidden_count']} 403 responses, "
                f"{item['unique_403_paths']} unique paths, "
                f"{item['total_requests']} total requests"
            )

    print()

    markdown_report_path = Path("reports/nginx-access-report.md")
    write_markdown_report(result, markdown_report_path)
    print(f"Markdown report saved: {markdown_report_path}")

    json_report_path = Path("reports/nginx-access-report.json")
    write_json_report(result, json_report_path)
    print(f"JSON report saved: {json_report_path}")

    csv_report_path = Path("reports/suspicious-events.csv")
    write_csv_suspicious_events(result, csv_report_path)
    print(f"CSV suspicious events saved: {csv_report_path}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())