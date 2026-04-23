from __future__ import annotations

from datetime import datetime
from typing import Optional

from .models import LogEntry
from .patterns import NGINX_COMBINED_LOG_PATTERN, NGINX_COMMON_LOG_PATTERN


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