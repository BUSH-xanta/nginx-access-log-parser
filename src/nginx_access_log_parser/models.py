from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


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
    suspicious_events: list[dict[str, object]]
    suspicious_ips: list[dict[str, int | str]]
    not_found_ips: list[dict[str, int | str]]
    forbidden_ips: list[dict[str, int | str]]