from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path

from .detectors import detect_suspicious_reasons
from .models import AnalysisResult, SuspiciousEvent
from .parser import parse_line
from .reader import open_log_file


def analyze_log(path: Path, top_limit: int = 10) -> AnalysisResult:
    total_lines = 0
    parsed_lines = 0
    failed_lines = 0

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

    time_values: list[str] = []

    for line in open_log_file(path):
        total_lines += 1

        entry = parse_line(line)

        if entry is None:
            failed_lines += 1
            continue

        parsed_lines += 1

        if entry.time_iso is not None:
            time_values.append(entry.time_iso)

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

        reasons = detect_suspicious_reasons(entry)

        for reason in reasons:
            suspicious_ip_counter[entry.ip] += 1
            suspicious_events.append(
                SuspiciousEvent(
                    ip=entry.ip,
                    time=entry.time_iso,
                    method=entry.method,
                    path=entry.path,
                    status=entry.status,
                    reason=reason,
                    user_agent=entry.user_agent,
                    raw_line=entry.raw_line,
                )
            )

    time_values.sort()
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
        suspicious_events=[asdict(event) for event in suspicious_events],
        suspicious_ips=suspicious_ips,
        not_found_ips=not_found_ips,
        forbidden_ips=forbidden_ips,
    )