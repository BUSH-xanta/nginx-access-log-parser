from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .detectors import detect_suspicious_reasons
from .models import SuspiciousEvent
from .parser import parse_line
from .reader import follow_log_file


def append_jsonl_event(event: SuspiciousEvent, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")


def format_monitor_event(event: SuspiciousEvent) -> str:
    time_value = event.time or "-"
    return (
        f"[ALERT] time={time_value} "
        f"ip={event.ip} "
        f"status={event.status} "
        f"method={event.method} "
        f'path="{event.path}" '
        f'reason="{event.reason}" '
        f'user_agent="{event.user_agent}"'
    )


def run_monitor(
    path: Path,
    interval: float = 1.0,
    from_start: bool = False,
    jsonl_output_path: Path | None = None,
) -> int:
    if path.suffix == ".gz":
        print("Error: real-time monitoring does not support .gz files")
        return 1

    if interval <= 0:
        print("Error: --interval must be greater than 0")
        return 1

    observed_lines = 0
    parsed_lines = 0
    failed_lines = 0
    suspicious_count = 0

    print()
    print("Nginx Access Log Parser - Real-Time Monitor")
    print("=" * 44)
    print(f"Log file: {path}")
    print(f"Polling interval: {interval} seconds")
    print(f"Start position: {'beginning of file' if from_start else 'end of file'}")

    if jsonl_output_path is not None:
        print(f"JSONL output: {jsonl_output_path}")

    print("Monitoring started. Press Ctrl+C to stop.")
    print()

    try:
        for line in follow_log_file(path, interval=interval, from_start=from_start):
            observed_lines += 1

            entry = parse_line(line)

            if entry is None:
                failed_lines += 1
                continue

            parsed_lines += 1

            reasons = detect_suspicious_reasons(entry)

            for reason in reasons:
                suspicious_count += 1

                event = SuspiciousEvent(
                    ip=entry.ip,
                    time=entry.time_iso,
                    method=entry.method,
                    path=entry.path,
                    status=entry.status,
                    reason=reason,
                    user_agent=entry.user_agent,
                    raw_line=entry.raw_line,
                )

                print(format_monitor_event(event))

                if jsonl_output_path is not None:
                    append_jsonl_event(event, jsonl_output_path)

    except KeyboardInterrupt:
        print()
        print("Stopping monitor...")
        print(f"Observed new lines: {observed_lines}")
        print(f"Parsed lines: {parsed_lines}")
        print(f"Failed lines: {failed_lines}")
        print(f"Suspicious events: {suspicious_count}")
        return 0