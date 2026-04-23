from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from .models import AnalysisResult


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


def write_json_report(result: AnalysisResult, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(asdict(result), file, ensure_ascii=False, indent=2)


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