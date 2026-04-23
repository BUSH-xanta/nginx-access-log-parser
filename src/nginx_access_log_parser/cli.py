from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .analyzer import analyze_log
from .models import AnalysisResult
from .monitor import run_monitor
from .reports import (
    write_csv_suspicious_events,
    write_json_report,
    write_markdown_report,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze Nginx access logs and run real-time monitoring."
    )

    subparsers = parser.add_subparsers(dest="command")

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an Nginx access log and generate reports.",
    )
    analyze_parser.add_argument(
        "--log",
        required=True,
        help="Path to Nginx access.log file. Supports plain .log and .gz files.",
    )
    analyze_parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of top items to include in summary. Default: 10.",
    )
    analyze_parser.add_argument(
        "--markdown",
        default="reports/nginx-access-report.md",
        help="Path to Markdown report output. Default: reports/nginx-access-report.md.",
    )
    analyze_parser.add_argument(
        "--json",
        default="reports/nginx-access-report.json",
        help="Path to JSON report output. Default: reports/nginx-access-report.json.",
    )
    analyze_parser.add_argument(
        "--csv",
        default="reports/suspicious-events.csv",
        help="Path to CSV suspicious events output. Default: reports/suspicious-events.csv.",
    )
    analyze_parser.add_argument(
        "--no-markdown",
        action="store_true",
        help="Do not create Markdown report.",
    )
    analyze_parser.add_argument(
        "--no-json",
        action="store_true",
        help="Do not create JSON report.",
    )
    analyze_parser.add_argument(
        "--no-csv",
        action="store_true",
        help="Do not create CSV report.",
    )
    analyze_parser.set_defaults(func=handle_analyze)

    monitor_parser = subparsers.add_parser(
        "monitor",
        help="Monitor an Nginx access log in real time.",
    )
    monitor_parser.add_argument(
        "--log",
        required=True,
        help="Path to a plain text Nginx access.log file.",
    )
    monitor_parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Polling interval in seconds. Default: 1.0.",
    )
    monitor_parser.add_argument(
        "--from-start",
        action="store_true",
        help="Start monitoring from the beginning of the file instead of the end.",
    )
    monitor_parser.add_argument(
        "--jsonl",
        default=None,
        help="Optional path to append suspicious events in JSONL format.",
    )
    monitor_parser.set_defaults(func=handle_monitor)

    return parser


def validate_log_path(path: Path, allow_missing: bool = False) -> int:
    if path.exists() and not path.is_file():
        print(f"Error: path is not a file: {path}")
        return 1

    if not path.exists() and not allow_missing:
        print(f"Error: log file does not exist: {path}")
        return 1

    return 0


def print_analysis_summary(result: AnalysisResult, top_limit: int) -> None:
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
    if not result.top_ips:
        print("  No data")
    else:
        for item in result.top_ips[:top_limit]:
            print(f"  {item['ip']}: {item['requests']} requests")

    print()
    print("HTTP status codes:")
    if not result.status_codes:
        print("  No data")
    else:
        for status, count in result.status_codes.items():
            print(f"  {status}: {count}")

    print()
    print("HTTP methods:")
    if not result.methods:
        print("  No data")
    else:
        for method, count in result.methods.items():
            print(f"  {method}: {count}")

    print()
    print("Top requested paths:")
    if not result.top_paths:
        print("  No data")
    else:
        for item in result.top_paths[:top_limit]:
            print(f"  {item['path']}: {item['requests']} requests")

    print()
    print("Top User-Agents:")
    if not result.top_user_agents:
        print("  No data")
    else:
        for item in result.top_user_agents[:top_limit]:
            print(f"  {item['user_agent']}: {item['requests']} requests")

    print()
    print("Suspicious IP addresses:")
    if not result.suspicious_ips:
        print("  No suspicious IPs found")
    else:
        for item in result.suspicious_ips[:top_limit]:
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
        for item in result.not_found_ips[:top_limit]:
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
        for item in result.forbidden_ips[:top_limit]:
            print(
                f"  {item['ip']}: "
                f"{item['forbidden_count']} 403 responses, "
                f"{item['unique_403_paths']} unique paths, "
                f"{item['total_requests']} total requests"
            )

    print()


def handle_analyze(args: argparse.Namespace) -> int:
    log_path = Path(args.log)

    validation_error = validate_log_path(log_path, allow_missing=False)
    if validation_error != 0:
        return validation_error

    if args.top < 1:
        print("Error: --top must be greater than 0")
        return 1

    result = analyze_log(log_path, top_limit=args.top)
    print_analysis_summary(result, args.top)

    if not args.no_markdown:
        markdown_report_path = Path(args.markdown)
        write_markdown_report(result, markdown_report_path)
        print(f"Markdown report saved: {markdown_report_path}")

    if not args.no_json:
        json_report_path = Path(args.json)
        write_json_report(result, json_report_path)
        print(f"JSON report saved: {json_report_path}")

    if not args.no_csv:
        csv_report_path = Path(args.csv)
        write_csv_suspicious_events(result, csv_report_path)
        print(f"CSV suspicious events saved: {csv_report_path}")

    return 0


def handle_monitor(args: argparse.Namespace) -> int:
    log_path = Path(args.log)

    validation_error = validate_log_path(log_path, allow_missing=True)
    if validation_error != 0:
        return validation_error

    jsonl_path = Path(args.jsonl) if args.jsonl else None

    return run_monitor(
        path=log_path,
        interval=args.interval,
        from_start=args.from_start,
        jsonl_output_path=jsonl_path,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    return args.func(args)