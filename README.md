# Nginx Access Log Parser

🔎 A defensive security tool for parsing, analyzing, and monitoring Nginx access logs.

This project processes Nginx `access.log` files, extracts useful statistics, highlights suspicious activity, and generates reports in Markdown, JSON, CSV, and JSONL formats.

It is designed as a lightweight command-line utility for blue team practice, log triage, simple threat hunting, and portfolio demonstration.

## 📌 Why this project

Web server logs often contain early indicators of reconnaissance, automated scanning, and opportunistic attacks. This tool helps transform raw Nginx access logs into structured, readable, security-oriented output without external dependencies or network access.

It is useful for:

- defensive log analysis
- identifying suspicious request patterns
- spotting scanner-like User-Agent values
- finding repeated 404 and 403 activity
- monitoring new suspicious events in real time
- generating reports for review and investigation

## ⚙️ Features

- Parse Nginx access logs
- Support common and combined log formats
- Read plain `.log` files and `.gz` archives
- Count total, parsed, and failed lines
- Show top source IP addresses
- Show top requested paths
- Count HTTP status codes
- Count HTTP methods
- Detect suspicious paths
- Detect suspicious User-Agent values
- Identify IP addresses with many 404 responses
- Identify IP addresses with many 403 responses
- Export a Markdown report
- Export a JSON report
- Export a CSV file with suspicious events
- Run real-time monitoring mode for live log files
- Append live suspicious events to JSONL
- Use only the Python standard library

## 🗂️ Project structure

```text
nginx-access-log-parser/
├── README.md
├── requirements.txt
├── .gitignore
├── examples/
│   └── access.log
├── reports/
│   └── .gitkeep
└── src/
    ├── main.py
    ├── legacy_single_file_version.py
    └── nginx_access_log_parser/
        ├── __init__.py
        ├── __main__.py
        ├── analyzer.py
        ├── cli.py
        ├── detectors.py
        ├── models.py
        ├── monitor.py
        ├── parser.py
        ├── patterns.py
        ├── reader.py
        └── reports.py
```

## 🧰 Requirements

- Python 3.10 or newer
- No third-party libraries required

## 🚀 Quick start

Run analysis against the included demo log:

```bash
python src/main.py analyze --log examples/access.log
```

Parse a gzipped archive:

```bash
python src/main.py analyze --log /var/log/nginx/access.log.1.gz
```

Use a custom top limit:

```bash
python src/main.py analyze --log examples/access.log --top 5
```

Write reports to custom paths:

```bash
python src/main.py analyze \
  --log examples/access.log \
  --markdown reports/custom-report.md \
  --json reports/custom-report.json \
  --csv reports/custom-events.csv
```

Disable selected outputs:

```bash
python src/main.py analyze --log examples/access.log --no-json --no-csv
```

## 📡 Real-time monitoring mode

Monitor a live Nginx access log:

```bash
python src/main.py monitor --log /var/log/nginx/access.log
```

Start from the beginning of the file:

```bash
python src/main.py monitor --log examples/access.log --from-start
```

Append suspicious live events to JSONL:

```bash
python src/main.py monitor \
  --log /var/log/nginx/access.log \
  --jsonl reports/live-events.jsonl
```

Use a custom polling interval:

```bash
python src/main.py monitor \
  --log /var/log/nginx/access.log \
  --interval 0.5
```

### Notes about monitor mode

- real-time monitoring supports plain text log files only
- `.gz` archives are supported for analysis mode, but not for live monitoring
- the monitor prints only suspicious events
- stop monitoring with `Ctrl+C`

## 📁 Default output files

By default, analysis mode creates:

```text
reports/nginx-access-report.md
reports/nginx-access-report.json
reports/suspicious-events.csv
```

In monitor mode, JSONL output is optional and only created if `--jsonl` is provided.

## 🖥️ Example console output

### Analyze mode

```text
Nginx Access Log Parser
================================
Log file: examples/access.log
Total lines: 3
Parsed lines: 3
Failed lines: 0
Time start: 2026-04-21T18:00:01+03:00
Time end: 2026-04-21T18:01:10+03:00
Total requests: 3
Suspicious events: 2

Top IP addresses:
  192.168.1.10: 1 requests
  192.168.1.11: 1 requests
  45.90.12.33: 1 requests

HTTP status codes:
  200: 2
  404: 1

HTTP methods:
  GET: 3

Top requested paths:
  /: 1 requests
  /contacts: 1 requests
  /.env: 1 requests

Top User-Agents:
  Mozilla/5.0 (Windows NT 10.0; Win64; x64): 1 requests
  Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X): 1 requests
  curl/8.1.2: 1 requests

Suspicious IP addresses:
  45.90.12.33: 2 suspicious events, 1 total requests

IP addresses with many 404 responses:
  45.90.12.33: 1 404 responses, 1 unique paths, 1 total requests

IP addresses with many 403 responses:
  No 403 responses found

Markdown report saved: reports/nginx-access-report.md
JSON report saved: reports/nginx-access-report.json
CSV suspicious events saved: reports/suspicious-events.csv
```

### Monitor mode

```text
Nginx Access Log Parser - Real-Time Monitor
============================================
Log file: examples/access.log
Polling interval: 1.0 seconds
Start position: beginning of file
JSONL output: reports/live-events.jsonl
Monitoring started. Press Ctrl+C to stop.

[ALERT] time=2026-04-21T18:01:10+03:00 ip=45.90.12.33 status=404 method=GET path="/.env" reason="suspicious path keyword: /.env" user_agent="curl/8.1.2"
[ALERT] time=2026-04-21T18:01:10+03:00 ip=45.90.12.33 status=404 method=GET path="/.env" reason="suspicious user-agent: curl" user_agent="curl/8.1.2"

Stopping monitor...
Observed new lines: 3
Parsed lines: 3
Failed lines: 0
Suspicious events: 2
```

## 📊 Output reports

### Markdown report

The Markdown report is intended for human-readable review.

It includes:

- summary table
- HTTP status code statistics
- HTTP method statistics
- top IP addresses
- top requested paths
- top User-Agent values
- suspicious IP addresses
- IP addresses with many 404 responses
- IP addresses with many 403 responses
- suspicious events table

Default path:

```text
reports/nginx-access-report.md
```

### JSON report

The JSON report is intended for structured processing and automation.

Default path:

```text
reports/nginx-access-report.json
```

### CSV report

The CSV report contains suspicious events and can be opened in Excel, LibreOffice Calc, or imported into other tools.

Default path:

```text
reports/suspicious-events.csv
```

CSV fields:

```text
ip
time
method
path
status
reason
user_agent
raw_line
```

### JSONL live event output

The optional JSONL file stores suspicious events produced during monitor mode, one JSON object per line.

Example path:

```text
reports/live-events.jsonl
```

## 🧠 Detection logic

The parser currently focuses on two main indicators.

### 1. Suspicious paths

The request path is checked against known risky keywords, sensitive endpoints, and common probe targets.

Examples:

```text
/.env
/.git
/wp-login.php
/wp-admin
/xmlrpc.php
/phpmyadmin
/admin
/backup.sql
/server-status
/actuator/env
/cgi-bin
```

### 2. Suspicious User-Agent values

The `User-Agent` header is checked for names commonly associated with scanners, automation tools, or scripted requests.

Examples:

```text
sqlmap
nikto
nmap
masscan
zgrab
gobuster
ffuf
wpscan
python-requests
curl
wget
```

A single request can produce multiple suspicious events if more than one indicator matches.

## 🧪 Example access log

The repository includes a small demo log file:

```text
examples/access.log
```

It contains both normal requests and intentionally suspicious requests for demonstration.

Example suspicious requests:

```text
GET /.env
GET /.git/config
GET /wp-login.php
GET /phpmyadmin
GET /backup.sql
GET /admin
GET /actuator/env
```

## 🖥️ Running on a real server

Analyze a live Nginx access log:

```bash
sudo python src/main.py analyze --log /var/log/nginx/access.log
```

Analyze an archived log:

```bash
sudo python src/main.py analyze --log /var/log/nginx/access.log.1.gz
```

Monitor a live log in real time:

```bash
sudo python src/main.py monitor --log /var/log/nginx/access.log
```

If you do not want to run the script with `sudo`, copy the log to your home directory first:

```bash
sudo cp /var/log/nginx/access.log ~/access.log
sudo chown "$USER":"$USER" ~/access.log
python src/main.py analyze --log ~/access.log
```

## 💼 Portfolio value

This project demonstrates practical blue team and engineering skills, including:

- Python scripting
- Linux log analysis
- Nginx log format handling
- basic web attack indicator detection
- defensive automation
- report generation in multiple formats
- real-time log monitoring
- command-line tool design
- modular Python project structure
- working with compressed log files

## 🔐 Security note

This tool is intended only for defensive analysis of logs from systems you own or are authorized to assess.

It does not scan targets, send network requests, exploit vulnerabilities, or interact with external infrastructure. It only analyzes existing log files.

## ⚠️ Limitations

This is a lightweight parser, not a full SIEM or monitoring platform.

Current limitations:

- no GeoIP enrichment
- no HTML dashboard
- no correlation with firewall or WAF logs
- no alerting system beyond console output and optional JSONL logging
- no support for custom JSON Nginx log format yet

## 🔮 Future improvements

Possible next steps:

- add HTML report generation
- add charts
- add GeoIP enrichment
- add support for JSON-formatted Nginx logs
- add unit tests
- add severity levels for suspicious events
- add configuration file for custom detection rules
- add Telegram or email notifications
- add threshold-based alerting
- add Docker support

## 📄 License

Released for educational and defensive security purposes.