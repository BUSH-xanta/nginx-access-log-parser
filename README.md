# Nginx Access Log Parser

🔎 A defensive security tool for parsing and analyzing Nginx access logs.

This project processes Nginx `access.log` files, extracts useful statistics, highlights suspicious activity, and generates reports in Markdown, JSON, and CSV formats.

It is designed as a lightweight command-line utility for blue team practice, log triage, and portfolio demonstration.

## 📌 Why this project

Web server logs often contain early indicators of reconnaissance, automated scanning, and opportunistic attacks. This tool helps transform raw Nginx access logs into structured, readable, security-oriented reports without external dependencies or network access.

It is useful for:

- defensive log analysis
- identifying suspicious request patterns
- spotting scanner-like User-Agent values
- finding repeated 404 and 403 activity
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
    └── nginx_access_log_parser.py
```

## 🧰 Requirements

- Python 3.10 or newer
- No third-party libraries required

## 🚀 Quick start

Run the parser against the included demo log:

```bash
python src/nginx_access_log_parser.py --log examples/access.log
```

Parse a gzipped archive:

```bash
python src/nginx_access_log_parser.py --log /var/log/nginx/access.log.1.gz
```

Use a custom top limit:

```bash
python src/nginx_access_log_parser.py --log examples/access.log --top 5
```

Write reports to custom paths:

```bash
python src/nginx_access_log_parser.py \
  --log examples/access.log \
  --markdown reports/custom-report.md \
  --json reports/custom-report.json \
  --csv reports/custom-events.csv
```

Disable selected outputs:

```bash
python src/nginx_access_log_parser.py --log examples/access.log --no-json --no-csv
```

## 📁 Default output files

By default, the tool creates:

```text
reports/nginx-access-report.md
reports/nginx-access-report.json
reports/suspicious-events.csv
```

## 🖥️ Example console output

```text
Nginx Access Log Parser
================================
Log file: examples/access.log
Total lines: 12
Parsed lines: 12
Failed lines: 0
Time start: 2026-04-21T18:00:01+03:00
Time end: 2026-04-21T18:04:15+03:00
Total requests: 12
Suspicious events: 14

Top IP addresses:
  45.90.12.33: 5 requests
  185.77.88.99: 3 requests
  192.168.1.10: 1 request

HTTP status codes:
  404: 6
  200: 4
  403: 1
  401: 1

HTTP methods:
  GET: 11
  POST: 1

Top requested paths:
  /: 1 request
  /contacts: 1 request
  /.env: 1 request
  /.git/config: 1 request
  /wp-login.php: 1 request

Suspicious IP addresses:
  45.90.12.33: 10 suspicious events, 5 total requests
  185.77.88.99: 4 suspicious events, 3 total requests
  198.51.100.23: 2 suspicious events, 2 total requests

IP addresses with many 404 responses:
  45.90.12.33: 5 404 responses, 5 unique paths, 5 total requests

IP addresses with many 403 responses:
  185.77.88.99: 1 403 response, 1 unique path, 3 total requests

Markdown report saved: reports/nginx-access-report.md
JSON report saved: reports/nginx-access-report.json
CSV suspicious events saved: reports/suspicious-events.csv
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
sudo python src/nginx_access_log_parser.py --log /var/log/nginx/access.log
```

Analyze an archived log:

```bash
sudo python src/nginx_access_log_parser.py --log /var/log/nginx/access.log.1.gz
```

If you do not want to run the script with `sudo`, copy the log to your home directory first:

```bash
sudo cp /var/log/nginx/access.log ~/access.log
sudo chown "$USER":"$USER" ~/access.log
python src/nginx_access_log_parser.py --log ~/access.log
```

## 💼 Portfolio value

This project demonstrates practical blue team and engineering skills, including:

- Python scripting
- Linux log analysis
- Nginx log format handling
- basic web attack indicator detection
- defensive automation
- report generation in multiple formats
- command-line tool design
- working with compressed log files

## 🔐 Security note

This tool is intended only for defensive analysis of logs from systems you own or are authorized to assess.

It does not scan targets, send network requests, exploit vulnerabilities, or interact with external infrastructure. It only analyzes existing log files.

## ⚠️ Limitations

This is a lightweight parser, not a full SIEM or monitoring platform.

Current limitations:

- no GeoIP enrichment
- no real-time monitoring
- no HTML dashboard
- no correlation with firewall or WAF logs
- no alerting system
- no support for custom JSON Nginx log format yet

## 🔮 Future improvements

Possible next steps:

- add HTML report generation
- add charts
- add GeoIP enrichment
- add support for JSON-formatted Nginx logs
- add real-time monitoring mode
- add Docker support
- add unit tests
- add severity levels for suspicious events
- add configuration file for custom detection rules
- add Telegram or email notifications

## 📄 License

Released for educational and defensive security purposes.