# Nginx Access Log Parser

Defensive security tool for analyzing Nginx access logs.

The project parses `access.log` files, extracts useful statistics and generates security-oriented reports in Markdown, JSON and CSV formats.

## Features

- Parse Nginx access logs
- Support combined and common log formats
- Support plain `.log` files and `.gz` archives
- Count total, parsed and failed lines
- Show top source IP addresses
- Show top requested paths
- Count HTTP status codes
- Count HTTP methods
- Detect suspicious paths
- Detect suspicious User-Agent values
- Analyze IP addresses with many 404 responses
- Analyze IP addresses with many 403 responses
- Export Markdown report
- Export JSON report
- Export CSV file with suspicious events

## Suspicious indicators

Examples of suspicious paths:

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

Examples of suspicious User-Agent values:

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

## Project structure

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

## Requirements

Python 3.10 or newer is recommended.

The project uses only the Python standard library.

## Usage

Basic usage:

```bash
python src/nginx_access_log_parser.py --log examples/access.log
```

Use a custom top limit:

```bash
python src/nginx_access_log_parser.py --log examples/access.log --top 5
```

Analyze a gzipped log archive:

```bash
python src/nginx_access_log_parser.py --log /var/log/nginx/access.log.1.gz
```

Use custom report paths:

```bash
python src/nginx_access_log_parser.py \
  --log examples/access.log \
  --markdown reports/custom-report.md \
  --json reports/custom-report.json \
  --csv reports/custom-events.csv
```

Disable some reports:

```bash
python src/nginx_access_log_parser.py --log examples/access.log --no-json --no-csv
```

## Default reports

By default, the tool creates:

```text
reports/nginx-access-report.md
reports/nginx-access-report.json
reports/suspicious-events.csv
```

## Example console output

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
  192.168.1.10: 1 requests

HTTP status codes:
  404: 6
  200: 4
  403: 1
  401: 1

HTTP methods:
  GET: 11
  POST: 1

Top requested paths:
  /: 1 requests
  /contacts: 1 requests
  /.env: 1 requests
  /.git/config: 1 requests
  /wp-login.php: 1 requests

Suspicious IP addresses:
  45.90.12.33: 10 suspicious events, 5 total requests
  185.77.88.99: 4 suspicious events, 3 total requests
  198.51.100.23: 2 suspicious events, 2 total requests

IP addresses with many 404 responses:
  45.90.12.33: 5 404 responses, 5 unique paths, 5 total requests

IP addresses with many 403 responses:
  185.77.88.99: 1 403 responses, 1 unique paths, 3 total requests

Markdown report saved: reports/nginx-access-report.md
JSON report saved: reports/nginx-access-report.json
CSV suspicious events saved: reports/suspicious-events.csv
```

## Output files

### Markdown report

The Markdown report is designed for human-readable analysis.

It contains:

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

The JSON report is designed for structured processing.

Default path:

```text
reports/nginx-access-report.json
```

### CSV report

The CSV report contains suspicious events and can be opened in Excel, LibreOffice Calc or imported into other tools.

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

## Example access log

The repository includes a small example log file:

```text
examples/access.log
```

It contains normal requests and several suspicious requests for demonstration purposes.

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

## How detection works

The tool checks two main indicators.

### 1. Suspicious paths

The request path is compared with a list of suspicious keywords and file extensions.

Examples:

```text
/.env
/.git
/wp-login.php
/phpmyadmin
/backup.sql
/server-status
/actuator/env
```

### 2. Suspicious User-Agent values

The User-Agent header is compared with known scanner and automation tool names.

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

A single request can generate more than one suspicious event if both the path and User-Agent look suspicious.

## Use on a real server

Run on a real Nginx access log:

```bash
sudo python src/nginx_access_log_parser.py --log /var/log/nginx/access.log
```

Run on an archived log:

```bash
sudo python src/nginx_access_log_parser.py --log /var/log/nginx/access.log.1.gz
```

If you do not want to run the script with `sudo`, copy the log to your home directory:

```bash
sudo cp /var/log/nginx/access.log ~/access.log
sudo chown "$USER":"$USER" ~/access.log
python src/nginx_access_log_parser.py --log ~/access.log
```

## GitHub portfolio value

This project demonstrates practical defensive security skills:

- Python scripting
- Linux log analysis
- Nginx log format understanding
- Basic web attack indicators
- Defensive automation
- Structured report generation
- Markdown, JSON and CSV exports
- Command-line tool development

## Security note

This tool is intended only for defensive analysis of your own infrastructure logs or logs you are authorized to analyze.

The tool does not scan external targets, does not send network requests and does not exploit vulnerabilities. It only analyzes existing log files.

## Limitations

This tool is not a full SIEM system and does not replace professional monitoring.

Current limitations:

- no GeoIP enrichment
- no real-time monitoring
- no HTML dashboard
- no correlation with firewall logs
- no alerting system
- no support for custom JSON Nginx log format yet

## Ideas for future improvements

Possible next steps:

- Add HTML report generation
- Add charts
- Add GeoIP lookup
- Add support for JSON-formatted Nginx logs
- Add real-time monitoring mode
- Add Dockerfile
- Add unit tests
- Add severity levels for suspicious events
- Add configuration file for custom detection rules
- Add integration with Telegram or email notifications

## License

This project is released for educational and defensive security purposes.