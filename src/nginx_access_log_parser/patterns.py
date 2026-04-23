from __future__ import annotations

import re

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