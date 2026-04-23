from __future__ import annotations

from .models import LogEntry
from .patterns import (
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_PATH_KEYWORDS,
    SUSPICIOUS_USER_AGENT_KEYWORDS,
)


def is_suspicious_path(path: str) -> str | None:
    path_lower = path.lower()

    for keyword in SUSPICIOUS_PATH_KEYWORDS:
        if keyword.lower() in path_lower:
            return f"suspicious path keyword: {keyword}"

    for extension in SUSPICIOUS_EXTENSIONS:
        if path_lower.endswith(extension.lower()):
            return f"suspicious file extension: {extension}"

    return None


def is_suspicious_user_agent(user_agent: str) -> str | None:
    user_agent_lower = user_agent.lower()

    for keyword in SUSPICIOUS_USER_AGENT_KEYWORDS:
        if keyword.lower() in user_agent_lower:
            return f"suspicious user-agent: {keyword}"

    return None


def detect_suspicious_reasons(entry: LogEntry) -> list[str]:
    reasons: list[str] = []

    path_reason = is_suspicious_path(entry.path)
    if path_reason:
        reasons.append(path_reason)

    ua_reason = is_suspicious_user_agent(entry.user_agent)
    if ua_reason:
        reasons.append(ua_reason)

    return reasons