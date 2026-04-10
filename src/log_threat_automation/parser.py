from __future__ import annotations

import json
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .models import Event, ParseError, ParsedInput


TIMESTAMP_FIELDS = ("timestamp", "@timestamp", "time", "event_time")


def parse_input(path: str) -> ParsedInput:
    if path == "-":
        import sys

        return parse_lines(sys.stdin)

    input_path = Path(path)
    with input_path.open("r", encoding="utf-8") as handle:
        return parse_lines(handle)


def parse_lines(lines: Iterable[str]) -> ParsedInput:
    events: list[Event] = []
    errors: list[ParseError] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = parse_line(line)
            events.append(to_event(payload))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            errors.append(
                ParseError(
                    line_number=line_number,
                    raw_line=line,
                    error=str(exc),
                )
            )
    return ParsedInput(events=events, errors=errors)


def parse_line(line: str) -> dict[str, object]:
    if line.startswith("{"):
        return json.loads(line)

    payload: dict[str, object] = {}
    for token in shlex.split(line):
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        payload[key] = value
    payload.setdefault("message", line)
    return payload


def to_event(payload: dict[str, object]) -> Event:
    timestamp_value = next(
        (payload.get(field) for field in TIMESTAMP_FIELDS if payload.get(field)),
        None,
    )
    timestamp = parse_timestamp(timestamp_value)
    host = str(payload.get("host", "unknown-host"))
    service = str(payload.get("service", payload.get("app", "unknown-service")))
    action = str(payload.get("action", payload.get("event_type", "unknown")))
    status = str(payload.get("status", payload.get("result", "unknown")))
    source_ip = optional_string(
        payload.get("source_ip")
        or payload.get("ip")
        or payload.get("client_ip")
        or payload.get("sender_ip")
    )
    user = optional_string(
        payload.get("user")
        or payload.get("username")
        or payload.get("recipient")
        or payload.get("target_user")
    )
    message = str(payload.get("message", payload.get("subject", payload.get("command", ""))))
    bytes_out = parse_int(payload.get("bytes_out") or payload.get("size") or 0)

    reserved = {
        "host",
        "service",
        "app",
        "action",
        "event_type",
        "status",
        "result",
        "source_ip",
        "ip",
        "client_ip",
        "sender_ip",
        "user",
        "username",
        "recipient",
        "target_user",
        "message",
        "subject",
        "command",
        "bytes_out",
        "size",
        *TIMESTAMP_FIELDS,
    }
    metadata = {key: value for key, value in payload.items() if key not in reserved}

    return Event(
        timestamp=timestamp,
        host=host,
        service=service,
        action=action,
        status=status,
        source_ip=source_ip,
        user=user,
        message=message,
        bytes_out=bytes_out,
        metadata=metadata,
        raw=payload,
    )


def parse_timestamp(value: object) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    text = str(value).strip()
    if text.isdigit():
        return datetime.fromtimestamp(float(text), tz=timezone.utc)

    normalized = text.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_int(value: object) -> int:
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def optional_string(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
