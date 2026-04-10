from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Event:
    timestamp: datetime
    host: str
    service: str
    action: str
    status: str
    source_ip: str | None
    user: str | None
    message: str
    bytes_out: int
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParseError:
    line_number: int
    raw_line: str
    error: str


@dataclass(slots=True)
class ParsedInput:
    events: list[Event]
    errors: list[ParseError] = field(default_factory=list)


@dataclass(slots=True)
class Incident:
    incident_id: str
    rule_id: str
    title: str
    severity: str
    event: Event
    reason: str
    response_plan: list[str]
    context: dict[str, Any] = field(default_factory=dict)
    mitre_tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ResponseResult:
    action: str
    target: str | None
    status: str
    details: str
    incident_id: str | None = None
