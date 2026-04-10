from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta
import ipaddress
from uuid import uuid4

from .models import Event, Incident


def build_incident(
    rule_id: str,
    title: str,
    severity: str,
    event: Event,
    reason: str,
    response_plan: list[str],
    context: dict[str, object] | None = None,
    mitre_tags: list[str] | None = None,
) -> Incident:
    base_context = {
        "event_summary": {
            "timestamp": event.timestamp.isoformat(),
            "host": event.host,
            "service": event.service,
            "action": event.action,
            "status": event.status,
            "source_ip": event.source_ip,
            "user": event.user,
            "bytes_out": event.bytes_out,
        },
        "related_entities": {
            "host": event.host,
            "service": event.service,
            "source_ip": event.source_ip,
            "user": event.user,
        },
        "evidence": {
            "message": event.message,
            "metadata": dict(event.metadata),
            "raw": dict(event.raw),
        },
    }
    return Incident(
        incident_id=str(uuid4()),
        rule_id=rule_id,
        title=title,
        severity=severity,
        event=event,
        reason=reason,
        response_plan=response_plan,
        context=_merge_context(base_context, context or {}),
        mitre_tags=mitre_tags or [],
    )


class BaseRule(ABC):
    rule_id = "base"
    title = "Base rule"

    def __init__(self, config: dict[str, object]) -> None:
        self.config = config
        self.exclude_users = {str(item).lower() for item in config.get("exclude_users", [])}
        self.exclude_hosts = {str(item).lower() for item in config.get("exclude_hosts", [])}
        self.exclude_services = {str(item).lower() for item in config.get("exclude_services", [])}
        self.exclude_source_ips = {str(item) for item in config.get("exclude_source_ips", [])}
        self.exclude_source_networks = [
            ipaddress.ip_network(str(item), strict=False)
            for item in config.get("exclude_source_networks", [])
        ]

    @abstractmethod
    def evaluate(self, event: Event) -> Incident | None:
        raise NotImplementedError

    def export_state(self) -> dict[str, object] | None:
        return None

    def import_state(self, payload: dict[str, object]) -> None:
        return None

    def is_excluded(self, event: Event) -> bool:
        user = (event.user or "").lower()
        host = event.host.lower()
        service = event.service.lower()
        if user and user in self.exclude_users:
            return True
        if host in self.exclude_hosts:
            return True
        if service in self.exclude_services:
            return True
        if event.source_ip and event.source_ip in self.exclude_source_ips:
            return True
        if event.source_ip and self.exclude_source_networks:
            try:
                address = ipaddress.ip_address(event.source_ip)
            except ValueError:
                return False
            if any(address in network for network in self.exclude_source_networks):
                return True
        return False


class BruteForceRule(BaseRule):
    rule_id = "brute_force"
    title = "Brute-force authentication attempts"

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        self.failures = int(config.get("failures", 5))
        self.window = timedelta(minutes=int(config.get("window_minutes", 10)))
        self.failures_by_actor: dict[str, deque] = defaultdict(deque)

    def evaluate(self, event: Event) -> Incident | None:
        if self.is_excluded(event):
            return None
        if event.action.lower() not in {"login", "auth", "signin"}:
            return None
        if event.status.lower() not in {"failed", "failure", "denied"}:
            return None

        actor = event.source_ip or event.user or "unknown"
        bucket = self.failures_by_actor[actor]
        bucket.append(event.timestamp)
        cutoff = event.timestamp - self.window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) != self.failures:
            return None

        reason = (
            f"{actor} generated {len(bucket)} failed authentication attempts "
            f"within {int(self.window.total_seconds() // 60)} minutes."
        )
        response_plan = ["record_incident", "notify_console"]
        if event.source_ip:
            response_plan.append("block_ip")
        return build_incident(
            self.rule_id,
            self.title,
            "high",
            event,
            reason,
            response_plan,
            {
                "analysis": {
                    "actor": actor,
                    "window_minutes": int(self.window.total_seconds() // 60),
                    "threshold": self.failures,
                    "observed_failures": len(bucket),
                },
                "recent_timestamps": [item.isoformat() for item in bucket],
            },
            ["TA0006 Credential Access", "T1110 Brute Force"],
        )

    def export_state(self) -> dict[str, object] | None:
        return {
            "failures_by_actor": {
                actor: [item.isoformat() for item in bucket]
                for actor, bucket in self.failures_by_actor.items()
                if bucket
            }
        }

    def import_state(self, payload: dict[str, object]) -> None:
        saved = payload.get("failures_by_actor", {})
        if not isinstance(saved, dict):
            return
        restored: dict[str, deque] = defaultdict(deque)
        for actor, timestamps in saved.items():
            if not isinstance(timestamps, list):
                continue
            restored[str(actor)] = deque(_parse_state_timestamp(item) for item in timestamps)
        self.failures_by_actor = restored


class CredentialCompromiseRule(BaseRule):
    rule_id = "credential_compromise"
    title = "Credential compromise after repeated failures"

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        self.failures = int(config.get("failures", 3))
        self.window = timedelta(minutes=int(config.get("window_minutes", 15)))
        self.failures_by_actor: dict[str, deque] = defaultdict(deque)

    def evaluate(self, event: Event) -> Incident | None:
        if self.is_excluded(event):
            return None
        if event.action.lower() not in {"login", "auth", "signin"}:
            return None

        actor = _actor_key(event)
        bucket = self.failures_by_actor[actor]
        cutoff = event.timestamp - self.window

        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        status = event.status.lower()
        if status in {"failed", "failure", "denied"}:
            bucket.append(event.timestamp)
            return None
        if status not in {"success", "ok", "allowed"}:
            return None
        if len(bucket) < self.failures:
            return None

        prior_failures = len(bucket)
        bucket.clear()

        response_plan = ["record_incident", "notify_console"]
        if event.user:
            response_plan.extend(["disable_user", "quarantine_user"])
        if event.source_ip:
            response_plan.append("block_ip")
        response_plan.append("isolate_host")
        return build_incident(
            self.rule_id,
            self.title,
            "critical",
            event,
            (
                f"Successful authentication was observed for {actor} after "
                f"{prior_failures} failed attempts within "
                f"{int(self.window.total_seconds() // 60)} minutes."
            ),
            response_plan,
            {
                "analysis": {
                    "actor": actor,
                    "window_minutes": int(self.window.total_seconds() // 60),
                    "threshold": self.failures,
                    "prior_failed_attempts": prior_failures,
                    "success_status": event.status,
                }
            },
            [
                "TA0001 Initial Access",
                "TA0006 Credential Access",
                "T1078 Valid Accounts",
                "T1110 Brute Force",
            ],
        )

    def export_state(self) -> dict[str, object] | None:
        return {
            "failures_by_actor": {
                actor: [item.isoformat() for item in bucket]
                for actor, bucket in self.failures_by_actor.items()
                if bucket
            }
        }

    def import_state(self, payload: dict[str, object]) -> None:
        saved = payload.get("failures_by_actor", {})
        if not isinstance(saved, dict):
            return
        restored: dict[str, deque] = defaultdict(deque)
        for actor, timestamps in saved.items():
            if not isinstance(timestamps, list):
                continue
            restored[str(actor)] = deque(_parse_state_timestamp(item) for item in timestamps)
        self.failures_by_actor = restored


class SuspiciousCommandRule(BaseRule):
    rule_id = "suspicious_command"
    title = "Suspicious command execution"

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        self.keywords = [str(item).lower() for item in config.get("keywords", [])]

    def evaluate(self, event: Event) -> Incident | None:
        if self.is_excluded(event):
            return None
        blob = " ".join(
            [
                event.action.lower(),
                event.message.lower(),
                str(event.metadata.get("command", "")).lower(),
            ]
        )
        for keyword in self.keywords:
            if keyword not in blob:
                continue
            response_plan = ["record_incident", "notify_console"]
            if event.user:
                response_plan.append("quarantine_user")
            if event.source_ip:
                response_plan.append("block_ip")
            return build_incident(
                self.rule_id,
                self.title,
                "critical",
                event,
                f"Detected suspicious command pattern '{keyword}'.",
                response_plan,
                {
                    "analysis": {
                        "matched_keyword": keyword,
                        "blob": blob,
                    }
                },
                ["TA0002 Execution", "T1059 Command and Scripting Interpreter"],
            )
        return None


class PrivilegeEscalationRule(BaseRule):
    rule_id = "privilege_escalation"
    title = "Privilege escalation activity"

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        self.watch_actions = {str(item).lower() for item in config.get("watch_actions", [])}
        self.sensitive_users = {str(item).lower() for item in config.get("sensitive_users", [])}

    def evaluate(self, event: Event) -> Incident | None:
        if self.is_excluded(event):
            return None
        action = event.action.lower()
        message = event.message.lower()
        user = (event.user or "").lower()

        matched = action in self.watch_actions or "sudo" in message or "admin" in message
        if not matched:
            return None
        if event.status.lower() in {"failed", "denied"}:
            return None

        severity = "high"
        if user in self.sensitive_users or "granted" in message:
            severity = "critical"

        response_plan = ["record_incident", "notify_console"]
        if event.user:
            response_plan.append("quarantine_user")
        return build_incident(
            self.rule_id,
            self.title,
            severity,
            event,
            "Privileged operation or escalation signal detected in authentication or role logs.",
            response_plan,
            {
                "analysis": {
                    "watch_actions": sorted(self.watch_actions),
                    "sensitive_user_match": user in self.sensitive_users,
                    "message_contains_granted": "granted" in message,
                }
            },
            ["TA0004 Privilege Escalation", "T1548 Abuse Elevation Control Mechanism"],
        )


class DataExfiltrationRule(BaseRule):
    rule_id = "data_exfiltration"
    title = "Potential data exfiltration"

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        self.bytes_threshold = int(config.get("bytes_threshold", 5000000))

    def evaluate(self, event: Event) -> Incident | None:
        if self.is_excluded(event):
            return None
        if event.bytes_out < self.bytes_threshold:
            return None

        response_plan = ["record_incident", "notify_console"]
        if event.user:
            response_plan.append("quarantine_user")
        if event.source_ip:
            response_plan.append("block_ip")
        return build_incident(
            self.rule_id,
            self.title,
            "critical",
            event,
            f"Outbound transfer volume reached {event.bytes_out} bytes.",
            response_plan,
            {
                "analysis": {
                    "bytes_out": event.bytes_out,
                    "threshold": self.bytes_threshold,
                    "over_threshold_bytes": event.bytes_out - self.bytes_threshold,
                }
            },
            ["TA0010 Exfiltration", "T1041 Exfiltration Over C2 Channel"],
        )


class LateralMovementRule(BaseRule):
    rule_id = "lateral_movement"
    title = "Potential lateral movement across multiple hosts"

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        self.unique_hosts = int(config.get("unique_hosts", 3))
        self.window = timedelta(minutes=int(config.get("window_minutes", 10)))
        self.watch_actions = {str(item).lower() for item in config.get("watch_actions", [])}
        self.watch_services = {str(item).lower() for item in config.get("watch_services", [])}
        self.exclude_users = {str(item).lower() for item in config.get("exclude_users", [])}
        self.events_by_actor: dict[str, deque[tuple]] = defaultdict(deque)

    def evaluate(self, event: Event) -> Incident | None:
        if self.is_excluded(event):
            return None
        if event.status.lower() not in {"success", "ok", "allowed"}:
            return None

        user = (event.user or "").lower()
        if user in self.exclude_users:
            return None

        action = event.action.lower()
        service = event.service.lower()
        if self.watch_actions and action not in self.watch_actions:
            return None
        if self.watch_services and service not in self.watch_services:
            return None

        actor = event.user or event.source_ip
        if not actor:
            return None

        bucket = self.events_by_actor[actor]
        bucket.append((event.timestamp, event.host, event.source_ip))
        cutoff = event.timestamp - self.window
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

        unique_hosts = sorted({host for _, host, _ in bucket})
        if len(unique_hosts) != self.unique_hosts:
            return None

        response_plan = ["record_incident", "notify_console", "isolate_host"]
        if event.user:
            response_plan.append("quarantine_user")
        if event.source_ip:
            response_plan.append("block_ip")
        recent_activity = [
            {
                "timestamp": timestamp.isoformat(),
                "host": host,
                "source_ip": source_ip,
            }
            for timestamp, host, source_ip in bucket
        ]
        bucket.clear()
        return build_incident(
            self.rule_id,
            self.title,
            "critical",
            event,
            (
                f"{actor} reached {len(unique_hosts)} hosts within "
                f"{int(self.window.total_seconds() // 60)} minutes: {', '.join(unique_hosts)}."
            ),
            response_plan,
            {
                "analysis": {
                    "actor": actor,
                    "window_minutes": int(self.window.total_seconds() // 60),
                    "threshold": self.unique_hosts,
                    "observed_unique_hosts": len(unique_hosts),
                },
                "unique_hosts": unique_hosts,
                "recent_activity": recent_activity,
            },
            ["TA0008 Lateral Movement", "T1021 Remote Services"],
        )

    def export_state(self) -> dict[str, object] | None:
        return {
            "events_by_actor": {
                actor: [
                    {
                        "timestamp": timestamp.isoformat(),
                        "host": host,
                        "source_ip": source_ip,
                    }
                    for timestamp, host, source_ip in bucket
                ]
                for actor, bucket in self.events_by_actor.items()
                if bucket
            }
        }

    def import_state(self, payload: dict[str, object]) -> None:
        saved = payload.get("events_by_actor", {})
        if not isinstance(saved, dict):
            return
        restored: dict[str, deque[tuple]] = defaultdict(deque)
        for actor, records in saved.items():
            if not isinstance(records, list):
                continue
            queue: deque[tuple] = deque()
            for record in records:
                if not isinstance(record, dict):
                    continue
                timestamp = _parse_state_timestamp(record.get("timestamp"))
                queue.append(
                    (
                        timestamp,
                        str(record.get("host", "unknown-host")),
                        _optional_state_string(record.get("source_ip")),
                    )
                )
            restored[str(actor)] = queue
        self.events_by_actor = restored


class PhishingRule(BaseRule):
    rule_id = "phishing_activity"
    title = "Phishing or email-borne social engineering activity"

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        self.keywords = [
            str(item).lower()
            for item in config.get(
                "keywords",
                [
                    "phish",
                    "credential harvest",
                    "malicious attachment",
                    "malicious link",
                    "spoofed sender",
                    "mailbox compromise",
                ],
            )
        ]
        self.min_indicator_hits = int(config.get("min_indicator_hits", 2))
        self.watch_services = {str(item).lower() for item in config.get("watch_services", ["email", "mail", "mail-gateway"])}
        self.watch_actions = {
            str(item).lower()
            for item in config.get(
                "watch_actions",
                ["phishing_report", "mail_quarantine", "mail_blocked", "credential_submission"],
            )
        }
        self.verdict_values = {
            str(item).lower()
            for item in config.get("verdict_values", ["phish", "malicious", "high-confidence-phish", "blocked"])
        }

    def evaluate(self, event: Event) -> Incident | None:
        if self.is_excluded(event):
            return None

        service = event.service.lower()
        action = event.action.lower()
        verdict = str(event.metadata.get("verdict", "")).lower()
        blob = " ".join(
            [
                service,
                action,
                event.message.lower(),
                str(event.metadata.get("subject", "")).lower(),
                str(event.metadata.get("sender", "")).lower(),
                str(event.metadata.get("url", "")).lower(),
                verdict,
            ]
        )

        if self.watch_services and service not in self.watch_services and action not in self.watch_actions:
            if not any(keyword in blob for keyword in self.keywords):
                return None

        indicator_hits = 0
        indicator_hits += sum(1 for keyword in self.keywords if keyword in blob)
        if action in self.watch_actions:
            indicator_hits += 1
        if verdict in self.verdict_values:
            indicator_hits += 2
        if indicator_hits < self.min_indicator_hits:
            return None

        response_plan = ["record_incident", "notify_console"]
        severity = "high"
        if event.user:
            response_plan.append("quarantine_user")
        if "credential" in blob or action == "credential_submission":
            severity = "critical"
            if event.user:
                response_plan.append("disable_user")
        if event.source_ip:
            response_plan.append("block_ip")
        return build_incident(
            self.rule_id,
            self.title,
            severity,
            event,
            "Mail security telemetry matched phishing indicators that exceeded the confidence threshold.",
            response_plan,
            {
                "analysis": {
                    "indicator_hits": indicator_hits,
                    "minimum_required_hits": self.min_indicator_hits,
                    "verdict": verdict or None,
                    "watched_service": service,
                    "watched_action": action,
                }
            },
            ["TA0001 Initial Access", "T1566 Phishing", "T1566.001 Spearphishing Attachment", "T1566.002 Spearphishing Link"],
        )


class LogTamperingRule(BaseRule):
    rule_id = "log_tampering"
    title = "Log tampering attempt"

    def __init__(self, config: dict[str, object]) -> None:
        super().__init__(config)
        self.keywords = [str(item).lower() for item in config.get("keywords", [])]

    def evaluate(self, event: Event) -> Incident | None:
        if self.is_excluded(event):
            return None
        blob = f"{event.action.lower()} {event.message.lower()}"
        for keyword in self.keywords:
            if keyword not in blob:
                continue
            response_plan = ["record_incident", "notify_console"]
            if event.user:
                response_plan.append("quarantine_user")
            return build_incident(
                self.rule_id,
                self.title,
                "critical",
                event,
                f"Matched log tampering indicator '{keyword}'.",
                response_plan,
                {
                    "analysis": {
                        "matched_keyword": keyword,
                        "blob": blob,
                    }
                },
                ["TA0005 Defense Evasion", "T1070 Indicator Removal on Host"],
            )
        return None


RULE_TYPES = {
    "brute_force": BruteForceRule,
    "credential_compromise": CredentialCompromiseRule,
    "suspicious_command": SuspiciousCommandRule,
    "privilege_escalation": PrivilegeEscalationRule,
    "data_exfiltration": DataExfiltrationRule,
    "lateral_movement": LateralMovementRule,
    "phishing_activity": PhishingRule,
    "log_tampering": LogTamperingRule,
}


def build_rules(config: dict[str, object]) -> list[BaseRule]:
    rules: list[BaseRule] = []
    for rule_id, rule_config in config.items():
        if not isinstance(rule_config, dict):
            continue
        if not rule_config.get("enabled", True):
            continue
        rule_type = RULE_TYPES.get(rule_id)
        if rule_type:
            rules.append(rule_type(rule_config))
    return rules


def _actor_key(event: Event) -> str:
    if event.user and event.source_ip:
        return f"{event.user}@{event.source_ip}"
    return event.user or event.source_ip or "unknown"


def _merge_context(base: dict[str, object], extra: dict[str, object]) -> dict[str, object]:
    merged = dict(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_context(merged[key], value)
        else:
            merged[key] = value
    return merged


def _parse_state_timestamp(value: object) -> datetime:
    text = str(value).replace("Z", "+00:00")
    return datetime.fromisoformat(text)


def _optional_state_string(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
