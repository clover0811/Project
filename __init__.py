from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import Incident, ResponseResult


class ResponseExecutor:
    def __init__(
        self,
        state_dir: str,
        dry_run: bool = True,
        response_config: dict[str, object] | None = None,
    ) -> None:
        response_config = response_config or {}
        self.state_dir = Path(state_dir)
        self.dry_run = dry_run
        self.deduplicate_targets = bool(response_config.get("deduplicate_targets", True))
        self.cooldown = timedelta(minutes=int(response_config.get("cooldown_minutes", 60)))
        self.record_response_history = bool(response_config.get("record_response_history", True))
        notifications = response_config.get("notifications", {})
        chatops = notifications.get("chatops", {}) if isinstance(notifications, dict) else {}
        firewall_api = response_config.get("firewall_api", {})
        self.chatops = chatops if isinstance(chatops, dict) else {}
        self.firewall_api = firewall_api if isinstance(firewall_api, dict) else {}
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def execute(self, incident: Incident) -> list[ResponseResult]:
        results: list[ResponseResult] = []
        actions = list(incident.response_plan)
        if self._chatops_enabled() and "notify_chatops" not in actions:
            insert_at = actions.index("notify_console") + 1 if "notify_console" in actions else len(actions)
            actions.insert(insert_at, "notify_chatops")
        for action in actions:
            handler = getattr(self, action, None)
            if handler is None:
                results.append(
                    ResponseResult(
                        action=action,
                        target=None,
                        status="skipped",
                        details="No handler registered.",
                        incident_id=incident.incident_id,
                    )
                )
                continue
            result = handler(incident)
            results.append(result)
            if self.record_response_history:
                self._append_response_history(incident, result)
        return results

    def record_incident(self, incident: Incident) -> ResponseResult:
        payload = {
            "incident_id": incident.incident_id,
            "rule_id": incident.rule_id,
            "title": incident.title,
            "severity": incident.severity,
            "reason": incident.reason,
            "timestamp": incident.event.timestamp.isoformat(),
            "host": incident.event.host,
            "service": incident.event.service,
            "source_ip": incident.event.source_ip,
            "user": incident.event.user,
            "response_plan": incident.response_plan,
            "context": incident.context,
            "mitre_tags": incident.mitre_tags,
        }
        incident_file = self.state_dir / "incidents.jsonl"
        with incident_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
        return ResponseResult(
            action="record_incident",
            target=incident.incident_id,
            status="executed",
            details=f"Incident stored in {incident_file}.",
            incident_id=incident.incident_id,
        )

    def notify_console(self, incident: Incident) -> ResponseResult:
        summary = (
            f"[{incident.severity.upper()}] {incident.title} | "
            f"host={incident.event.host} service={incident.event.service} "
            f"user={incident.event.user or '-'} ip={incident.event.source_ip or '-'}"
        )
        return ResponseResult(
            action="notify_console",
            target=incident.event.host,
            status="executed",
            details=summary,
            incident_id=incident.incident_id,
        )

    def notify_chatops(self, incident: Incident) -> ResponseResult:
        if not self._chatops_enabled():
            return ResponseResult(
                action="notify_chatops",
                target=None,
                status="skipped",
                details="ChatOps integration is disabled.",
                incident_id=incident.incident_id,
            )

        payload_text = self._format_chatops_message(incident)
        if self.dry_run:
            return ResponseResult(
                action="notify_chatops",
                target="slack,teams",
                status="dry-run",
                details=f"Simulation only. ChatOps notification would send: {payload_text}",
                incident_id=incident.incident_id,
            )

        destinations: list[str] = []
        failures: list[str] = []
        slack_url = str(self.chatops.get("slack_webhook_url", "")).strip()
        teams_url = str(self.chatops.get("teams_webhook_url", "")).strip()

        if slack_url:
            try:
                self._post_json(slack_url, {"text": payload_text}, timeout_seconds=self._chatops_timeout())
                destinations.append("slack")
            except RuntimeError as exc:
                failures.append(f"slack={exc}")

        if teams_url:
            try:
                self._post_json(teams_url, {"text": payload_text}, timeout_seconds=self._chatops_timeout())
                destinations.append("teams")
            except RuntimeError as exc:
                failures.append(f"teams={exc}")

        if destinations and not failures:
            return ResponseResult(
                action="notify_chatops",
                target=",".join(destinations),
                status="executed",
                details=f"Notification delivered to {', '.join(destinations)}.",
                incident_id=incident.incident_id,
            )
        if destinations and failures:
            return ResponseResult(
                action="notify_chatops",
                target=",".join(destinations),
                status="partial-failure",
                details=f"Delivered to {', '.join(destinations)}; failures: {'; '.join(failures)}",
                incident_id=incident.incident_id,
            )
        return ResponseResult(
            action="notify_chatops",
            target=None,
            status="skipped",
            details="No Slack or Teams webhook URL configured.",
            incident_id=incident.incident_id,
        )

    def block_ip(self, incident: Incident) -> ResponseResult:
        target = incident.event.source_ip
        if not target:
            return ResponseResult(
                action="block_ip",
                target=None,
                status="skipped",
                details="No source IP available.",
                incident_id=incident.incident_id,
            )
        result = self._write_state_entry("blocked_ips.json", target, "block_ip", incident.incident_id)
        result = self._apply_firewall_block(target, result)
        return result

    def quarantine_user(self, incident: Incident) -> ResponseResult:
        target = incident.event.user
        if not target:
            return ResponseResult(
                action="quarantine_user",
                target=None,
                status="skipped",
                details="No user available.",
                incident_id=incident.incident_id,
            )
        return self._write_state_entry(
            "quarantined_users.json",
            target,
            "quarantine_user",
            incident.incident_id,
        )

    def isolate_host(self, incident: Incident) -> ResponseResult:
        target = incident.event.host
        if not target:
            return ResponseResult(
                action="isolate_host",
                target=None,
                status="skipped",
                details="No host available.",
                incident_id=incident.incident_id,
            )
        return self._write_state_entry(
            "isolated_hosts.json",
            target,
            "isolate_host",
            incident.incident_id,
        )

    def disable_user(self, incident: Incident) -> ResponseResult:
        target = incident.event.user
        if not target:
            return ResponseResult(
                action="disable_user",
                target=None,
                status="skipped",
                details="No user available.",
                incident_id=incident.incident_id,
            )
        return self._write_state_entry(
            "disabled_users.json",
            target,
            "disable_user",
            incident.incident_id,
        )

    def _chatops_enabled(self) -> bool:
        return bool(self.chatops.get("enabled"))

    def _chatops_timeout(self) -> int:
        return int(self.chatops.get("timeout_seconds", 5))

    def _firewall_enabled(self) -> bool:
        return bool(self.firewall_api.get("enabled"))

    def _format_chatops_message(self, incident: Incident) -> str:
        tags = ", ".join(incident.mitre_tags) if incident.mitre_tags else "none"
        return (
            f"[{incident.severity.upper()}] {incident.title}\n"
            f"Rule: {incident.rule_id}\n"
            f"Host: {incident.event.host} | Service: {incident.event.service}\n"
            f"User: {incident.event.user or '-'} | IP: {incident.event.source_ip or '-'}\n"
            f"Reason: {incident.reason}\n"
            f"MITRE: {tags}"
        )

    def _apply_firewall_block(self, target: str, result: ResponseResult) -> ResponseResult:
        if not self._firewall_enabled():
            return result
        if result.status == "already-contained":
            result.details = f"{result.details} Firewall API skipped because the IP is already contained."
            return result
        if result.status == "dry-run":
            result.details = f"{result.details} Firewall API call simulated."
            return result
        if result.status != "executed":
            return result

        base_url = str(self.firewall_api.get("base_url", "")).strip()
        if not base_url:
            result.status = "partial-failure"
            result.details = f"{result.details} Firewall API enabled but base_url is missing."
            return result

        blocklist_path = str(self.firewall_api.get("blocklist_path", "/blocklist"))
        method = str(self.firewall_api.get("method", "POST")).upper()
        timeout_seconds = int(self.firewall_api.get("timeout_seconds", 5))
        ip_field = str(self.firewall_api.get("ip_field", "ip"))
        headers = {"Content-Type": "application/json"}
        api_key = str(self.firewall_api.get("api_key", "")).strip()
        if api_key:
            headers[str(self.firewall_api.get("api_key_header", "Authorization"))] = api_key
        payload = {ip_field: target}
        url = f"{base_url.rstrip('/')}/{blocklist_path.lstrip('/')}"

        try:
            self._post_json(url, payload, timeout_seconds=timeout_seconds, headers=headers, method=method)
        except RuntimeError as exc:
            result.status = "partial-failure"
            result.details = f"{result.details} Firewall API failed: {exc}"
            return result

        result.details = f"{result.details} Firewall API updated for {target}."
        return result

    def _write_state_entry(
        self,
        filename: str,
        target: str,
        action: str,
        incident_id: str,
    ) -> ResponseResult:
        state_file = self.state_dir / filename
        existing = self._read_state_list(state_file)
        if self.deduplicate_targets and target in existing:
            return ResponseResult(
                action=action,
                target=target,
                status="already-contained",
                details=f"{target} is already present in {state_file}.",
                incident_id=incident_id,
            )

        if not self.dry_run and self._within_cooldown(action, target):
            return ResponseResult(
                action=action,
                target=target,
                status="skipped",
                details=f"Suppressed duplicate {action} for {target} within cooldown window.",
                incident_id=incident_id,
            )

        if self.dry_run:
            return ResponseResult(
                action=action,
                target=target,
                status="dry-run",
                details=f"Simulation only. {target} would be added to {filename}.",
                incident_id=incident_id,
            )

        if target not in existing:
            existing.append(target)
            with state_file.open("w", encoding="utf-8") as handle:
                json.dump(sorted(existing), handle, ensure_ascii=True, indent=2)
        return ResponseResult(
            action=action,
            target=target,
            status="executed",
            details=f"{target} written to {state_file}.",
            incident_id=incident_id,
        )

    def _within_cooldown(self, action: str, target: str) -> bool:
        if self.cooldown <= timedelta(0):
            return False

        history_file = self.state_dir / "response_history.jsonl"
        if not history_file.exists():
            return False

        cutoff = datetime.now(timezone.utc) - self.cooldown
        with history_file.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                payload = json.loads(line)
                if payload.get("action") != action or payload.get("target") != target:
                    continue
                if payload.get("status") != "executed":
                    continue
                timestamp_text = str(payload.get("recorded_at", ""))
                timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
                if timestamp >= cutoff:
                    return True
        return False

    def _append_response_history(self, incident: Incident, result: ResponseResult) -> None:
        payload = {
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "incident_id": incident.incident_id,
            "rule_id": incident.rule_id,
            "severity": incident.severity,
            "mitre_tags": incident.mitre_tags,
            "action": result.action,
            "target": result.target,
            "status": result.status,
            "host": incident.event.host,
            "service": incident.event.service,
            "details": result.details,
        }
        history_file = self.state_dir / "response_history.jsonl"
        with history_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")

    @staticmethod
    def _post_json(
        url: str,
        payload: dict[str, object],
        timeout_seconds: int,
        headers: dict[str, str] | None = None,
        method: str = "POST",
    ) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        request = Request(url=url, data=body, headers=headers or {}, method=method)
        try:
            with urlopen(request, timeout=timeout_seconds):
                return
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(str(exc)) from exc

    @staticmethod
    def _read_state_list(path: Path) -> list[str]:
        if not path.exists():
            return []
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if isinstance(payload, list):
            return [str(item) for item in payload]
        return []


def summarize_results(results: Iterable[ResponseResult]) -> dict[str, int]:
    summary = {"executed": 0, "dry-run": 0, "skipped": 0, "already-contained": 0}
    for result in results:
        summary[result.status] = summary.get(result.status, 0) + 1
    return summary
