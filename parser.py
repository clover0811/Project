from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .models import Event, Incident, ResponseResult
from .responders import ResponseExecutor
from .rules import BaseRule, build_rules


@dataclass(slots=True)
class EngineResult:
    incidents: list[Incident]
    responses: list[ResponseResult]


class DetectionEngine:
    def __init__(self, config: dict[str, object], dry_run: bool | None = None) -> None:
        self.config = config
        rules_config = config.get("rules", {})
        self.rules: list[BaseRule] = build_rules(rules_config if isinstance(rules_config, dict) else {})
        state_dir = str(config.get("state_dir", "state"))
        rule_state_config = config.get("rule_state", {})
        response_config = config.get("response_control", {})
        self.state_dir = Path(state_dir)
        self.persist_rule_state = bool(
            rule_state_config.get("enabled", True)
            if isinstance(rule_state_config, dict)
            else True
        )
        self.rule_state_dir = self.state_dir / str(
            rule_state_config.get("directory", "rule_state")
            if isinstance(rule_state_config, dict)
            else "rule_state"
        )
        if dry_run is None:
            dry_run = bool(config.get("default_dry_run", True))
        self.responder = ResponseExecutor(
            state_dir=state_dir,
            dry_run=dry_run,
            response_config=response_config if isinstance(response_config, dict) else {},
        )
        if self.persist_rule_state:
            self.rule_state_dir.mkdir(parents=True, exist_ok=True)
            self._load_rule_states()

    def process_events(self, events: Iterable[Event]) -> EngineResult:
        incidents: list[Incident] = []
        responses: list[ResponseResult] = []

        for event in events:
            for rule in self.rules:
                incident = rule.evaluate(event)
                if incident is None:
                    continue
                incidents.append(incident)
                responses.extend(self.responder.execute(incident))

        if self.persist_rule_state:
            self._save_rule_states()
        return EngineResult(incidents=incidents, responses=responses)

    def _load_rule_states(self) -> None:
        for rule in self.rules:
            state_path = self.rule_state_dir / f"{rule.rule_id}.json"
            if not state_path.exists():
                continue
            try:
                payload = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            state = payload.get("state", payload)
            if isinstance(state, dict):
                try:
                    rule.import_state(state)
                except (TypeError, ValueError):
                    continue

    def _save_rule_states(self) -> None:
        for rule in self.rules:
            state = rule.export_state()
            if state is None:
                continue
            payload = {
                "rule_id": rule.rule_id,
                "saved_at": datetime.now(timezone.utc).isoformat(),
                "state": state,
            }
            state_path = self.rule_state_dir / f"{rule.rule_id}.json"
            state_path.write_text(
                json.dumps(payload, ensure_ascii=True, indent=2),
                encoding="utf-8",
            )
