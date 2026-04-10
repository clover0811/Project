from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict

from .config import load_config
from .engine import DetectionEngine
from .parser import parse_input
from .responders import summarize_results


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Log-based threat detection and automated response system",
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a JSONL or key=value log file. Use '-' for stdin.",
    )
    parser.add_argument(
        "--config",
        help="Optional JSON configuration path.",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate containment actions without modifying local state lists.",
    )
    mode_group.add_argument(
        "--live-response",
        action="store_true",
        help="Execute containment actions and update local state lists.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print results as JSON.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    config = load_config(args.config)
    dry_run_override: bool | None = None
    if args.dry_run:
        dry_run_override = True
    elif args.live_response:
        dry_run_override = False

    engine = DetectionEngine(config, dry_run=dry_run_override)
    parsed_input = parse_input(args.input)
    result = engine.process_events(parsed_input.events)

    if args.json:
        payload = {
            "processed_event_count": len(parsed_input.events),
            "parse_error_count": len(parsed_input.errors),
            "parse_errors": [asdict(error) for error in parsed_input.errors],
            "incident_count": len(result.incidents),
            "incidents_by_rule": dict(Counter(incident.rule_id for incident in result.incidents)),
            "incidents": [asdict(incident) for incident in result.incidents],
            "responses": [asdict(response) for response in result.responses],
        }
        print(json.dumps(payload, ensure_ascii=True, indent=2, default=str))
        return

    incidents_by_rule = Counter(incident.rule_id for incident in result.incidents)
    response_summary = summarize_results(result.responses)

    print("=== Parse Summary ===")
    print(f"Processed events: {len(parsed_input.events)}")
    print(f"Parse errors: {len(parsed_input.errors)}")
    for error in parsed_input.errors[:3]:
        print(f"- line {error.line_number}: {error.error}")

    print("=== Detection Summary ===")
    print(f"Processed incidents: {len(result.incidents)}")
    for rule_id, count in sorted(incidents_by_rule.items()):
        print(f"- {rule_id}: {count}")

    print("=== Response Summary ===")
    for status, count in sorted(response_summary.items()):
        print(f"- {status}: {count}")

    print("=== Incident Details ===")
    if not result.incidents:
        print("No threats detected.")
        return

    for incident in result.incidents:
        print(
            f"[{incident.severity.upper()}] {incident.rule_id} "
            f"user={incident.event.user or '-'} ip={incident.event.source_ip or '-'} "
            f"host={incident.event.host}"
        )
        print(f"  reason: {incident.reason}")
        if incident.mitre_tags:
            print(f"  mitre_tags: {', '.join(incident.mitre_tags)}")
        print(f"  response_plan: {', '.join(incident.response_plan)}")
        action_results = [
            response
            for response in result.responses
            if response.incident_id == incident.incident_id
        ]
        for response in action_results:
            print(f"  response: {response.action} -> {response.status}")
