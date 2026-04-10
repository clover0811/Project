from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from log_threat_automation.config import deep_merge, load_config
from log_threat_automation.engine import DetectionEngine
from log_threat_automation.parser import parse_input, parse_line, to_event


def build_event(raw: str):
    return to_event(parse_line(raw))


class DummyResponse:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class DetectionEngineTests(unittest.TestCase):
    def test_brute_force_triggers_block_ip_dry_run(self) -> None:
        config = deep_merge(
            load_config(None),
            {
                "state_dir": tempfile.mkdtemp(),
                "rules": {"brute_force": {"failures": 3, "window_minutes": 5}},
            },
        )
        engine = DetectionEngine(config, dry_run=True)
        events = [
            to_event(
                parse_line(
                    '{"timestamp":"2026-04-08T00:00:00Z","host":"app","service":"auth","action":"login","status":"failed","source_ip":"1.2.3.4","user":"eve","message":"bad password"}'
                )
            ),
            to_event(
                parse_line(
                    '{"timestamp":"2026-04-08T00:01:00Z","host":"app","service":"auth","action":"login","status":"failed","source_ip":"1.2.3.4","user":"eve","message":"bad password"}'
                )
            ),
            to_event(
                parse_line(
                    '{"timestamp":"2026-04-08T00:02:00Z","host":"app","service":"auth","action":"login","status":"failed","source_ip":"1.2.3.4","user":"eve","message":"bad password"}'
                )
            ),
        ]

        result = engine.process_events(events)

        self.assertEqual(len(result.incidents), 1)
        self.assertEqual(result.incidents[0].rule_id, "brute_force")
        self.assertTrue(any(item.action == "block_ip" and item.status == "dry-run" for item in result.responses))

    def test_real_response_writes_state_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = deep_merge(
                load_config(None),
                {
                    "state_dir": temp_dir,
                    "rules": {
                        "suspicious_command": {
                            "keywords": ["mimikatz"],
                        }
                    },
                },
            )
            engine = DetectionEngine(config, dry_run=False)
            event = to_event(
                parse_line(
                    '{"timestamp":"2026-04-08T00:00:00Z","host":"win-01","service":"shell","action":"process_start","status":"success","source_ip":"5.6.7.8","user":"trent","message":"mimikatz privilege::debug"}'
                )
            )

            result = engine.process_events([event])

            self.assertEqual(len(result.incidents), 1)
            blocked_ips = json.loads(Path(temp_dir, "blocked_ips.json").read_text(encoding="utf-8"))
            quarantined_users = json.loads(Path(temp_dir, "quarantined_users.json").read_text(encoding="utf-8"))
            self.assertIn("5.6.7.8", blocked_ips)
            self.assertIn("trent", quarantined_users)
            self.assertTrue(all(item.incident_id == result.incidents[0].incident_id for item in result.responses))

    def test_credential_compromise_disables_user_and_isolates_host(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = deep_merge(
                load_config(None),
                {
                    "state_dir": temp_dir,
                    "rules": {
                        "credential_compromise": {
                            "failures": 2,
                            "window_minutes": 10,
                        }
                    },
                },
            )
            engine = DetectionEngine(config, dry_run=False)
            events = [
                to_event(
                    parse_line(
                        '{"timestamp":"2026-04-08T00:00:00Z","host":"vpn-01","service":"auth","action":"login","status":"failed","source_ip":"9.9.9.9","user":"alice","message":"bad password"}'
                    )
                ),
                to_event(
                    parse_line(
                        '{"timestamp":"2026-04-08T00:01:00Z","host":"vpn-01","service":"auth","action":"login","status":"failed","source_ip":"9.9.9.9","user":"alice","message":"bad password"}'
                    )
                ),
                to_event(
                    parse_line(
                        '{"timestamp":"2026-04-08T00:02:00Z","host":"vpn-01","service":"auth","action":"login","status":"success","source_ip":"9.9.9.9","user":"alice","message":"login accepted"}'
                    )
                ),
            ]

            result = engine.process_events(events)

            self.assertEqual(len(result.incidents), 1)
            self.assertEqual(result.incidents[0].rule_id, "credential_compromise")
            disabled_users = json.loads(Path(temp_dir, "disabled_users.json").read_text(encoding="utf-8"))
            isolated_hosts = json.loads(Path(temp_dir, "isolated_hosts.json").read_text(encoding="utf-8"))
            self.assertIn("alice", disabled_users)
            self.assertIn("vpn-01", isolated_hosts)

    def test_lateral_movement_triggers_after_multiple_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = deep_merge(
                load_config(None),
                {
                    "state_dir": temp_dir,
                    "rules": {
                        "lateral_movement": {
                            "unique_hosts": 3,
                            "window_minutes": 10,
                            "watch_actions": ["login"],
                            "watch_services": ["ssh"],
                        }
                    },
                },
            )
            engine = DetectionEngine(config, dry_run=False)
            events = [
                to_event(
                    parse_line(
                        '{"timestamp":"2026-04-08T00:00:00Z","host":"srv-01","service":"ssh","action":"login","status":"success","source_ip":"7.7.7.7","user":"ops-temp","message":"ssh login"}'
                    )
                ),
                to_event(
                    parse_line(
                        '{"timestamp":"2026-04-08T00:03:00Z","host":"srv-02","service":"ssh","action":"login","status":"success","source_ip":"7.7.7.7","user":"ops-temp","message":"ssh login"}'
                    )
                ),
                to_event(
                    parse_line(
                        '{"timestamp":"2026-04-08T00:05:00Z","host":"srv-03","service":"ssh","action":"login","status":"success","source_ip":"7.7.7.7","user":"ops-temp","message":"ssh login"}'
                    )
                ),
            ]

            result = engine.process_events(events)

            self.assertEqual(len(result.incidents), 1)
            self.assertEqual(result.incidents[0].rule_id, "lateral_movement")
            isolated_hosts = json.loads(Path(temp_dir, "isolated_hosts.json").read_text(encoding="utf-8"))
            quarantined_users = json.loads(Path(temp_dir, "quarantined_users.json").read_text(encoding="utf-8"))
            self.assertIn("srv-03", isolated_hosts)
            self.assertIn("ops-temp", quarantined_users)

    def test_duplicate_containment_is_marked_as_already_contained(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = deep_merge(
                load_config(None),
                {
                    "state_dir": temp_dir,
                    "rules": {
                        "suspicious_command": {
                            "keywords": ["mimikatz"],
                        }
                    },
                },
            )
            engine = DetectionEngine(config, dry_run=False)
            events = []
            events.append(build_event("timestamp=2026-04-08T00:00:00Z host=win-01 service=shell action=process_start status=success source_ip=6.6.6.6 user=trent message=mimikatz"))
            events.append(build_event("timestamp=2026-04-08T00:01:00Z host=win-02 service=shell action=process_start status=success source_ip=6.6.6.6 user=trent message=mimikatz"))
            result = engine.process_events(events)
            duplicate_actions = [
                response
                for response in result.responses
                if response.action == "block_ip" and response.status == "already-contained"
            ]
            self.assertTrue(duplicate_actions)

    def test_excluded_user_reduces_false_positive(self) -> None:
        config = deep_merge(
            load_config(None),
            {
                "state_dir": tempfile.mkdtemp(),
                "rules": {
                    "suspicious_command": {
                        "keywords": ["mimikatz"],
                        "exclude_users": ["it-admin"],
                    }
                },
            },
        )
        engine = DetectionEngine(config, dry_run=True)
        event = build_event(
            "timestamp=2026-04-08T01:00:00Z host=jump-01 service=shell action=process_start status=success "
            "source_ip=10.10.10.10 user=it-admin message=mimikatz"
        )

        result = engine.process_events([event])

        self.assertEqual(len(result.incidents), 0)

    def test_parser_collects_errors_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir, "mixed_logs.log")
            log_path.write_text(
                "\n".join(
                    [
                        '{"timestamp":"2026-04-08T00:00:00Z","host":"app","service":"auth","action":"login","status":"failed","source_ip":"1.1.1.1","user":"eve","message":"bad password"}',
                        '{"timestamp":"broken-json"',
                        "timestamp=not-a-timestamp host=app service=auth action=login status=failed user=eve",
                    ]
                ),
                encoding="utf-8",
            )

            parsed = parse_input(str(log_path))

            self.assertEqual(len(parsed.events), 1)
            self.assertEqual(len(parsed.errors), 2)
            self.assertEqual(parsed.errors[0].line_number, 2)

    def test_incident_context_is_richly_recorded(self) -> None:
        config = deep_merge(
            load_config(None),
            {
                "state_dir": tempfile.mkdtemp(),
                "rules": {
                    "suspicious_command": {
                        "keywords": ["mimikatz"],
                    }
                },
            },
        )
        engine = DetectionEngine(config, dry_run=True)
        event = build_event(
            "timestamp=2026-04-08T00:00:00Z host=jump-01 service=shell action=process_start status=success "
            "source_ip=203.0.113.77 user=trent message=mimikatz"
        )

        result = engine.process_events([event])

        context = result.incidents[0].context
        self.assertIn("event_summary", context)
        self.assertIn("evidence", context)
        self.assertIn("analysis", context)
        self.assertEqual(context["analysis"]["matched_keyword"], "mimikatz")

    def test_phishing_rule_adds_mitre_tags_and_disable_user(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = deep_merge(
                load_config(None),
                {
                    "state_dir": temp_dir,
                    "rules": {
                        "phishing_activity": {
                            "min_indicator_hits": 2,
                        }
                    },
                },
            )
            engine = DetectionEngine(config, dry_run=False)
            event = to_event(
                {
                    "timestamp": "2026-04-08T03:20:00Z",
                    "host": "mail-gw-01",
                    "service": "email",
                    "action": "credential_submission",
                    "status": "success",
                    "sender_ip": "203.0.113.55",
                    "recipient": "dana",
                    "subject": "Reset your VPN password",
                    "message": "phish malicious link credential harvest",
                    "verdict": "high-confidence-phish",
                }
            )

            result = engine.process_events([event])

            self.assertEqual(len(result.incidents), 1)
            self.assertEqual(result.incidents[0].rule_id, "phishing_activity")
            self.assertIn("T1566 Phishing", result.incidents[0].mitre_tags)
            disabled_users = json.loads(Path(temp_dir, "disabled_users.json").read_text(encoding="utf-8"))
            self.assertIn("dana", disabled_users)

    @patch("log_threat_automation.responders.urlopen", return_value=DummyResponse())
    def test_chatops_notification_posts_to_slack_and_teams(self, mocked_urlopen) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = deep_merge(
                load_config(None),
                {
                    "state_dir": temp_dir,
                    "response_control": {
                        "notifications": {
                            "chatops": {
                                "enabled": True,
                                "slack_webhook_url": "https://hooks.slack.test/services/demo",
                                "teams_webhook_url": "https://teams.example.test/webhook",
                                "timeout_seconds": 2,
                            }
                        }
                    },
                },
            )
            engine = DetectionEngine(config, dry_run=False)
            event = build_event(
                "timestamp=2026-04-08T04:00:00Z host=db-01 service=shell action=process_start status=success "
                "source_ip=198.51.100.10 user=bob message=mimikatz"
            )

            result = engine.process_events([event])

            chatops_results = [item for item in result.responses if item.action == "notify_chatops"]
            self.assertEqual(len(chatops_results), 1)
            self.assertEqual(chatops_results[0].status, "executed")
            self.assertEqual(mocked_urlopen.call_count, 2)

    @patch("log_threat_automation.responders.urlopen", return_value=DummyResponse())
    def test_firewall_api_block_ip_calls_remote_api(self, mocked_urlopen) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = deep_merge(
                load_config(None),
                {
                    "state_dir": temp_dir,
                    "response_control": {
                        "firewall_api": {
                            "enabled": True,
                            "base_url": "https://firewall.example.test/api",
                            "blocklist_path": "/v1/block-ip",
                            "api_key": "Bearer test-token",
                            "api_key_header": "Authorization",
                            "timeout_seconds": 2,
                            "ip_field": "indicator_ip",
                            "method": "POST",
                        }
                    },
                },
            )
            engine = DetectionEngine(config, dry_run=False)
            event = build_event(
                "timestamp=2026-04-08T04:05:00Z host=db-01 service=shell action=process_start status=success "
                "source_ip=198.51.100.11 user=bob message=mimikatz"
            )

            result = engine.process_events([event])

            block_results = [item for item in result.responses if item.action == "block_ip"]
            self.assertEqual(len(block_results), 1)
            self.assertEqual(block_results[0].status, "executed")
            self.assertIn("Firewall API updated", block_results[0].details)
            request = mocked_urlopen.call_args.args[0]
            self.assertEqual(request.full_url, "https://firewall.example.test/api/v1/block-ip")

    def test_stateful_rule_state_persists_between_engine_instances(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = deep_merge(
                load_config(None),
                {
                    "state_dir": temp_dir,
                    "rule_state": {
                        "enabled": True,
                        "directory": "rule_state",
                    },
                    "rules": {
                        "brute_force": {
                            "failures": 3,
                            "window_minutes": 5,
                        }
                    },
                },
            )
            engine = DetectionEngine(config, dry_run=True)
            first_batch = [
                build_event(
                    "timestamp=2026-04-08T00:00:00Z host=app service=auth action=login status=failed "
                    "source_ip=8.8.8.8 user=eve message=bad-password"
                ),
                build_event(
                    "timestamp=2026-04-08T00:01:00Z host=app service=auth action=login status=failed "
                    "source_ip=8.8.8.8 user=eve message=bad-password"
                ),
            ]

            first_result = engine.process_events(first_batch)
            self.assertEqual(len(first_result.incidents), 0)

            reloaded_engine = DetectionEngine(config, dry_run=True)
            second_result = reloaded_engine.process_events(
                [
                    build_event(
                        "timestamp=2026-04-08T00:02:00Z host=app service=auth action=login status=failed "
                        "source_ip=8.8.8.8 user=eve message=bad-password"
                    )
                ]
            )

            self.assertEqual(len(second_result.incidents), 1)
            self.assertEqual(second_result.incidents[0].rule_id, "brute_force")
            self.assertTrue(Path(temp_dir, "rule_state", "brute_force.json").exists())


if __name__ == "__main__":
    unittest.main()
