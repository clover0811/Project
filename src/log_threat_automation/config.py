from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any


DEFAULT_CONFIG: dict[str, Any] = {
    "state_dir": "state",
    "default_dry_run": True,
    "rules": {
        "brute_force": {
            "enabled": True,
            "failures": 5,
            "window_minutes": 10,
        },
        "suspicious_command": {
            "enabled": True,
            "keywords": [
                "powershell -enc",
                "mimikatz",
                "certutil -urlcache",
                "curl http",
                "wget http",
                "nc -e",
                "whoami /priv",
            ],
            "exclude_users": [],
            "exclude_hosts": [],
            "exclude_source_ips": [],
        },
        "privilege_escalation": {
            "enabled": True,
            "watch_actions": [
                "sudo",
                "role_change",
                "privilege_granted",
                "admin_login",
            ],
            "sensitive_users": ["administrator", "admin", "root"],
            "exclude_users": [],
        },
        "data_exfiltration": {
            "enabled": True,
            "bytes_threshold": 5000000,
            "exclude_source_networks": [],
        },
        "log_tampering": {
            "enabled": True,
            "keywords": [
                "wevtutil cl",
                "audit log stopped",
                "truncate /var/log",
                "history cleared",
                "rm /var/log",
            ],
        },
        "credential_compromise": {
            "enabled": True,
            "failures": 3,
            "window_minutes": 15,
            "exclude_users": [],
        },
        "lateral_movement": {
            "enabled": True,
            "unique_hosts": 3,
            "window_minutes": 10,
            "watch_actions": [
                "login",
                "auth",
                "signin",
                "remote_exec",
                "process_start",
            ],
            "watch_services": [
                "auth",
                "ssh",
                "rdp",
                "winrm",
                "smb",
                "shell",
            ],
            "exclude_users": [],
        },
        "phishing_activity": {
            "enabled": True,
            "min_indicator_hits": 2,
            "watch_services": ["email", "mail", "mail-gateway", "secure-email"],
            "watch_actions": [
                "phishing_report",
                "mail_quarantine",
                "mail_blocked",
                "credential_submission",
            ],
            "verdict_values": ["phish", "malicious", "high-confidence-phish", "blocked"],
            "keywords": [
                "phish",
                "credential harvest",
                "malicious attachment",
                "malicious link",
                "spoofed sender",
                "mailbox compromise",
            ],
            "exclude_users": [],
            "exclude_hosts": [],
        },
    },
    "rule_state": {
        "enabled": True,
        "directory": "rule_state",
    },
    "response_control": {
        "deduplicate_targets": True,
        "cooldown_minutes": 60,
        "record_response_history": True,
        "notifications": {
            "chatops": {
                "enabled": False,
                "slack_webhook_url": "",
                "teams_webhook_url": "",
                "timeout_seconds": 5,
            }
        },
        "firewall_api": {
            "enabled": False,
            "base_url": "",
            "blocklist_path": "/blocklist",
            "api_key": "",
            "api_key_header": "Authorization",
            "timeout_seconds": 5,
            "ip_field": "ip",
            "method": "POST",
        },
    },
}


def load_config(config_path: str | None) -> dict[str, Any]:
    if not config_path:
        return deepcopy(DEFAULT_CONFIG)

    path = Path(config_path)
    with path.open("r", encoding="utf-8") as handle:
        user_config = json.load(handle)

    return deep_merge(DEFAULT_CONFIG, user_config)


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged
