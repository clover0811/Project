# Log Threat Automation Overview

This project implements a log-based threat detection and automated response workflow.

## Pipeline

1. Parse input logs from JSONL or `key=value` records.
2. Normalize them into `Event` objects.
3. Evaluate the stream against stateful detection rules.
4. Generate `Incident` records with response playbooks.
5. Execute or simulate containment actions.
6. Persist incident and response state under `state/`.

## Detection Coverage

- Brute-force authentication attempts
- Successful login after repeated failures
- Suspicious command execution
- Privilege escalation activity
- Large outbound transfer / data exfiltration
- Lateral movement across multiple hosts
- Phishing and email-borne social engineering alerts
- Log tampering / audit evasion

## Response Actions

- `record_incident`
- `notify_console`
- `block_ip`
- `quarantine_user`
- `disable_user`
- `isolate_host`
- `notify_chatops`

## Operational Controls

- Target deduplication prevents repeated containment for already blocked IPs, quarantined users, disabled users, or isolated hosts.
- Response cooldown suppresses repeated live actions inside a configurable time window.
- Response history is recorded to `state/response_history.jsonl` for auditability.
- Rule-level false-positive suppression is available through `exclude_users`, `exclude_hosts`, `exclude_services`, `exclude_source_ips`, and `exclude_source_networks`.
- MITRE ATT&CK tags are attached to incidents and stored in incident history.

## Integrations

- Slack and Microsoft Teams incoming webhooks via `response_control.notifications.chatops`
- Firewall REST API blocking via `response_control.firewall_api`

## Run Examples

```powershell
$env:PYTHONPATH='src'; py -3.11 -m log_threat_automation --input samples/sample_logs.jsonl --config samples/detection_config.json --dry-run
```

```powershell
$env:PYTHONPATH='src'; py -3.11 -m log_threat_automation --input samples/sample_logs.jsonl --config samples/detection_config.json --live-response
```

```powershell
$env:PYTHONPATH='src'; py -3.11 -m unittest discover -s tests
```
