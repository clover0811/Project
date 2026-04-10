# Log Threat Automation

로그 기반 위협 탐지 및 대응 자동화 예제 프로젝트입니다.

이 프로젝트는 JSONL 또는 `key=value` 형식의 로그를 읽어 정규화하고, 상태 기반 탐지 규칙으로 위협 징후를 찾아 인시던트를 생성하며, 차단/격리/알림 같은 대응을 시뮬레이션하거나 실제로 반영합니다.

## 주요 기능

- JSONL, `key=value` 로그 파싱
- 파서 예외 처리와 라인 단위 오류 수집
- 상태 기반 탐지
- MITRE ATT&CK 태그 부여
- Slack / Teams 웹훅 알림 연동
- 방화벽 REST API 연동
- 룰 상태 스냅샷 저장
- 풍부한 탐지 근거(`context`) 기록

## 디렉터리 구조

- `src/log_threat_automation/`: 엔진, 룰, 파서, 대응기, CLI
- `samples/sample_logs.jsonl`: 샘플 입력 로그
- `samples/detection_config.json`: 샘플 설정
- `state/`: 실행 시 생성되는 인시던트, 대응, 룰 상태 산출물 디렉터리
- `tests/`: 단위 테스트

## 실행 방법

### 1. 설치 없이 바로 실행

패키지를 설치하지 않은 상태에서는 `src/`를 `PYTHONPATH`에 추가해야 합니다.

```powershell
$env:PYTHONPATH='src'
py -3.11 -m log_threat_automation --input samples/sample_logs.jsonl --config samples/detection_config.json --dry-run
```

실제 대응 반영:

```powershell
$env:PYTHONPATH='src'
py -3.11 -m log_threat_automation --input samples/sample_logs.jsonl --config samples/detection_config.json --live-response
```

### 2. editable install 후 실행

```powershell
py -3.11 -m pip install -e .
log-threat-automation --input samples/sample_logs.jsonl --config samples/detection_config.json --dry-run
```

## JSON 출력

```powershell
$env:PYTHONPATH='src'
py -3.11 -m log_threat_automation --input samples/sample_logs.jsonl --config samples/detection_config.json --json --dry-run
```

JSON 출력에는 다음 정보가 포함됩니다.

- `processed_event_count`
- `parse_error_count`
- `parse_errors`
- `incident_count`
- `incidents`
- `responses`

## 로그 형식

### JSON Lines 예시

```json
{"timestamp":"2026-04-08T02:30:00Z","host":"storage-01","service":"files","action":"download","status":"success","source_ip":"10.0.0.99","user":"carol","bytes_out":7400000,"message":"bulk export executed"}
```

### key=value 예시

```text
timestamp=2026-04-08T02:45:00Z host=log-01 service=syslog action=command status=success user=mallory message=wevtutil_cl_Security
```

## 상태 저장

`samples/`는 예제 입력과 예제 설정을 담는 디렉터리이고, `state/`는 샘플 데이터가 아니라 실행할 때마다 생성되는 런타임 산출물 디렉터리입니다.

기본적으로 `state/` 아래에 다음 파일들이 생성됩니다.

- `incidents.jsonl`
- `blocked_ips.json`
- `quarantined_users.json`
- `disabled_users.json`
- `isolated_hosts.json`
- `response_history.jsonl`
- `rule_state/`

`rule_state/` 아래에는 상태 기반 룰의 누적 상태가 저장됩니다. 그래서 프로세스를 다시 시작해도 brute force, credential compromise, lateral movement 같은 규칙은 이전 누적 상태를 이어서 사용할 수 있습니다.

저장소에는 빈 `state/` 디렉터리만 유지하고, 실제 산출물은 `.gitignore`로 제외하도록 정리했습니다.

## 탐지 근거 기록

각 인시던트의 `context`에는 다음 정보가 함께 저장됩니다.

- `event_summary`
- `related_entities`
- `evidence`
- `analysis`

이 구조 덕분에 어떤 이벤트가 왜 탐지되었는지, 어떤 키워드나 임계값이 매칭되었는지, 어떤 엔터티가 관련됐는지 추적하기 쉽습니다.

## 설정

샘플 설정은 [`samples/detection_config.json`](samples/detection_config.json)에 있습니다.

중요 항목:

- `state_dir`: 상태 저장 디렉터리
- `default_dry_run`: 기본 응답 모드
- `rule_state.enabled`: 상태 기반 룰 상태 저장 여부
- `rule_state.directory`: 룰 상태 저장 디렉터리 이름
- `rules.<rule_name>.enabled`: 룰 활성화 여부
- `rules.<rule_name>.exclude_users`
- `rules.<rule_name>.exclude_hosts`
- `rules.<rule_name>.exclude_services`
- `rules.<rule_name>.exclude_source_ips`
- `rules.<rule_name>.exclude_source_networks`
- `response_control.notifications.chatops`: Slack / Teams 연동
- `response_control.firewall_api`: 방화벽 API 연동

## 테스트

```powershell
$env:PYTHONPATH='src'
py -3.11 -m unittest discover -s tests
```

## 참고

- 상대경로 기준으로 실행 예시를 작성했습니다.
- 설치하지 않고 바로 실행할 때는 `PYTHONPATH=src`가 필요합니다.
- `py -3.11 -m log_threat_automation ...` 명령은 패키지가 import 가능한 상태가 아니면 그대로는 동작하지 않습니다.
