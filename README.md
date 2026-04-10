# Log-based Threat Detection & Response Automation System

로그 데이터를 입력으로 받아 보안 위협 징후를 자동 탐지하고, 인시던트 생성과 대응 기록까지 수행하는 규칙 기반 보안 자동화 포트폴리오 프로젝트입니다.

## Overview

- Language : Python
- Detection Approach : Rule-based Detection
- Input Format : JSONL, key=value log
- Response Mode : dry-run / live-response
- Storage : local state files(JSON/JSONL)
- 특징
  - 형식이 다른 로그를 공통 이벤트 구조로 정규화
  - 브루트포스, 계정 탈취, 권한 상승, 데이터 반출, 내부 이동, 피싱, 로그 변조 탐지
  - MITRE ATT&CK 태그와 탐지 근거 저장
  - 차단, 격리, 비활성화, 알림 같은 대응 흐름 구현
  - 룰 상태 저장으로 재실행 후에도 일부 탐지 상태 유지

## 주요 기능

- 로그 파싱 및 정규화
  - JSONL 로그 파싱
  - key=value 로그 파싱
  - 파싱 실패 로그 분리 수집

- 규칙 기반 위협 탐지
  - Brute Force 탐지
  - Credential Compromise 탐지
  - Suspicious Command 탐지
  - Privilege Escalation 탐지
  - Data Exfiltration 탐지
  - Lateral Movement 탐지
  - Phishing Activity 탐지
  - Log Tampering 탐지

- 대응 자동화
  - Incident 기록
  - 콘솔 알림
  - IP 차단
  - 사용자 격리
  - 계정 비활성화
  - 호스트 격리
  - ChatOps 알림(Slack/Teams 연동 구조)

- 결과물
  - incidents.jsonl
  - response_history.jsonl
  - blocked_ips.json
  - quarantined_users.json
  - disabled_users.json
  - isolated_hosts.json
  - rule_state/

## 프로젝트 구조

.
├─ src/
│  └─ log_threat_automation/
│     ├─ __main__.py
│     ├─ cli.py
│     ├─ config.py
│     ├─ engine.py
│     ├─ models.py
│     ├─ parser.py
│     ├─ responders.py
│     └─ rules.py
├─ samples/
│  ├─ sample_logs.jsonl
│  └─ detection_config.json
├─ state/
│  └─ .gitkeep
├─ tests/
│  └─ test_engine.py
├─ README.md
├─ SYSTEM_OVERVIEW.md
└─ pyproject.toml

## 동작 흐름

1. 사용자가 로그 파일을 입력한다.
2. parser가 로그를 읽고 Event 구조로 정규화한다.
3. engine이 이벤트를 각 탐지 룰에 전달한다.
4. rules가 위협 여부를 판단하고 Incident를 생성한다.
5. responders가 설정에 따라 대응을 수행하거나 시뮬레이션한다.
6. 결과와 상태를 state 디렉터리에 저장한다.

## 주요 탐지 시나리오

- 동일 IP/사용자의 반복 로그인 실패 → Brute Force
- 반복 실패 후 로그인 성공 → Credential Compromise
- Mimikatz, powershell -enc 등 위험 명령 실행 → Suspicious Command
- 관리자 권한 획득 관련 이벤트 → Privilege Escalation
- 대량 외부 전송 → Data Exfiltration
- 짧은 시간 안에 여러 호스트 로그인 → Lateral Movement
- 피싱 관련 이메일/보안 이벤트 → Phishing Activity
- 로그 삭제/초기화 시도 → Log Tampering

## 로컬 실행

사전 조건:
- Python 3.x

설치 없이 실행:
```bash
PYTHONPATH=src python -m log_threat_automation --input samples/sample_logs.jsonl --config samples/detection_config.json --dry-run
