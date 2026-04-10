# Log-based Threat Detection & Response Automation System

- 로그 데이터를 입력으로 받아 보안 위협 징후를 자동으로 탐지하고, 인시던트 생성 및 대응 기록까지 수행하는 **규칙 기반 보안 자동화 프로젝트**입니다.

- 서로 다른 형식의 로그를 공통 이벤트 구조로 정규화한 뒤, 브루트포스, 계정 탈취, 권한 상승, 데이터 반출, 내부 이동, 피싱, 로그 변조 같은 주요 위협 시나리오를 탐지하고 대응 흐름까지 연결할 수 있도록 구현했습니다.

---

## Overview
- **Language** : Python
- **Detection Approach** : Rule-based Detection
- **Input Format** : JSONL, key=value log
- **Response Mode** : dry-run / live-response
- **Storage** : local state files (JSON / JSONL)
  

### 프로젝트 목표
이 프로젝트의 목표는 단순히 로그를 읽는 데서 끝나는 것이 아닌, **로그를 정규화하고 → 위협을 탐지하고 → 인시던트를 생성하고 → 대응 및 기록까지 이어지는 보안 운영 자동화 흐름**을 직접 구현하는 것입니다.

---


## 주요 기능

### 1. 로그 파싱 및 정규화
- JSONL 형식 로그 파싱
- key=value 형식 로그 파싱
- 서로 다른 형식의 로그를 공통 `Event` 모델로 변환
- 파싱 실패 로그 분리 수집

### 2. 규칙 기반 위협 탐지
다음과 같은 위협 시나리오를 탐지할 수 있습니다.

- **Brute Force**
  - 짧은 시간 내 반복 로그인 실패
- **Credential Compromise**
  - 여러 번 로그인 실패 후 성공
- **Suspicious Command Execution**
  - 공격 도구/의심 명령 실행 흔적 탐지
- **Privilege Escalation**
  - 관리자 권한 상승 관련 이벤트 탐지
- **Data Exfiltration**
  - 대량 데이터 외부 반출 시도 탐지
- **Lateral Movement**
  - 짧은 시간 안에 여러 호스트 이동
- **Phishing Activity**
  - 피싱 관련 이메일/보안 이벤트 탐지
- **Log Tampering**
  - 로그 삭제, 감사 무력화, 흔적 은폐 시도 탐지

### 3. 대응 자동화
탐지 결과에 따라 아래와 같은 대응 흐름을 수행하거나 시뮬레이션할 수 있습니다.

- Incident 기록
- 콘솔 알림
- IP 차단
- 사용자 격리
- 계정 비활성화
- 호스트 격리
- ChatOps 알림 구조(Slack / Teams webhook)

### 4. 탐지 근거와 상태 저장
- 탐지 결과를 `incidents.jsonl`에 저장
- 대응 내역을 `response_history.jsonl`에 저장
- 룰 상태를 `rule_state/`에 저장해 재실행 후에도 일부 상태 유지
- MITRE ATT&CK 태그와 evidence/context 함께 기록

### 5. 오탐 감소를 위한 운영 제어
- 예외 사용자 설정
- 예외 호스트 설정
- 예외 서비스 설정
- 예외 IP / 네트워크 설정
- 중복 대응 억제 및 cooldown 처리

---

## 프로젝트 구조

```text
.
├─ src/
│  └─ log_threat_automation/
│     ├─ __init__.py
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
```

---

## 동작 방식

1. 사용자가 로그 파일을 입력.
2. `parser.py`가 로그를 읽고 공통 이벤트 구조(`Event`)로 정규화.
3. `engine.py`가 이벤트를 각 탐지 룰에 전달.
4. `rules.py`가 위협 여부를 판단하고 `Incident`를 생성.
5. `responders.py`가 설정에 따라 대응을 실행 또는 시뮬레이션.
6. 결과와 상태를 `state/` 디렉터리에 저장.

즉 전체 흐름은 다음과 같습니다.

**Input Logs → Parsing/Normalization → Rule Evaluation → Incident Creation → Response Execution → State Persistence**

---

## 주요 구성 요소

### `parser.py`
- JSONL / key=value 로그를 파싱합니다.
- 서로 다른 형식의 로그를 공통 `Event` 구조로 정리합니다.
- 잘못된 로그는 `ParseError`로 분리 수집합니다.

### `rules.py`
- 핵심 위협 탐지 로직이 구현된 파일입니다.
- 상태 기반 탐지를 포함해 다양한 공격 패턴을 판별합니다.

### `engine.py`
- 전체 탐지 파이프라인을 조립하고 실행하는 중앙 엔진입니다.
- 이벤트를 순회하며 각 룰을 실행하고 대응 단계로 연결합니다.

### `responders.py`
- 탐지 이후의 대응을 담당합니다.
- Incident 기록, 콘솔 알림, IP 차단, 계정 비활성화, 호스트 격리 등을 처리합니다.

### `cli.py`
- 사용자가 프로그램을 실행할 때 사용하는 진입점입니다.
- 입력 로그, 설정 파일, dry-run / live-response 모드를 제어합니다.

---

## 탐지 시나리오

| Scenario | Detection Meaning |
|---|---|
| Repeated login failures | Brute Force |
| Multiple failures followed by success | Credential Compromise |
| Suspicious command execution | Suspicious Command |
| Admin privilege granted / escalation activity | Privilege Escalation |
| Large outbound transfer | Data Exfiltration |
| Same user accessing multiple hosts quickly | Lateral Movement |
| Phishing-related email/security events | Phishing Activity |
| Audit/log deletion attempts | Log Tampering |

---

## Sample Input

`samples/sample_logs.jsonl`에는 다음과 같은 예시 시나리오가 포함되어 있습니다.

- 동일 IP/사용자의 반복 로그인 실패
- 반복 실패 후 로그인 성공
- 의심 명령 실행
- 권한 상승
- 대량 데이터 반출
- 여러 호스트 로그인
- 로그 삭제 시도
- 피싱 관련 이벤트

샘플 로그를 통해 각 탐지 규칙이 어떻게 동작하는지 확인할 수 있습니다.

---

## 설정

`samples/detection_config.json`을 통해 다음 항목들을 조정할 수 있습니다.

- 활성화할 탐지 룰
- 탐지 임계값
- 시간 윈도우
- 대응 방식
- 예외 사용자/호스트/IP 대역
- ChatOps 설정
- Firewall API 설정
- 상태 저장 디렉터리

즉, 코드를 직접 수정하지 않고도 탐지 정책과 대응 정책을 조정할 수 있습니다.

---

## 실행 방법

### 1. 설치 없이 실행

```bash
PYTHONPATH=src python -m log_threat_automation --input samples/sample_logs.jsonl --config samples/detection_config.json --dry-run
```

### 2. 패키지 설치 후 실행

```bash
pip install -e .
log-threat-automation --input samples/sample_logs.jsonl --config samples/detection_config.json --dry-run
```

### 3. 실제 대응 모드 실행

```bash
PYTHONPATH=src python -m log_threat_automation --input samples/sample_logs.jsonl --config samples/detection_config.json --live-response
```

---

## Response Modes

### `--dry-run`
- 실제 차단/격리 대신 시뮬레이션 중심으로 동작합니다.
- 탐지 로직을 안전하게 검증할 때 사용합니다.

### `--live-response`
- 차단, 격리, 비활성화 같은 대응 결과를 상태 파일에 반영합니다.
- 실제 대응 흐름을 확인할 때 사용합니다.

---

## 출력 파일

실행 후 주요 결과는 `state/` 디렉터리에 저장됩니다.

- `incidents.jsonl`
  - 탐지된 인시던트 기록
- `response_history.jsonl`
  - 실행된 대응 기록
- `blocked_ips.json`
  - 차단된 IP 목록
- `quarantined_users.json`
  - 격리된 사용자 목록
- `disabled_users.json`
  - 비활성화된 계정 목록
- `isolated_hosts.json`
  - 격리된 호스트 목록
- `rule_state/`
  - 탐지 룰 상태 저장

---

## Testing

아래 명령어로 테스트를 실행할 수 있습니다.

```bash
python -m unittest discover -s tests -v
```

테스트를 통해 다음과 같은 항목을 검증할 수 있습니다.

- 브루트포스 탐지
- 계정 탈취 탐지
- 내부 이동 탐지
- 대응 상태 반영
- 오탐 감소용 예외 처리
- ChatOps / Firewall 연동 구조
- 파싱 오류 수집

---

## 설계 포인트

### 1. 정규화된 이벤트 모델
형식이 다른 로그라도 하나의 `Event` 구조로 맞춘 뒤 탐지 엔진에 넣도록 설계했습니다.

### 2. 상태 기반 탐지
브루트포스, 계정 탈취, 내부 이동 같은 탐지는 단일 로그 한 줄만 보는 것이 아니라  
이전 상태와 현재 이벤트의 관계를 함께 고려하도록 구현했습니다.

### 3. 탐지 근거 저장
탐지 결과에 evidence, context, related entities, MITRE ATT&CK 태그를 함께 저장해  
사후 분석과 설명 가능성을 높였습니다.

### 4. 대응 자동화 흐름
탐지만 수행하는 것이 아니라 Incident 기록, 알림, 차단, 격리까지 이어지는 구조를 구현했습니다.

### 5. 운영 현실성 반영
예외 사용자/호스트/IP 대역을 설정할 수 있도록 하여 오탐 감소를 고려했습니다.

---

## 한계점

- 일부 탐지 룰은 키워드 기반 또는 임계값 기반이라 문맥 이해에 한계가 있습니다.
- 완전한 실시간 스트리밍 처리보다는 로컬 파일 기반 분석에 가깝습니다.
- 실제 SIEM, EDR, IAM, 방화벽과의 완전한 실운영 수준 연동은 아닙니다.
- 대규모 환경에서의 성능 최적화는 추가 구현이 필요합니다.

---

## 개선 방향

- 실시간 로그 수집 파이프라인 연동
- SIEM / EDR / Firewall / IAM API 실제 연동
- 웹 대시보드 및 시각화 기능 추가
- 더 정교한 화이트리스트 / 예외 정책
- 룰 기반 탐지 외 점수 기반 / 행위 기반 탐지 보강
- 탐지 결과 리포트 자동 생성 기능 추가

---

## 배운 점

- 로그 정규화의 필요성
- 규칙 기반 탐지 시스템의 구조
- 상태 기반 위협 탐지 방식
- 탐지와 대응을 연결하는 자동화 흐름
- 보안 운영 관점에서의 인시던트 기록과 상태 관리

---

## 문서

- `README.md` : 프로젝트 소개 및 사용 방법
- `SYSTEM_OVERVIEW.md` : 시스템 개요
- `tests/test_engine.py` : 테스트 코드

---

## 요약

이 프로젝트는 **로그를 자동 분석하여 보안 위협을 탐지하고, 대응과 기록까지 연결하는 규칙 기반 보안 자동화 시스템**입니다.  
단순한 로그 분석기를 넘어, **정규화 → 탐지 → 인시던트 생성 → 대응 → 상태 저장** 흐름을 직접 구현한 포트폴리오 프로젝트라는 점에 의미가 있습니다.
