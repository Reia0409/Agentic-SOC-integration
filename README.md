# Agentic SOC — 1차탐지 (정규화 + 탐지)

Agentic SOC 파이프라인의 **앞단** 모듈. raw 로그를 공통 스키마로 **정규화**하고,
Sigma 룰로 조사할 시작점(**seed**)을 선별한다. 뒤에 오는 조사 에이전트에 넘길 진입점을 만드는 것이
역할이며, 판단은 하지 않는 **결정론 코드**다.

```
Raw Log (apache access.log / auth.log / suricata eve.json)
      │  파일 직접 조회
      ▼
① 정규화 ── 계층별 파서 (tools/fetch_*_log.py)
      │       raw → 공통 스키마 dict  (web / auth / network)
      ▼
   normalize.py ── fan-out + 병합 + timestamp(UTC) 정렬
      │  단일 이벤트 스트림
      ▼
② 탐지 ── Sigma 룰 엔진 (detect/engine.py + rules/sigma/)
      │  이벤트마다 룰 평가
      ▼
   seed (조사 시작점, 원본 포인터 포함) ──▶ 조사 에이전트로
```

`python tools/normalize.py` 하나로 3계층 정규화가 실행된다.

---

## 폴더 구조

```
├── common/                     # 공통 계약
│   ├── schema.py               #   공통 스키마 + LAYER_DATA_KEYS
│   ├── join_keys.py            #   계층 간 조인키(src_ip/pid/ppid)
│   └── seed.py                 #   탐지→조사 seed 스키마
├── detect/                     # ② 탐지
│   ├── engine.py / loader.py   #   Sigma 엔진 + 룰 로더
│   └── rules/sigma/
│       ├── apache/  (룰 4)     #   web 탐지 룰
│       └── auth/    (룰 10)    #   auth 탐지 룰
├── tools/                      # ① 정규화 파서 + 도구 프레임워크
│   ├── base.py / registry.py   #   success/failure 래퍼, @register 명부
│   ├── fetch_apache_log.py     #   web 파서
│   ├── fetch_auth_log.py       #   auth 파서
│   ├── fetch_network_log.py    #   network 파서 (Suricata)
│   ├── normalize.py            #   정규화 오케스트레이터
│   └── sample_*.log / .json    #   테스트용 샘플 로그
├── .env.example
└── requirements.txt
```

## 계층별 파서

| 계층 | 파일 | 입력 | src_ip 출처 | 탐지 룰 |
| --- | --- | --- | --- | --- |
| web | `fetch_apache_log.py` | Apache access.log | client(`%a`) | apache 4개 |
| auth | `fetch_auth_log.py` | auth.log (syslog) | 원격 IP | auth 10개 |
| network | `fetch_network_log.py` | Suricata eve.json | XFF 실 클라이언트 | 없음(IDS) |
| system | *(예정)* | auditd audit.log | — | 예정 |

- **network는 Sigma 룰이 없다** — IDS라 Suricata 자체 `alert`를 증거로 쓴다.
- **system(audit)은 보류** — 나중에 파서를 도구 계약에 맞춰 추가한다.

---

## 설치 및 실행

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

pip install -r requirements.txt
cp .env.example .env            # 경로·값 채우기
```

`.env` 최소 항목:
```
APACHE_LOG_PATH=tools/sample_access.log     # 실 배포: /var/log/apache2/access.log
AUTH_LOG_PATH=tools/sample_auth.log         # 실 배포: /var/log/auth.log
SURICATA_LOG_PATH=tools/sample_eve.json     # 실 배포: /var/log/suricata/eve.json
AUTH_LOG_YEAR=2026                          # BSD syslog 엔 연도가 없어 지정
SERVER_PUBLIC_IP=54.180.11.0                # 자기호출(wp-cron) 제외용
```

실행 (레포 루트에서):
```bash
python tools/normalize.py       # 3계층 정규화 → 병합·정렬된 이벤트 스트림
```

---

## 공통 스키마 (계약)

모든 파서는 **같은 모양의 dict**를 반환한다.
```json
{
  "timestamp": "…Z",        // ISO8601 UTC — 전 계층 정렬축
  "layer": "web|network|system|auth",
  "raw_ref": "파일:줄번호",  // 원본 역추적 포인터
  "src_ip": "…",            // ┐ 조인키(top-level): 계층을 넘나들며 사건을 잇는다
  "pid": null, "ppid": null, // ┘
  "layer_data": { … }       // 계층마다 다른 고유 필드
}
```
- **조인키(src_ip/pid/ppid)는 top-level, 계층 고유값은 layer_data.** 계층별 키는 `common/schema.py`.
- 새 파서를 붙일 때 **도구 계약**: `fetch_<계층>_log(log_path, …) -> list[dict]` + `@register` + `success/failure`.

## 검증

- **파서**: 계층별 샘플 + 실데이터로 파싱, 공통 스키마 strict 검증 통과.
  - network는 실제 EC2 `eve.json`(50,782줄)으로 검증 → http 1,335 + alert 23 = **1,358 선택**, loopback 승격 0.
- **룰↔파서**: apache 공격 4/4 발화·정상 오탐 0, auth 공격 9룰 발화·필드 커버리지 100%.
  - `detect/engine.py`가 아직 미구현이라, 룰 검증은 엔진 로직 사본으로 파서 출력을 태워 확인.

## 알아둘 것 / 남은 것

- **엔진 구현(담당 별도)**: `detect/engine.py`의 `get_field`가 top-level → 점 경로(`layer_data.x`) →
  접두어 없는 이름 순으로 찾아야 apache·auth 룰이 둘 다 걸린다. `routed`는 `service:auth`를
  `layer=="auth"`로 라우팅해야 한다.
- **web 계층 주의**: Apache가 nginx 뒤라 `%a`가 실 클라이언트다(XFF 미사용, 단일 프록시 환경).
- **system(audit) 재추가**: 파서를 도구 계약 + `layer_data` 구조로 맞추고, `normalize.py` 한 줄 +
  `.env AUDIT_LOG_PATH` 추가.
