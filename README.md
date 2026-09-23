# Agentic SOC — 1차탐지 (정규화 + 탐지)

Agentic SOC 파이프라인의 **앞단** 모듈. raw 로그를 공통 스키마로 **정규화**하고,
Sigma 룰로 조사할 시작점(**seed**)을 선별한다. 뒤에 오는 조사 에이전트에 넘길 진입점을 만드는 것이
역할이며, 판단은 하지 않는 **결정론 코드**다.

```
Raw Log (apache access.log / auth.log / suricata eve.json / auditd audit.log)
      │  파일 직접 조회
      ▼
① 정규화 ── 계층별 파서 (tools/fetch_*_log.py)
      │       raw → 공통 스키마 dict  (web / auth / network / system)
      ▼
   normalize.py ── fan-out + 병합 + timestamp(UTC) 정렬
      │  단일 이벤트 스트림
      ▼
② 탐지 ── Sigma 룰 엔진 (detect/engine.py + rules/sigma/)
      │  이벤트마다 룰 평가
      ▼
   seed (조사 시작점, 원본 포인터 포함) ──▶ 조사 에이전트로
```

`python tools/normalize.py` 하나로 4계층 정규화가, `python detect/run.py` 로 정규화 → 탐지 → seed 까지 실행된다.

---

## 폴더 구조

```
├── common/                     # 공통 계약
│   ├── schema.py               #   공통 스키마 + LAYER_DATA_KEYS
│   ├── join_keys.py            #   계층 간 조인키(src_ip/pid/ppid)
│   └── seed.py                 #   탐지→조사 seed 스키마
├── detect/                     # ② 탐지
│   ├── loader.py               #   룰 로더 (yml → Rule, condition 문법 검증)
│   ├── engine.py               #   매칭 엔진 (필드 3단계 탐색, logsource 라우팅, seed 생성)
│   ├── suricata_flow.py        #   sensor/flow/tx 기반 Alert↔HTTP 연결
│   ├── web_network_correlation.py # Apache↔Suricata HTTP 결합
│   ├── suricata_seed.py        #   Suricata Alert seed + 교차계층 증거
│   ├── run.py                  #   정규화 → 탐지 → seed 실행 진입점
│   ├── rules/sigma/            #   활성 룰 (로더가 재귀로 읽음)
│   │   ├── apache/  (룰 4)     #   web 탐지 룰
│   │   ├── auth/    (룰 10)    #   auth 탐지 룰
│   │   └── audit/   (룰 12)    #   system(audit) 탐지 룰
│   └── rules/candidates/       #   보류 룰 (로더가 읽지 않음). audit_cloud_creds_access
├── tools/                      # ① 정규화 파서 + 도구 프레임워크
│   ├── base.py / registry.py   #   success/failure 래퍼, @register 명부
│   ├── fetch_apache_log.py     #   web 파서
│   ├── fetch_auth_log.py       #   auth 파서
│   ├── fetch_network_log.py    #   network 파서 (Suricata)
│   ├── fetch_audit_log.py      #   system 파서 (auditd, serial 조립·ENRICHED·hex)
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
| system | `fetch_audit_log.py` | auditd audit.log (.gz 가능) | 없음(IP 없음, 조인키 pid/ppid) | audit 12개 |

- **network는 Sigma 룰이 없다** — IDS라 Suricata 자체 `alert`를 증거로 쓴다.
- **system(audit)은 serial 단위 조립** — 한 이벤트 = 같은 `msg=audit(epoch:serial)` 레코드 묶음. `raw_ref` 는 `파일:SYSCALL 줄번호`, 묶음 전체 줄번호는 `layer_data.raw_lines`.

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
AUDIT_LOG_PATH=tools/sample_audit.log       # 실 배포: /var/log/audit/audit.log
AUTH_LOG_YEAR=2026                          # BSD syslog 엔 연도가 없어 지정
SERVER_PUBLIC_IP=54.180.11.0                # 자기호출(wp-cron) 제외용
```

실행 (레포 루트에서):
```bash
python tools/normalize.py       # 4계층 정규화 → out/ 아래 계층별 JSONL 저장
python detect/run.py            # 정규화 → Sigma·Suricata Alert 탐지 → seed (--out-seeds out/seeds.jsonl)
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

## Apache–Suricata 결합

Suricata Alert는 먼저 `sensor_id + flow_id + tx_id`로 같은 Suricata HTTP 이벤트에 연결된다.
`tx_id`가 없을 때만 같은 flow·전송 튜플·±5초 안의 유일한 HTTP 이벤트를 보수적으로 사용한다.
이후 HTTP 이벤트의 XFF 기반 `src_ip`와 Apache `%a`를 표준 IP로 비교하고, UTC 시각과
`method/path/status`를 함께 사용해 다음 등급으로 판정한다.

| 등급 | 기본 조건 | seed 처리 |
| --- | --- | --- |
| `strong` | 동일 IP, ±1초, method/path/status 일치, 후보 1건 | Apache `raw_ref`를 `evidence_refs`에 자동 편입 |
| `ambiguous_cluster` | strong 조건 후보가 여러 건 | 후보만 보존, 자동 편입 안 함 |
| `context_only` | ±2초 fallback, 요청 필드 불일치, ±900초 장시간 정확 후보, XFF 결측 후보 | 상세 메타데이터로만 보존 |
| `unmatched` | 후보 없음, timestamp 오류, XFF invalid/conflict | 미결합 사유 보존 |

XFF가 없는 경우 IP 독립 검증이 불가능하므로 `strong`으로 승격하지 않는다. XFF가
`invalid` 또는 `conflict`이면 IP 없는 fallback도 수행하지 않는다. 판정 결과는 Suricata
seed의 `detail.web_network_correlations`에 기록된다.

기본 결합 창은 `detect/run.py`의 `--web-strong-window`, `--web-fallback-window`,
`--web-long-delay-window`로 조정할 수 있다. 이 값은 seed 자체의 `--window`와 독립적이다.

## 검증

- **파서**: 계층별 샘플 + 실데이터로 파싱, 공통 스키마 strict 검증 통과.
  - network는 실제 EC2 `eve.json`(50,782줄)으로 검증 → http 1,335 + alert 23 = **1,358 선택**, loopback 승격 0.
- **룰↔파서**: apache 공격 4/4 발화·정상 오탐 0, auth 공격 9룰 발화·필드 커버리지 100%.
- **audit**: 실 표본 500줄 → 107 이벤트(strict 통과), uid=33(www-data) 이벤트가 없어 seed 0. 합성 침해 로그(21 이벤트) → 12룰 전부 발화, 음성 7건 오탐 0.
- **엔진**: 룰 26개 로드(+ 보류 1), apache·auth·audit 룰이 한 엔진에서 발화, layer 라우팅, seed 계약(evidence_refs 필수) 확인.
- **Suricata 결합**: Alert↔HTTP flow/transaction 연결과 Apache strong/ambiguous/context/unmatched,
  IPv6 표준화, XFF 결측·충돌, strong 증거만 seed로 승격하는 경로를 단위 테스트로 확인.

## 알아둘 것 / 남은 것

- **엔진 필드 탐색**: `get_field`는 top-level → 점 경로(`layer_data.x`) → 접두어 없는 이름(`layer_data` 폴백) 순.
  apache 룰은 접두어 없이, auth·audit 룰은 점 경로로 쓴다. 새 룰은 점 경로 권장.
- **logsource 라우팅**: `product/service` 로 layer 를 정한다(`linux/auditd`→system, `linux/auth`→auth, `apache`→web). category 는 무시.
- **web 계층 주의**: Apache가 nginx 뒤라 `%a`가 실 클라이언트다(XFF 미사용, 단일 프록시 환경).
- **system(audit) 주의**: `str.splitlines()` 는 ENRICHED 구분자 0x1D 를 줄바꿈으로 취급해 레코드가 쪼개진다. 파일 반복 또는 `split("\n")` 만 쓴다.
- **audit session_type**: SYSCALL 레코드가 있을 때만 `interactive`/`non_interactive` 로 판정, 없으면 `None`(판정 불가). `exclude_interactive=True` 는 `non_interactive` 만 남긴다.
- **audit serial 은 유니크가 아니다**: 재부팅 시 리셋된다(실파일 498738→75). 식별·중복제거 키는 `(timestamp, serial)` 또는 `raw_ref`.
- **time_window**: tz 없는 ISO 시각은 UTC 로 간주한다. 형식 오류는 도구 봉투 `failure("잘못된 인자: …")` 로 돌아온다(파싱 실패와 구분).

