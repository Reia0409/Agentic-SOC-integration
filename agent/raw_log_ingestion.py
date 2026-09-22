"""raw log ingestion — seed 생성(경량 LLM triage) 전용 데이터 소스.

agent/tools/real/fetch_*.py들은 "이미 seed가 있고, 그 seed를 검증하기 위해
특정 조건(호스트+시간+필터)으로 좁혀서 조회"하는 조사 단계용 도구다.

이 모듈은 그 이전 단계다 — 아직 seed가 없는 상태에서, 최근 N분 동안 쌓인
web/auth/audit/network 로그를 필터 없이 통째로 긁어와서 LLM(seed_generation.py)에게
"여기서 수상한 거 있어?"라고 물어볼 재료를 만든다.

*** S3 raw 데이터 실측 결과 반영 (2026-09-13/14, 지금은 전부 아래 2026-09-22
업데이트로 대체됨 — 옛 경위만 기록으로 남김) ***
auditd 로그는 NDJSON이 아니라 정규화 이전의 raw 텍스트(ENRICHED 포맷 + 멀티라인
구조)로 확인됐다. web 소스는 처음엔 web tool 담당 팀원의 apache_parser.py(공백
구분 14필드)를 썼는데, 실제 sample_web.log가 그 형식이 아니라 한 줄 = JSON
객체인 nginx JSON 로그로 확인돼서(2026-09-14) agent/tools/parsers/nginx_json_parser.py
(실측 기반으로 새로 작성)로 교체했었다. network 소스도 agent/tools/parsers/network_parser.py의
parse_network_events()(조사 단계의 fetch_network_log.py와 동일한 파서)를
재사용해서 src/dst ip·port, protocol, alert_signature까지 구조화했었다.

*** 2026-09-22 업데이트 (B 이후 추가 반영: 공통 정규화 함수로 audit/auth 교체) ***
audit·auth 두 소스는 더 이상 자체 파서(parsers/audit_parser.py, parsers/auth_parser.py)를
쓰지 않는다. 완료 기준(같은 raw 로그 → 1차 탐지팀과 동일한 정규화 결과)을 이 진입점
(seed 생성용 raw 수집)에도 맞추기 위해, primary_detection/normalizer/tools/ 안의 1차
탐지팀 정규화 함수(fetch_audit_log/fetch_auth_log, agent/tools/real/fetch_audit_log.py·
fetch_auth_log.py가 쓰는 것과 동일한 코드)를 직접 재사용한다. (2026-09-22: 이 벤더
코드가 agent/tools/normalizer/에서 레포 루트의 primary_detection/normalizer/로
이동했다 — primary_detection은 정식 파이썬 패키지명이라 별도 설정 없이 아래처럼
`primary_detection.normalizer.tools...`로 바로 import된다.)

*** 2026-09-22 추가 업데이트: web·network도 공통 정규화 함수로 교체 ***
조사 도구(agent/tools/real/fetch_web_log.py·fetch_network_log.py)가 이미 web은
nginx가 아니라 apache access.log를, network는 Suricata eve.json을 1차 탐지팀
정규화 함수로 읽도록 바뀌어 있었는데, 이 모듈(seed 생성용 raw 수집)만 그때 같이
안 바뀌고 예전 자체 파서(nginx_json_parser.py로 nginx JSON 파싱, network_parser.py로
직접 파싱)를 계속 쓰고 있었다. 그 결과 WEB_LOG_LOCAL_PATH가 (조사 도구 쪽 기준에
맞춰) apache 샘플을 가리키는 지금 상태에서는, 이 모듈의 web 수집이 nginx JSON
포맷을 기대하다가 조용히 0건으로 실패하고 있었다(에러가 안 나서 눈치채기 어려웠음
— 웰시님이 발견). 그래서 audit·auth와 똑같은 패턴으로 web·network도
primary_detection.normalizer.tools.fetch_apache_log/fetch_network_log의 순수
파싱 함수를 직접 재사용하도록 교체했다. 이제 이 모듈이 쓰는 4계층 전부
1차 탐지팀 정규화 함수 하나로 통일됐고, agent/tools/parsers/nginx_json_parser.py·
network_parser.py는 더 이상 아무 데서도 쓰이지 않는다(agent/tools/parsers/README.md
갱신 필요 — 삭제는 다음 정리에서).

audit/auth·web/network 공통: agent.tools.normalizer_adapter의 normalize_*()를
그대로 쓰지는 않는다 — 이 모듈은 자체적으로 RAW_LOG_LOCAL_MAX_LINES만큼 마지막
줄만 잘라 읽는(무료 티어 토큰 한도 회피용) _read_layer_text()를 갖고 있는데,
adapter.py의 함수들은 로컬 파일을 항상 통째로 읽어서 이 잘라내기 기능이 없다.
그래서 이 모듈은 소스 읽기(S3/로컬 선택 + 줄 자르기)는 그대로 자기가 하고, 잘라낸
텍스트를 임시 파일에 쓴 뒤 1차 탐지팀의 "순수 파싱 함수"만 직접 불러써서
구조화한다(_events_via_normalizer 참고) — adapter.py의 S3/로컬 선택 로직은
건너뛴다(이미 이 모듈이 그 역할을 하고 있어서 중복이기 때문).

*** 현재 한계 ***
팀 결정사항 기준으로 S3 로그 수집이 실제로 켜져 있다고 확인된 건 auditd(audit) 뿐이다.
web/auth/network 파티션에 아직 데이터가 없으면 그냥 빈 리스트로 조용히 넘어간다
(에러 아님) — 인프라팀이 나머지도 연결하면 자동으로 같이 잡힌다.

*** 로컬 테스트 모드 ***
agent/tools/real/fetch_*.py와 동일한 환경변수(WEB_LOG_LOCAL_PATH,
AUTH_LOG_LOCAL_PATH, AUDIT_LOG_LOCAL_PATH, NETWORK_LOG_LOCAL_PATH)가 있으면
S3 대신 그 로컬 파일을 읽는다. AWS 키가 생기면 .env에서 이 줄들만 지우면 된다.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from primary_detection.normalizer.tools.fetch_apache_log import fetch_apache_log as _normalize_web_text
from primary_detection.normalizer.tools.fetch_audit_log import fetch_audit_log as _normalize_audit_text
from primary_detection.normalizer.tools.fetch_auth_log import fetch_auth_log as _normalize_auth_text
from primary_detection.normalizer.tools.fetch_network_log import fetch_network_log as _normalize_network_text
from .tools.real._s3_common import daterange, list_and_read_text
from .tools.time_utils import parse_iso

DEFAULT_BUCKET = "ogwanwan-shop-bucket"

# S3 경로의 source_type= 값과, 결과 레코드에 태그로 남길 이름을 매핑.
# (2026-09-22: web은 조사 도구 쪽과 맞춰 nginx -> apache로 정정 — WEB_LOG_LOCAL_PATH/
# WEB_LOG_BUCKET이 가리키는 실제 대상이 이제 apache access.log이기 때문)
SOURCE_TYPES = {
    "web": "apache",
    "auth": "auth",
    "audit": "auditd",
    "network": "suricata",
}

# agent/tools/real/fetch_*.py와 동일한 이름의 로컬 대체 환경변수.
LOCAL_PATH_ENV = {
    "web": "WEB_LOG_LOCAL_PATH",
    "auth": "AUTH_LOG_LOCAL_PATH",
    "audit": "AUDIT_LOG_LOCAL_PATH",
    "network": "NETWORK_LOG_LOCAL_PATH",
}


def _flatten(event: Dict[str, Any]) -> Dict[str, Any]:
    """공통스키마 {timestamp, layer, raw_ref, src_ip, pid, ppid, layer_data:{...}} 를
    LLM이 읽기 편하도록 layer_data를 top-level에 펼친 평평한 dict 하나로 만든다.
    (agent/tools/real/fetch_audit_log.py·fetch_auth_log.py의 _flatten()과 동일한 규칙 —
    같은 raw 로그에 대해 두 진입점이 같은 모양의 결과를 내도록 맞춘다.)
    """
    flat = {k: v for k, v in event.items() if k != "layer_data"}
    flat.update(event.get("layer_data") or {})
    return flat


def _events_via_normalizer(text: str, suffix: str, normalize_fn, **kwargs) -> List[Dict[str, Any]]:
    """이미 읽어들인(그리고 필요하면 잘라낸) raw 텍스트를 임시 파일에 쓴 뒤,
    1차 탐지팀 공통 정규화 함수(primary_detection.normalizer.tools.fetch_audit_log/
    fetch_auth_log/fetch_apache_log/fetch_network_log)의 순수 파싱 함수를 그대로
    불러써서 공통스키마 이벤트 리스트로 만든다.
    time_window는 넘기지 않는다 — 시간 필터는 fetch_recent_raw_logs()가 밖에서
    _ts 기준으로 따로 적용한다(로컬 모드에선 아예 끄기도 하므로 여기서 걸러버리면 안 된다).
    """
    if not text.strip():
        return []
    fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        events = normalize_fn(tmp_path, **kwargs)
    finally:
        os.remove(tmp_path)

    flat_events = [_flatten(e) for e in events]
    for e in flat_events:
        ts_str = e.get("timestamp")
        e["_ts"] = parse_iso(ts_str) if ts_str else None
    return flat_events


def _events_from_text(source_key: str, text: str) -> List[Dict[str, Any]]:
    """소스 타입별로 raw 텍스트를 이벤트 단위 레코드로 가공한다.
    반환되는 각 이벤트는 내부 필터링용 "_ts"(datetime|None)를 포함한다 — 호출자가
    시간 범위로 거른 뒤 제거해야 한다.
    """
    if source_key == "audit":
        # 1차 탐지팀 공통 정규화 함수 재사용(agent/tools/real/fetch_audit_log.py와 동일 코드).
        return _events_via_normalizer(text, ".log", _normalize_audit_text)

    if source_key == "web":
        # 1차 탐지팀 공통 정규화 함수 재사용(agent/tools/real/fetch_web_log.py와 동일 코드).
        # 2026-09-22: nginx_json_parser.py(자체 파서) 대신 apache access.log 정규화로 교체.
        return _events_via_normalizer(text, ".log", _normalize_web_text)

    if source_key == "auth":
        # 1차 탐지팀 공통 정규화 함수 재사용(agent/tools/real/fetch_auth_log.py와 동일 코드).
        # syslog는 연도가 없어서 "지금"의 연도를 기준으로 삼는다(연말/연초 경계 한계는 기존과 동일).
        return _events_via_normalizer(
            text, ".log", _normalize_auth_text, year=datetime.now(timezone.utc).year
        )

    if source_key == "network":
        # 1차 탐지팀 공통 정규화 함수 재사용(agent/tools/real/fetch_network_log.py와 동일 코드).
        # 2026-09-22: network_parser.py(자체 파서) 대신 정규화 함수로 교체.
        return _events_via_normalizer(text, ".json", _normalize_network_text)

    # 여기 도달하면 알 수 없는 source_key다 (지금은 4계층 다 위에서 처리되므로
    # 실제로는 호출될 일이 없다) — 안전하게 빈 리스트를 반환한다.
    return []


def _read_layer_text(
    source_key: str,
    s3_source_type: str,
    host: str,
    bucket: str,
    start: datetime,
    end: datetime,
) -> str:
    """이 계층의 로컬 대체 경로가 있으면 그 파일을, 없으면 S3를 읽는다.
    로컬 파일일 때는 RAW_LOG_LOCAL_MAX_LINES(기본 30)만큼 마지막 줄만 잘라서
    반환한다 — 안 자르면 무료 티어 분당 토큰 한도(429 에러)를 바로 넘긴다.
    """
    local_path = os.environ.get(LOCAL_PATH_ENV[source_key])
    if local_path:
        if not os.path.exists(local_path):
            return ""
        with open(local_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        max_lines = int(os.environ.get("RAW_LOG_LOCAL_MAX_LINES", "30"))
        lines = [line for line in text.splitlines() if line.strip()]
        return "\n".join(lines[-max_lines:])

    import boto3  # 실제 호출 시에만 필요하므로 지연 import

    s3 = boto3.client("s3", region_name=os.environ.get("AWS_DEFAULT_REGION"))
    chunks: List[str] = []
    for date_str in daterange(start, end):
        prefix = f"raw/source_type={s3_source_type}/host={host}/dt={date_str}/"
        text, _ = list_and_read_text(s3, bucket, prefix)
        chunks.append(text)
    return "\n".join(chunks)


def fetch_recent_raw_logs(
    host: str,
    minutes: int = 10,
    source_types: Optional[List[str]] = None,
    bucket: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """최근 `minutes`분 동안의 raw log를 source_type 구분 없이 전부 긁어온다.

    반환되는 각 레코드에는 어느 소스에서 왔는지 알 수 있도록 "_source_type" 키를
    덧붙인다 (원본 필드와 충돌하지 않도록 언더스코어 프리픽스 사용).
    """
    source_types = source_types or list(SOURCE_TYPES.keys())
    bucket = bucket or os.environ.get("AUDIT_LOG_BUCKET", DEFAULT_BUCKET)

    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=minutes)

    all_records: List[Dict[str, Any]] = []

    for source_key in source_types:
        # 로컬 샘플 모드(*_LOCAL_PATH)일 땐 "진짜 지금 기준 최근 N분" 필터를 끈다.
        # 샘플 로그는 실제 과거 시각(예: 2026-09-13 새벽)을 그대로 담고 있어서,
        # 이 필터를 그대로 적용하면 "지금(실행 시점)으로부터 10분 이내"가 아니라서
        # audit/web/auth가 실제 타임스탬프를 갖게 된 뒤로 전부 걸러져 버린다.
        # 로컬 모드에선 RAW_LOG_LOCAL_MAX_LINES(마지막 N줄)가 이미 "관심 구간"을
        # 정하는 역할을 하므로, 절대 시각 필터는 S3(실운영) 모드에서만 의미가 있다.
        is_local_mode = bool(os.environ.get(LOCAL_PATH_ENV[source_key]))

        s3_source_type = SOURCE_TYPES.get(source_key, source_key)
        text = _read_layer_text(source_key, s3_source_type, host, bucket, start, end)
        for record in _events_from_text(source_key, text):
            ts = record.pop("_ts", None)
            if not is_local_mode and ts is not None and not (start <= ts <= end):
                continue
            record["_source_type"] = source_key
            all_records.append(record)

    return all_records