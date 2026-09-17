"""
tools/normalize.py — ① 정규화 오케스트레이터

파싱(정규화)은 각 fetch_*_log 도구가 담당한다. 이 모듈은 파싱을 다시 하지 않고,
계층별 fetch 를 불러 나온 공통스키마 이벤트를 전 계층 합쳐 timestamp(UTC)로 정렬만
한다. ② 탐지(Sigma 엔진)의 입력(정규화된 이벤트 스트림)을 만드는 코드 단계다.

원칙:
  - "raw → 공통스키마" 로직은 각 fetch_*_log 한 곳에만 존재(중복 파서 금지).
  - 여기서는 fan-out(계층별 호출) + merge + sort 만.
  - 현재 계층: web(apache) + auth + network(suricata). system(audit)은 도구를 없애 제외
    → 나중에 fetch_audit_log 를 만들면 여기 한 줄 + .env AUDIT_LOG_PATH 만 추가.

경로는 .env 에서 읽는다: APACHE_LOG_PATH / AUTH_LOG_PATH / SURICATA_LOG_PATH
"""

import os
from datetime import datetime, timezone

# 스크립트로 직접 실행돼도 레포 루트를 path 에 올려 top-level 패키지(tools/common)를 찾게 한다.
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:  # dotenv 선택 의존성
    from dotenv import load_dotenv
    load_dotenv()
except Exception:  # pragma: no cover
    pass

# 파싱은 각 도구의 '순수 함수'를 직접 쓴다(@register 래퍼 말고). 현재 계층 3종.
from tools.fetch_apache_log import fetch_apache_log      # web
from tools.fetch_auth_log import fetch_auth_log          # auth
from tools.fetch_network_log import fetch_network_log    # network
# system(audit)은 나중에: 여기에 `from tools.fetch_audit_log import fetch_audit_log` 추가


def _ts_key(event):
    """timestamp(ISO8601 UTC, 'Z') → datetime. 정밀도 차이에도 정확히 정렬."""
    s = (event.get("timestamp") or "").strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _safe(fetch_fn, path, **kwargs):
    """도구 하나 호출. 도구/경로 없거나 파일 없으면 조용히 빈 리스트(정규화는 안 죽는다)."""
    if fetch_fn is None or not path:
        return []
    try:
        return fetch_fn(path, **kwargs)
    except FileNotFoundError:
        return []


def normalize_all(
    apache_path=None,
    auth_path=None,
    network_path=None,
    sort=True,
):
    """전 계층 raw 로그 → 공통스키마 이벤트 하나의 리스트로 정규화(fan-out + merge + sort).

    각 경로 생략 시 .env 에서 읽는다. 특정 계층만 넘기면 그 계층만 정규화된다.
    현재 계층: web(apache) + auth + network(suricata). system(audit)은 나중에 추가.
    반환: list[dict] (공통스키마), sort=True면 timestamp(UTC) 오름차순.
    """
    apache_path = apache_path or os.getenv("APACHE_LOG_PATH")
    auth_path = auth_path or os.getenv("AUTH_LOG_PATH")
    network_path = network_path or os.getenv("SURICATA_LOG_PATH")

    events = []
    events += _safe(fetch_apache_log, apache_path)    # web
    events += _safe(fetch_auth_log, auth_path)        # auth
    events += _safe(fetch_network_log, network_path)  # network
    # system(audit)은 나중에: events += _safe(fetch_audit_log, audit_path)

    if sort:
        events.sort(key=_ts_key)  # 전 계층 공통 정렬축 = timestamp(UTC)
    return events


if __name__ == "__main__":
    evs = normalize_all()
    by_layer = {}
    for e in evs:
        by_layer[e["layer"]] = by_layer.get(e["layer"], 0) + 1
    print("정규화 이벤트 %d건, 계층별=%s" % (len(evs), by_layer))
    for e in evs[:5]:
        print("  %s  %-7s %s" % (e["timestamp"], e["layer"], e["raw_ref"]))
