"""fetch_web_log 실제 구현 - EC2의 apache access 로그를 읽어온다 (S3 또는 로컬 파일).

파일명 == 함수명 규칙에 따라 agent/tools/real/fetch_web_log.py 안의 fetch_web_log
함수만 있으면 agent/tools/registry.py의 build_default_registry()가 자동으로 이 함수를
mock_tools.py 대신 사용한다.

*** 2026-09-22 업데이트 (web 계층도 1차 탐지팀 공통 정규화 함수로 교체) ***
자체 파서(parsers/nginx_json_parser.py)를 버리고 1차 탐지팀 공통 정규화 함수
(agent/tools/normalizer_adapter.py → normalizer/tools/fetch_apache_log.py)를 쓰도록
교체했다. 완료 기준(같은 raw 로그에 대해 1차 탐지와 에이전트 도구가 동일한 정규화
결과를 반환해야 한다)을 지키기 위해, S3/로컬 소스 선택과 파싱은 전부
normalizer.adapter.normalize_web()에 맡긴다.

*** 왜 nginx가 아니라 apache로 바꿨는가 ***
EC2에 SSH로 직접 접속해 확인(2026-09-22): nginx(리버스 프록시, 80/443)와 apache
(백엔드, 127.0.0.1:8080)가 같이 떠 있고, apache의 access.log가 1차 탐지팀
fetch_apache_log.py가 기대하는 포맷(%t %{req_id} %a %{c}a %{scheme} %{Host}i "%r"
%>s %O %D %P "%{Referer}i" "%{User-Agent}i" xff="...")과 컬럼 단위로 정확히
일치했다. nginx의 JSON 로그는 실존하지만 1차 탐지팀 파서가 다루는 대상이 아니라서,
1차 탐지팀 설계를 그대로 따르기로 하고 web 계층의 정규화 대상을 apache로 바꿨다.
(예전엔 nginx JSON을 "uri"/"xff" 필드로 다뤘지만, 이제 apache 스키마는 "path"
필드를 쓰고 client IP(%a)가 이미 실제 클라이언트라 xff 보정이 필요 없다.)

*** limit/offset 페이지네이션 유지 (auth/network와 동일한 이유) ***

필요 환경변수: agent/tools/normalizer_adapter.py 문서 참고
  (.env에 WEB_LOG_LOCAL_PATH 있으면 로컬 파일 — 이제 apache access.log를 가리켜야
  함, 없으면 WEB_LOG_BUCKET/S3의 raw/source_type=apache/... 파티션)
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..normalizer_adapter import normalize_web


def _flatten(event: Dict[str, Any]) -> Dict[str, Any]:
    """공통스키마 {timestamp, layer, raw_ref, src_ip, pid, ppid, layer_data:{...}} 를
    LLM이 읽기 편하도록 layer_data를 top-level에 펼친 평평한 dict 하나로 만든다.
    (agent/tools/real/fetch_audit_log.py·fetch_auth_log.py의 _flatten()과 동일한 규칙.)
    """
    flat = {k: v for k, v in event.items() if k != "layer_data"}
    flat.update(event.get("layer_data") or {})
    return flat


def fetch_web_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start_time = args["start_time"]
    end_time = args["end_time"]
    limit = int(args.get("limit", 200))
    offset = int(args.get("offset", 0))

    path_pattern = None
    if "path" in args and args["path"]:
        import re

        path_pattern = re.escape(args["path"])  # 부분 문자열 매칭처럼 동작하게(정규식 특수문자 이스케이프)

    status = args.get("status_code")
    if status is not None:
        status = int(status)

    events = normalize_web(
        host,
        start_time,
        end_time,
        src_ip=args.get("src_ip"),
        path_pattern=path_pattern,
        status=status,
        method=args.get("method"),
        exclude_self=args.get("exclude_self", False),
    )
    all_events: List[Dict[str, Any]] = [_flatten(e) for e in events]

    total_matched = len(all_events)
    page = all_events[offset : offset + limit]
    has_more = (offset + limit) < total_matched

    if not all_events:
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 web 요청을 찾지 못했습니다. "
            "host 이름, 기간, 또는 WEB_LOG_LOCAL_PATH/WEB_LOG_BUCKET 설정을 확인하세요."
        )
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={offset + limit})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 web 요청 총 {total_matched}건 중 "
            f"{page_desc} {len(page)}건 반환. ({more_desc}, method/path/status/duration_us까지 구조화, "
            "1차 탐지팀 공통 정규화 함수 사용)"
        )

    return {
        "count": len(page),
        "summary": summary,
        "records": page,
        "total_matched": total_matched,
        "has_more": has_more,
        "next_offset": offset + limit if has_more else None,
    }
