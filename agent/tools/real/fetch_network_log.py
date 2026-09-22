"""fetch_network_log 실제 구현 - Suricata eve.json을 읽어온다 (S3 또는 로컬 파일).

파일명 == 함수명 규칙에 따라 agent/tools/real/fetch_network_log.py 안의
fetch_network_log 함수만 있으면 agent/tools/registry.py의 build_default_registry()가
자동으로 이 함수를 mock_tools.py 대신 사용한다.

*** 2026-09-22 업데이트 (network 계층도 1차 탐지팀 공통 정규화 함수로 교체) ***
자체 파서(parsers/network_parser.py)를 버리고 1차 탐지팀 공통 정규화 함수
(agent/tools/normalizer_adapter.py → normalizer/tools/fetch_network_log.py)를 쓰도록
교체했다. 완료 기준(같은 raw 로그에 대해 1차 탐지와 에이전트 도구가 동일한 정규화
결과를 반환해야 한다)을 지키기 위해, S3/로컬 소스 선택과 파싱은 전부
normalizer.adapter.normalize_network()에 맡긴다. Suricata eve.json 포맷 자체는
parsers/network_parser.py 때와 동일한 소스라 형식 호환 문제는 없었다.

*** dst_ip/src_port/dst_port/protocol 필터는 공통 정규화 함수에 없어서 여기서 후처리 ***
1차 탐지팀 fetch_network_log()의 필터는 time_window/src_ip/event_type/flow_id/
signature 뿐이라(dst_ip·src_port·dst_port·protocol 없음), 예전과 동일하게 이 파일이
결과를 받은 뒤 그 조건으로 한 번 더 걸러준다. alert_only는 event_type="alert"로
그대로 정규화 함수에 넘긴다.

*** direction(internal/outbound/inbound) 계산은 여전히 안 함 ***
예전 parsers/network_parser.py와 동일한 이유(호스트 IP 사전 등록 단계가 우리
시스템엔 없음) — 1차 탐지팀 공통스키마에도 그 필드는 없다.

*** limit/offset 페이지네이션 유지 (auth/web과 동일한 이유) ***

필요 환경변수: agent/tools/normalizer_adapter.py 문서 참고
  (.env에 NETWORK_LOG_LOCAL_PATH 있으면 로컬 파일, 없으면 NETWORK_LOG_BUCKET/S3)
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..normalizer_adapter import normalize_network


def _flatten(event: Dict[str, Any]) -> Dict[str, Any]:
    """공통스키마 {timestamp, layer, raw_ref, src_ip, pid, ppid, layer_data:{...}} 를
    LLM이 읽기 편하도록 layer_data를 top-level에 펼친 평평한 dict 하나로 만든다.
    (agent/tools/real/fetch_audit_log.py·fetch_auth_log.py의 _flatten()과 동일한 규칙.)
    """
    flat = {k: v for k, v in event.items() if k != "layer_data"}
    flat.update(event.get("layer_data") or {})
    return flat


def fetch_network_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start_time = args["start_time"]
    end_time = args["end_time"]
    limit = int(args.get("limit", 200))
    offset = int(args.get("offset", 0))

    event_type = "alert" if args.get("alert_only") else None

    events = normalize_network(
        host,
        start_time,
        end_time,
        src_ip=args.get("src_ip"),
        event_type=event_type,
    )
    flat_events: List[Dict[str, Any]] = [_flatten(e) for e in events]

    if args.get("dst_ip") is not None:
        flat_events = [e for e in flat_events if e.get("dest_ip") == args["dst_ip"]]
    if args.get("src_port") is not None:
        flat_events = [e for e in flat_events if e.get("transport_src_port") == int(args["src_port"])]
    if args.get("dst_port") is not None:
        flat_events = [e for e in flat_events if e.get("transport_dest_port") == int(args["dst_port"])]
    if args.get("protocol") is not None:
        flat_events = [
            e for e in flat_events if (e.get("protocol") or "").upper() == str(args["protocol"]).upper()
        ]

    total_matched = len(flat_events)
    page = flat_events[offset : offset + limit]
    has_more = (offset + limit) < total_matched

    if not flat_events:
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 네트워크 이벤트를 찾지 못했습니다. "
            "host 이름, 기간, 또는 NETWORK_LOG_LOCAL_PATH/NETWORK_LOG_BUCKET 설정을 확인하세요."
        )
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={offset + limit})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 네트워크 이벤트 총 {total_matched}건 중 "
            f"{page_desc} {len(page)}건 반환. ({more_desc}, http 이벤트는 url/method/status/xff까지 포함, "
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
