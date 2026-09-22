"""fetch_auth_log 실제 구현 - EC2의 auth.log(syslog)를 읽어온다.

파일명 == 함수명 규칙에 따라 agent/tools/real/fetch_auth_log.py 안의 fetch_auth_log
함수만 있으면 agent/tools/registry.py의 build_default_registry()가 자동으로 이 함수를
mock_tools.py 대신 사용한다.

*** 2026-09-22 업데이트 (B: 조사 도구 담당) ***
자체 파서(parsers/auth_parser.py, "Accepted password"만 인식하던 버그 있던 버전)를 버리고
1차 탐지팀 공통 정규화 함수(agent/tools/normalizer_adapter.py → normalizer/tools/fetch_auth_log.py)
를 쓰도록 교체했다. 완료 기준(같은 raw 로그에 대해 1차 탐지와 에이전트 도구가 동일한
정규화 결과를 반환해야 한다)을 지키기 위해, S3/로컬 소스 선택과 파싱은 전부
normalizer.adapter.normalize_auth() 에 맡긴다. 이 파일은 그 결과를 우리 tool 인터페이스
(args dict → {count, summary, records, total_matched, has_more, next_offset})로 감싸는
얇은 어댑터 역할만 한다 — parsers/auth_parser.py 는 더 이상 여기서 쓰지 않는다.

*** 필드가 예전과 달라졌다 (팀 공유 필요) ***
예전 parsers/auth_parser.py: event_type(ssh_login/sudo/pam 3종) · source_ip · raw_log_ref
새 공통 정규화 함수: event(ssh_accepted/ssh_failed/ssh_invalid_user/ssh_probe/pam_auth_failure/
pam_session_opened/sudo_command/sudo_denied/su_success/su_failure/pkexec_*/account_* 등 훨씬
세분화된 값) · src_ip · raw_ref. loop.py/report.py/models.py 는 이 필드명을 하드코딩하지
않고 LLM이 반환한 JSON(evidence)만 읽으므로(2026-09-22 확인) 코드는 안 깨지지만, tool을
event_type=... 필터로 호출할 때 넘기는 값은 이제 새 세분화된 이벤트 이름이어야 한다.

*** limit/offset 페이지네이션 유지 ***
공통 정규화 함수는 전체 목록만 돌려주고 페이지네이션이 없어서, 예전과 동일하게 이
파일이 직접 slicing 한다 (SSH 브루트포스 하나로도 수백 건씩 매칭될 수 있어서 필요).

필요 환경변수: agent/tools/normalizer_adapter.py 문서 참고
  (.env에 AUTH_LOG_LOCAL_PATH 있으면 로컬 파일, 없으면 AUTH_LOG_BUCKET/S3)
"""

from __future__ import annotations

from typing import Any, Dict

from ..normalizer_adapter import normalize_auth

DEFAULT_LIMIT = 200


def _flatten(event: Dict[str, Any]) -> Dict[str, Any]:
    """공통스키마 {timestamp, layer, raw_ref, src_ip, pid, ppid, layer_data:{...}} 를
    LLM이 읽기 편하도록 layer_data를 top-level에 펼친 평평한 dict 하나로 만든다.
    (primary_detection/normalizer/common/schema.py 의 get_field()와 같은 목적 — 다만 여긴
    필터링 없이 전부 펼친다. 안 쓰는 필드는 LLM이 알아서 무시한다.)
    """
    flat = {k: v for k, v in event.items() if k != "layer_data"}
    flat.update(event.get("layer_data") or {})
    return flat


def fetch_auth_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start_time = args["start_time"]
    end_time = args["end_time"]
    limit = int(args.get("limit", DEFAULT_LIMIT))
    offset = int(args.get("offset", 0))

    events = normalize_auth(
        host,
        start_time,
        end_time,
        user=args.get("user"),
        src_ip=args.get("src_ip"),
        event=args.get("event_type"),  # 우리 tool schema의 event_type == 공통 정규화의 event
        result=args.get("result"),
    )
    all_events = [_flatten(e) for e in events]

    total_matched = len(all_events)
    page = all_events[offset : offset + limit]
    has_more = (offset + limit) < total_matched

    if total_matched == 0:
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 인증 이벤트를 찾지 못했습니다. "
            "host 이름, 기간, 또는 AUTH_LOG_LOCAL_PATH/AUTH_LOG_BUCKET 설정을 확인하세요."
        )
    else:
        page_desc = f"{offset}~{offset + len(page) - 1}번째" if page else "0건"
        more_desc = f"더 있음 (next_offset={offset + limit})" if has_more else "더 없음"
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 인증 이벤트 총 {total_matched}건 중 "
            f"{page_desc} {len(page)}건 반환. ({more_desc}, event/result까지 구조화, "
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
