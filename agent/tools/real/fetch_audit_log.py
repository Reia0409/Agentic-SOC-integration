"""fetch_audit_log 실제 구현 - EC2에서 S3로 쌓인 auditd 로그를 읽어온다.

파일명 == 함수명 규칙에 따라 agent/tools/real/fetch_audit_log.py 안의 fetch_audit_log
함수만 있으면 agent/tools/registry.py의 build_default_registry()가 자동으로 이 함수를
mock_tools.py 대신 사용한다. (agent/tools/real/README.md 참고)

*** 2026-09-22 업데이트 (B: 조사 도구 담당) ***
자체 파서(parsers/audit_parser.py)를 버리고 1차 탐지팀 공통 정규화 함수
(agent/tools/normalizer_adapter.py → normalizer/tools/fetch_audit_log.py)를 쓰도록
교체했다. 완료 기준(같은 raw 로그에 대해 1차 탐지와 에이전트 도구가 동일한 정규화
결과를 반환해야 한다)을 지키기 위해, S3/로컬 소스 선택과 파싱은 전부
normalizer.adapter.normalize_audit() 에 맡긴다. 이 파일은 그 결과를 우리 tool
인터페이스(args dict → {count, summary, records})로 감싸는 얇은 어댑터 역할만 한다 —
parsers/audit_parser.py 는 더 이상 여기서 쓰지 않는다. (2026-09-22 추가: G 작업에서
get_process_tree.py도 같은 normalize_audit()로 교체돼서 audit_parser.py는 완전히
안 쓰이게 됐고, 실제로 parsers/ 폴더에서 삭제했다.)

*** user/serial 필터는 공통 정규화 함수에 없어서 여기서 후처리 ***
1차 탐지팀 fetch_audit_log()의 필터는 time_window/pid/ppid/key/session_type/
exclude_interactive 뿐이라(user·serial 없음), 예전과 동일하게 이 파일이 결과를
받은 뒤 user/serial 조건으로 한 번 더 걸러준다.

필요 환경변수: agent/tools/normalizer_adapter.py 문서 참고
  (.env에 AUDIT_LOG_LOCAL_PATH 있으면 로컬 파일, 없으면 AUDIT_LOG_BUCKET/S3)
"""

from __future__ import annotations

from typing import Any, Dict

from ..normalizer_adapter import normalize_audit


def _flatten(event: Dict[str, Any]) -> Dict[str, Any]:
    """공통스키마 {timestamp, layer, raw_ref, src_ip, pid, ppid, layer_data:{...}} 를
    LLM이 읽기 편하도록 layer_data를 top-level에 펼친 평평한 dict 하나로 만든다.
    """
    flat = {k: v for k, v in event.items() if k != "layer_data"}
    flat.update(event.get("layer_data") or {})
    return flat


def fetch_audit_log(args: Dict[str, Any]) -> Dict[str, Any]:
    host = args["host"]
    start_time = args["start_time"]
    end_time = args["end_time"]

    events = normalize_audit(
        host,
        start_time,
        end_time,
        pid=args.get("pid"),
        ppid=args.get("ppid"),
        key=args.get("event_type"),  # 우리 tool schema의 event_type == auditd 룰 key
        exclude_interactive=args.get("exclude_interactive", False),
    )
    flat_events = [_flatten(e) for e in events]

    if "user" in args:
        flat_events = [e for e in flat_events if e.get("user") == args["user"]]
    if "serial" in args:
        flat_events = [e for e in flat_events if e.get("serial") == args["serial"]]

    if not flat_events:
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 audit 이벤트를 찾지 못했습니다. "
            "host 이름, 기간, 또는 AUDIT_LOG_LOCAL_PATH/AUDIT_LOG_BUCKET 설정을 확인하세요."
        )
    else:
        summary = (
            f"{host}의 {start_time}~{end_time} 구간에서 조건에 맞는 audit 이벤트 {len(flat_events)}건 확인 "
            "(uid/euid/session_type/exec_args까지 구조화해서 반환, 1차 탐지팀 공통 정규화 함수 사용)"
        )

    return {"count": len(flat_events), "summary": summary, "records": flat_events}
