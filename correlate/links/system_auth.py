"""
correlate/links/system_auth.py — Audit↔Auth 연결 (담당: 지희)

계층쌍: 시스템(audit) ↔ 인증(auth)
연결 키: pid 단독.
  audit.log 에는 ses/auid 가 없어서(설계 문서: JOIN_RULES["system_auth"] = "pid"),
  pid 가 같으면 "그 프로세스가 그 인증 세션에서 실행됐다"고 보고 잇는다.
  시간 근접은 보지 않는다 — pid 재사용으로 인한 오연결은 guards/상위 단계에서 다룬다.

역할 경계 (왜 계보를 여기서 안 하나):
  - 이 파일은 audit → auth '단일 edge'만 만든다.
  - PID 계보(PPID→PID)로 자식 프로세스까지 잇는 건 audit_lineage(민혁)가 담당한다.
  - grouping(통합)이 [system_auth edge] + [audit_lineage edge] + [web_system edge] 를 합쳐
    apache → www-data audit → 그 자식 프로세스 → auth 세션까지 하나의 사건으로
    전이(transitive) 연결한다. 여기서 계보를 또 하면 중복.

판정 predicate 는 common/join_keys.system_auth_match 를 재사용한다(로직 한 곳, 중복 금지).

edge 계약(전 계층쌍 공통 — web_system.py 가 먼저 제안한 형식과 동일):
  {
    "a":   "<raw_ref_system>",   # audit 이벤트의 원본 포인터(= XAI 역추적 ID)
    "b":   "<raw_ref_auth>",     # auth 이벤트
    "join":"system_auth",        # 어떤 규칙으로 이었나 → grouping이 join_path에 기록
    "keys":{"pid":..}            # 연결 근거(pid) → 오연결 방지/디버깅
  }
"""

import os
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from common.join_keys import system_auth_match
from correlate.registry import register_linker

JOIN = "system_auth"


@register_linker
def system_auth_edges(events):
    """events(system+auth 혼재) → audit↔auth edge 리스트.

    system 이벤트마다, pid 가 같은 auth 이벤트를 잇는다. 1:1로 강제하지 않는다
    — "묶일 수 있는 후보"는 넉넉히 만들고(코드), guards/클러스터 단계가 정리한다.

    결정과 근거:
      · pid 단독 매칭       → audit.log 에 ses/auid 가 없어 시간·uid 로 좁힐 수단이 없음(JOIN_RULES).
      · 시간창을 두지 않음   → 같은 pid 면 사실상 같은 프로세스. 필요해지면 join_keys 쪽에
                              time_proximity 를 추가로 걸면 된다(판정 로직은 거기 한 곳에만).
      · pid 없는 이벤트 제외 → system_auth_match 자체가 None 을 걸러준다.
    """
    systems = [e for e in events if e.get("layer") == "system"]
    auths = [e for e in events if e.get("layer") == "auth"]

    edges = []
    for s in systems:
        for a in auths:
            if system_auth_match(s, a):   # pid 단독 (join_keys)
                edges.append({
                    "a": s["raw_ref"],
                    "b": a["raw_ref"],
                    "join": JOIN,
                    "keys": {"pid": s.get("pid")},
                })
    return edges


if __name__ == "__main__":
    # 최소 데모 (파일 없이)
    audit = {"timestamp": "2026-09-11T02:00:04.100Z", "layer": "system",
             "raw_ref": "audit.log:21", "pid": 1400, "ppid": 1301,
             "layer_data": {"uid": 33, "user": "www-data", "comm": "curl"}}
    auth = {"timestamp": "2026-09-11T02:00:06.000Z", "layer": "auth",
            "raw_ref": "auth.log:30", "pid": 1400, "ppid": None,
            "layer_data": {"event": "sudo_command", "user": "root", "src_user": "www-data"}}
    print(system_auth_edges([audit, auth]))