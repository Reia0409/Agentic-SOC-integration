"""
correlate/incident.py — 사건(Incident) 데이터 구조 = 사건 묶기의 출력 계약

grouping 이 이벤트 클러스터 하나를 Incident dict 로 조립한다. 이게 Triage/조사 에이전트의 입력.

Incident 형태:
  {
    "incident_id":  "INC-<8hex>",              # members 해시(재현 가능)
    "entity":       {"type","value"},          # 대표 조사 대상(seed 있으면 seed.entity)
    "window":       [min_ts, max_ts],          # 사건 시간 범위(UTC)
    "layers":       ["web","system",...],      # 걸친 계층
    "members":      ["apache_access.log:10",…],# 묶인 이벤트 raw_ref
    "join_path":    [ {a,b,join,keys}, … ],    # 연결에 쓴 edge (XAI: 왜 묶였나)
    "evidence_refs":[…],                       # = members (원본 역추적)
    "seeds":        [ …seed… ],                # 이 사건에 걸린 seed(탐지 결과)
  }
"""

import hashlib


def _window(events):
    ts = sorted(e["timestamp"] for e in events if e.get("timestamp"))
    return [ts[0], ts[-1]] if ts else [None, None]


def _entity(events, seeds):
    """대표 엔티티: seed 있으면 seed.entity, 없으면 이벤트에서 가장 흔한 src_ip → pid 순."""
    if seeds:
        return dict(seeds[0]["entity"])
    ips = [e.get("src_ip") for e in events if e.get("src_ip")]
    if ips:
        return {"type": "src_ip", "value": max(set(ips), key=ips.count)}
    pids = [e.get("pid") for e in events if e.get("pid") is not None]
    if pids:
        return {"type": "pid", "value": str(max(set(pids), key=pids.count))}
    return {"type": "src_ip", "value": None}


def build_incident(events, edges, seeds):
    """이벤트 클러스터 + 연결 edge + 걸린 seed → Incident dict 1건."""
    members = sorted(e["raw_ref"] for e in events)
    iid = "INC-" + hashlib.sha1("|".join(members).encode("utf-8")).hexdigest()[:8]
    return {
        "incident_id": iid,
        "entity": _entity(events, seeds),
        "window": _window(events),
        "layers": sorted({e["layer"] for e in events}),
        "members": members,
        "join_path": list(edges),
        "evidence_refs": members,
        "seeds": list(seeds),
    }
