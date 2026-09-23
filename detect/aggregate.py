"""detect/aggregate.py — seed 노이즈 축소 (집계 + 임계값).

문제: 브루트포스처럼 "시도 1건당 seed 1개"가 나오면(예: SSH 실패 1,371 → seed 1,371),
사건묶기·트리아지가 노이즈에 묻힌다.

해결(2단):
  ① 집계  — 같은 (룰, entity) seed 를 하나로 합치고 count·window[처음,마지막]·evidence 를 보존.
  ② 임계값 — 저심각(low/medium) 인데 count 가 min_count 미만이면 버린다(단발 노이즈).
            high/critical 은 단발이어도 항상 남긴다(놓치면 안 되는 신호).
"""
from __future__ import annotations

_THRESHOLD_LEVELS = frozenset({"low", "medium"})


def aggregate_seeds(seeds, min_count: int = 5):
    """seed 리스트 → 집계·임계값 적용된 seed 리스트.

    같은 (reason, entity.type, entity.value) 를 1건으로 합친다:
      window       = [모든 start 의 min, 모든 end 의 max]
      evidence_refs = 합집합(순서 보존)
      count        = 합쳐진 원본 seed 수 (신규 필드)
    합친 뒤 count < min_count 이고 rule_severity 가 low/medium 이면 버린다.
    """
    groups: dict = {}  # 3.7+ dict 는 삽입순 보존 → OrderedDict 불필요
    for s in seeds:
        key = (s["reason"], s["entity"]["type"], s["entity"]["value"])
        g = groups.get(key)
        if g is None:
            g = dict(s)
            g["window"] = list(s["window"])
            g["evidence_refs"] = list(s.get("evidence_refs", []))
            g["_refset"] = set(g["evidence_refs"])
            g["count"] = 1
            groups[key] = g
            continue
        g["count"] += 1
        w = s["window"]
        if w and w[0] is not None and (g["window"][0] is None or w[0] < g["window"][0]):
            g["window"][0] = w[0]
        if w and w[1] is not None and (g["window"][1] is None or w[1] > g["window"][1]):
            g["window"][1] = w[1]
        for r in s.get("evidence_refs", []):
            if r not in g["_refset"]:
                g["_refset"].add(r)
                g["evidence_refs"].append(r)

    out = []
    for g in groups.values():
        g.pop("_refset", None)
        sev = g.get("score_parts", {}).get("rule_severity")
        if g["count"] < min_count and sev in _THRESHOLD_LEVELS:
            continue  # 저심각 단발 노이즈 → 버림
        out.append(g)
    return out


if __name__ == "__main__":  # 자체 점검: python detect/aggregate.py
    def _seed(reason, ip, ref, level, w0, w1):
        return {"entity": {"type": "src_ip", "value": ip}, "window": [w0, w1],
                "layer": "auth", "source": ["sigma"], "reason": reason,
                "score_parts": {"rule_severity": level, "deviation": None, "layer_count": 1},
                "signal_tags": [], "evidence_refs": [ref]}

    # 같은 룰·IP 브루트포스 6건 → 1건(count=6), window 는 [처음, 마지막]
    brute = [_seed("SSH fail", "1.2.3.4", f"auth.log:{i}", "low",
                   f"2026-09-20T00:00:0{i}Z", f"2026-09-20T00:00:0{i}Z") for i in range(6)]
    agg = aggregate_seeds(brute, min_count=5)
    assert len(agg) == 1 and agg[0]["count"] == 6
    assert agg[0]["window"] == ["2026-09-20T00:00:00Z", "2026-09-20T00:00:05Z"]
    assert len(agg[0]["evidence_refs"]) == 6

    # 저심각 단발 → 임계값 미달로 버림
    assert aggregate_seeds([_seed("x", "9.9.9.9", "a:1", "low", "t", "t")], min_count=5) == []
    # high 단발 → 항상 남김
    keep = aggregate_seeds([_seed("crit", "9.9.9.9", "a:1", "high", "t", "t")], min_count=5)
    assert len(keep) == 1 and keep[0]["count"] == 1
    print("ok")
