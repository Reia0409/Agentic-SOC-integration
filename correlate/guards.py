"""
correlate/guards.py — 오연결 방지 (edge → edge 필터)

edges 를 클러스터로 묶기 '전에' 약한 연결을 거른다.
설계 원칙: "IP만 같거나 시간만 가까운 경우 자동 병합 제한."

현재 규칙:
  1) 중복 edge 제거 (a,b,join 같으면 하나만; 방향 무시)
  2) 자기 자신(a==b) 제거
  3) 약한 join 단독 차단 — WEAK_JOINS 에 든 join 은 탈락(현재 비어 있음)

확장 지점(통합 담당): 한 신호(시간만/IP만)로만 잇는 join 이 생기면 WEAK_JOINS 에 추가하거나,
edge["keys"] 를 보고 신호 개수·강도 기반 규칙을 여기서 강화한다.
"""

# 단독으로는 클러스터 병합을 허용하지 않을 join 이름(예: 향후 "time_only", "ip_only")
WEAK_JOINS = set()


def apply_guards(edges, events=None):
    """약한/중복 edge 를 걸러 유효 edge 리스트를 돌려준다."""
    seen = set()
    out = []
    for e in edges:
        if e["a"] == e["b"]:
            continue
        if e["join"] in WEAK_JOINS:
            continue
        key = frozenset((e["a"], e["b"])), e["join"]  # 방향 무시 중복 제거
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out
