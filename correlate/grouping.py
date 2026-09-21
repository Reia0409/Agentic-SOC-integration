"""
correlate/grouping.py — 사건 묶기 총괄 (통합)

입력: normalize_all() 이벤트 스트림 + 탐지가 만든 seed(앵커)
처리: links/ 자동 로드 → 전 계층쌍 edge 수집 → guards(오연결 방지) → 클러스터 → Incident
출력: Incident 리스트 → Triage/조사 에이전트

담당자는 links/<pair>.py 에 @register_linker edge 함수만 추가하면 자동으로 합류한다
(이 파일은 안 건드림).
"""

import os
import importlib

import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlate.registry import LINKERS
from correlate.guards import apply_guards
from correlate.incident import build_incident


def _load_linkers():
    """links/ 폴더의 모든 pair 모듈을 import 해 @register_linker 를 발동시킨다."""
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "links")
    if not os.path.isdir(d):
        return
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".py") and not fn.startswith("_"):
            try:
                importlib.import_module("correlate.links." + fn[:-3])
            except Exception as exc:  # 한 링크가 깨져도 나머지는 돌아간다
                print("[correlate] 링크 로드 실패 %s: %s" % (fn, exc))


def _clusters(nodes, edges):
    """union-find 로 edge 로 연결된 raw_ref 들을 클러스터로 묶는다."""
    parent = {n: n for n in nodes}

    def find(x):
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    for e in edges:
        a, b = e["a"], e["b"]
        if a in parent and b in parent:
            parent[find(a)] = find(b)

    groups = {}
    for n in nodes:
        groups.setdefault(find(n), []).append(n)
    return list(groups.values())


def correlate(events, seeds=None):
    """이벤트 + seed → Incident 리스트."""
    seeds = list(seeds or [])
    _load_linkers()
    by_ref = {e["raw_ref"]: e for e in events}

    # 1) 전 계층쌍 edge 수집 → 2) 오연결 방지
    edges = []
    for linker in LINKERS:
        edges += linker(events)
    edges = apply_guards(edges, events)

    # 3) edge 로 연결된 노드만 클러스터 대상
    nodes = set()
    for e in edges:
        nodes.add(e["a"])
        nodes.add(e["b"])

    incidents = []
    used = set()
    for cluster in _clusters(nodes, edges):
        cset = set(cluster)
        cev = [by_ref[r] for r in cluster if r in by_ref]
        cedges = [e for e in edges if e["a"] in cset and e["b"] in cset]
        cseeds = [s for s in seeds if set(s.get("evidence_refs", [])) & cset]
        for s in cseeds:
            used.add(id(s))
        incidents.append(build_incident(cev, cedges, cseeds))

    # 4) 어느 클러스터에도 안 붙은 seed → 단일 계층 사건(누락 방지)
    for s in seeds:
        if id(s) in used:
            continue
        cev = [by_ref[r] for r in s.get("evidence_refs", []) if r in by_ref]
        if cev:
            incidents.append(build_incident(cev, [], [s]))

    incidents.sort(key=lambda i: i["window"][0] or "")
    return incidents


if __name__ == "__main__":
    # 데모: normalize_all() 로 실제 이벤트를 받아 사건 묶기 (seed 없이 edge만)
    from tools.normalize import normalize_all
    evs = normalize_all()
    incs = correlate(evs)
    print("이벤트 %d건 → 사건 %d건" % (len(evs), len(incs)))
    for i in incs:
        print("  %s layers=%s members=%d join=%d" % (
            i["incident_id"], i["layers"], len(i["members"]), len(i["join_path"])))
