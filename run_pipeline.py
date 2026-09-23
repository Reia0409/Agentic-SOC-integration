"""run_pipeline.py — 정규화 → 탐지 → 사건묶기 전체를 실행해 Incident 를 낸다.

detect/run.py 는 seed 까지만 만든다. 이 파일은 그 seed 를 correlate() 에 넣어
Incident 까지 잇는 엔드투엔드 러너다(새 로직 없이 기존 함수 배선만).

예)
  python run_pipeline.py                                  # .env 경로로 4계층 전부
  python run_pipeline.py --audit tools/sample_audit.log   # 특정 계층 경로만 덮어쓰기
  python run_pipeline.py --out-incidents out/incidents.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from correlate.grouping import correlate  # noqa: E402
from detect.aggregate import aggregate_seeds  # noqa: E402
from detect.engine import detect  # noqa: E402
from detect.loader import load_rules  # noqa: E402
from detect.suricata_seed import build_suricata_seeds  # noqa: E402
from tools.normalize import normalize_all  # noqa: E402

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apache")
    ap.add_argument("--auth")
    ap.add_argument("--network")
    ap.add_argument("--audit")
    ap.add_argument("--rules", default=str(HERE / "detect" / "rules" / "sigma"), help="Sigma 룰 디렉터리(재귀)")
    ap.add_argument("--window", type=int, default=60, help="seed window 반경(초)")
    ap.add_argument("--min-count", type=int, default=5,
                    help="seed 집계 후 저심각(low/medium) 최소 발생 수(미만이면 버림)")
    ap.add_argument("--no-require-seed", action="store_true",
                    help="탐지 seed 없는 클러스터도 사건으로 낸다(기본: 안 냄)")
    ap.add_argument("--out-incidents", help="Incident JSONL 저장 경로")
    ap.add_argument("--show", type=int, default=10, help="콘솔에 보여줄 다계층 사건 수")
    args = ap.parse_args()

    # ① 정규화
    events = normalize_all(apache_path=args.apache, auth_path=args.auth,
                           network_path=args.network, audit_path=args.audit)
    print(f"[normalize] 이벤트 {len(events)}건, 계층별={dict(Counter(e['layer'] for e in events))}")

    # ② 탐지 → seed
    rules = load_rules(args.rules)
    sigma_seeds = [seed for _ev, _rule, seed in detect(events, rules, args.window)]
    suricata_seeds, _rejects = build_suricata_seeds(events, window_seconds=args.window)
    seeds = sigma_seeds + suricata_seeds
    raw_n = len(seeds)
    seeds = aggregate_seeds(seeds, min_count=args.min_count)
    print(f"[detect] seed {raw_n}건(Sigma {len(sigma_seeds)} + Suricata {len(suricata_seeds)}) "
          f"→ 집계·임계값 후 {len(seeds)}건")

    # ③ 사건묶기
    incidents = correlate(events, seeds, require_seed=not args.no_require_seed)
    dist = Counter(len(set(i["layers"])) for i in incidents)
    multi = [i for i in incidents if len(set(i["layers"])) >= 2]
    print(f"[correlate] Incident {len(incidents)}건, 계층수 분포={dict(sorted(dist.items()))}, 다계층(2+)={len(multi)}건")

    for i in sorted(multi, key=lambda x: -len(x["members"]))[: args.show]:
        joins = sorted({e["join"] for e in i["join_path"]})
        reasons = list({s.get("reason") for s in i.get("seeds", [])})[:3]
        print(f"  {i['incident_id']} layers={sorted(set(i['layers']))} members={len(i['members'])} "
              f"joins={joins} entity={i.get('entity')} seeds={len(i.get('seeds', []))} {reasons}")

    if args.out_incidents:
        Path(args.out_incidents).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out_incidents, "w", encoding="utf-8") as fh:
            for i in incidents:
                fh.write(json.dumps(i, ensure_ascii=False) + "\n")
        print(f"[correlate] 저장: {args.out_incidents}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
