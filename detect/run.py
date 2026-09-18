"""detect/run.py — ① 정규화(4계층) → ② Sigma 매칭 → seed 를 한 번에 실행.

예)
  python detect/run.py                                   # .env 경로로 4계층 전부
  python detect/run.py --audit tools/sample_audit.log    # 특정 계층 경로만 덮어쓰기
  python detect/run.py --out-normalized out/n.jsonl --out-seeds out/s.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detect.engine import detect  # noqa: E402
from detect.loader import load_rules  # noqa: E402
from tools.normalize import normalize_all  # noqa: E402

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apache")
    ap.add_argument("--auth")
    ap.add_argument("--network")
    ap.add_argument("--audit")
    ap.add_argument("--rules", default=str(HERE / "rules" / "sigma"), help="Sigma 룰 디렉터리(재귀)")
    ap.add_argument("--out-normalized", help="정규화 이벤트 JSONL 저장 경로")
    ap.add_argument("--out-seeds", help="seed JSONL 저장 경로")
    ap.add_argument("--window", type=int, default=60, help="seed window 반경(초)")
    ap.add_argument("--show", type=int, default=3, help="룰별로 콘솔에 보여줄 매칭 예시 수")
    args = ap.parse_args()

    rules = load_rules(args.rules)
    print(f"[rules] {len(rules)}개 로드: " + str(dict(Counter(r.path.parent.name for r in rules))))

    events = normalize_all(apache_path=args.apache, auth_path=args.auth,
                           network_path=args.network, audit_path=args.audit)
    print(f"[normalize] 이벤트 {len(events)}건, 계층별={dict(Counter(e['layer'] for e in events))}")

    if args.out_normalized:
        Path(args.out_normalized).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out_normalized, "w", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps(e, ensure_ascii=False) + "\n")
        print(f"[normalize] 저장: {args.out_normalized}")

    hits: dict[str, list] = defaultdict(list)
    seeds = []
    for ev, rule, seed in detect(events, rules, args.window):
        hits[rule.name].append(ev)
        seeds.append(seed)

    print(f"\n[detect] seed {len(seeds)}건")
    for r in rules:
        evs = hits.get(r.name, [])
        if not evs:
            continue
        print(f"  - {r.path.parent.name}/{r.name} [{r.level}]: {len(evs)}건")
        for e in evs[: args.show]:
            ld = e["layer_data"]
            brief = {k: ld[k] for k in ("event", "user", "src_user", "comm", "exec_args", "method", "path", "user_agent")
                     if ld.get(k) is not None}
            print(f"      {e['timestamp']} src_ip={e['src_ip']} pid={e['pid']} {brief} ref={e['raw_ref']}")

    if args.out_seeds:
        Path(args.out_seeds).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out_seeds, "w", encoding="utf-8") as fh:
            for s in seeds:
                fh.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"[detect] 저장: {args.out_seeds}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
