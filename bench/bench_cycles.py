#!/usr/bin/env python3
"""Cycle-count matrix (zkVM execution, no proof) for Proof-of-Policy.

Sweeps response length x rule count x matcher mode and records the zkVM cycle
count via ``pop-script --execute``. Fast enough to cover many points; the
(much slower) proof time/size curve lives in ``bench_proofs.py``.

Usage:
  python3 bench/bench_cycles.py [--out bench/results/cycles.json]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import pii  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.serialize import spec_to_rust_constraints  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
WORK = REPO / "bench" / "work"

EMAIL = pii.PII_PATTERNS["email"]


def make_policy(rule_count: int, mode: str = "pike") -> Policy:
    """1 length rule + (rule_count-1) extra constraints (keyword/pattern)."""
    rules = [Rule("length_bound", "len", {"min": 1, "max": 10_000_000})]
    extras = [
        Rule("keyword_block", "kw", {"keywords": ["exploit", "weaponize", "doxxing"]}),
        Rule("pattern_block", "pat", {"patterns": [EMAIL], "match_mode": mode}),
        Rule("keyword_block", "kw2", {"keywords": ["terrorism", "child abuse"]}),
        Rule("pattern_block", "pat2", {"patterns": [pii.PII_PATTERNS["secret_key"]], "match_mode": mode}),
        Rule("keyword_block", "kw3", {"keywords": ["leverage"]}),
    ]
    rules.extend(extras[: max(0, rule_count - 1)])
    return Policy("bench", "1", rules=rules)


def response(prefix: str, length: int) -> str:
    body = (prefix + " ") * ((length // (len(prefix) + 1)) + 1)
    return body[:length]


def run_execute(vector: dict) -> dict:
    WORK.mkdir(parents=True, exist_ok=True)
    vp = WORK / "v.json"
    op = WORK / "r.json"
    vp.write_text(json.dumps({"vectors": [vector]}))
    subprocess.run([str(POP_SCRIPT), "--execute", "--vectors", str(vp), "--out", str(op)],
                   cwd=str(REPO), check=True, capture_output=True, text=True)
    return json.loads(op.read_text())[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "cycles.json")
    args = ap.parse_args()

    lengths = [200, 2_000, 20_000]
    rule_counts = [1, 3, 6]
    modes = ["pike", "naive"]
    rows = []
    for length in lengths:
        for rc in rule_counts:
            for mode in modes:
                # naive is O(n^2): keep it to the smaller lengths
                if mode == "naive" and length > 2_000:
                    continue
                policy = make_policy(rc, mode)
                spec = compile_policy(policy)
                # a long clean response (no hits) so all constraints must be scanned
                text = response("the quick brown fox jumps", length)
                out = run_execute({"name": f"L{length}-R{rc}-{mode}", "response": text,
                                   "constraints": spec_to_rust_constraints(spec)})
                rows.append({"length": length, "rules": rc, "mode": mode,
                             "cycles": out["cycles"], "passed": out["passed"]})
                print(f"L={length:>6} rules={rc} mode={mode:<5} cycles={out['cycles']:,}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rows, indent=2))

    md = ["# Cycle-count matrix (zkVM execution, no proof)", "",
          "| length | rules | mode | cycles |", "|---:|---:|:--|---:|"]
    for r in rows:
        md.append(f"| {r['length']} | {r['rules']} | {r['mode']} | {r['cycles']:,} |")
    (args.out.with_suffix(".md")).write_text("\n".join(md) + "\n")
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
