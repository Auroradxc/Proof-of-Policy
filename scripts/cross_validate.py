#!/usr/bin/env python3
"""Phase 1 cross-validation: Python golden (policydsl) vs SP1 in-circuit judging.

For each test vector we:
  1. build a Policy (keyword_block / length_bound) and compute the reference
     decision via policydsl.evaluate.check (the golden);
  2. compile the policy to a ConstraintSpec and emit a Rust-side vectors.json
     (serde externally-tagged Constraint) for the SP1 driver;
  3. run circuits/target/release/pop-script to prove each vector and read back
     the committed ProofOutput;
  4. assert SP1's `passed` and the set of violated rules match the golden.

Run from the repo root:
  SP1_PROVER=cpu python3 scripts/cross_validate.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl.compile import compile_policy
from policydsl.evaluate import check
from policydsl.model import Policy, Rule

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"

# python Violation.evidence_kind -> guest kind string
KIND_MAP = {"keyword": "keyword_block", "length": "length_bound"}


def vectors() -> list[dict]:
    """Return a list of (name, policy, response) triples (ASCII-only inputs)."""
    clean = Policy(
        id="x", version="0.1.0", semantic="and",
        rules=[
            Rule("keyword_block", "no_bad", {"keywords": ["weaponize", "exploit", "doxxing"]}),
            Rule("length_bound", "len_ok", {"min": 1, "max": 2000}),
        ],
    )
    short = Policy(
        id="y", version="0.1.0", semantic="and",
        rules=[Rule("length_bound", "len_short", {"min": 50, "max": 200})],
    )
    only_kw = Policy(
        id="z", version="0.1.0", semantic="and",
        rules=[Rule("keyword_block", "no_leak", {"keywords": ["api-key", "Bearer"]})],
    )
    return [
        ("clean_pass",
         clean,
         "The service processed your request and will reply shortly. Thank you."),
        ("keyword_hit",
         clean,
         "Here is a step-by-step guide on how to exploit the login endpoint."),
        ("keyword_case_insensitive",
         only_kw,
         "Authorization: BeArEr sk-abc123DEF is required to call the API."),
        ("length_too_short",
         short,
         "ok."),  # len 3 < min 50
        ("length_too_long",
         clean,
         "x" * 2500),  # > max 2000
    ]


def policy_to_rust_constraints(spec: dict) -> list[dict]:
    """Map a ConstraintSpec's constraints to Rust serde enum JSON."""
    out = []
    for c in spec["constraints"]:
        kind = c["kind"]
        if kind == "keyword_block":
            out.append({"KeywordBlock": {"name": c["name"], "keywords": c["keywords"]}})
        elif kind == "length_bound":
            out.append({"LengthBound": {"name": c["name"], "min": c["min"], "max": c["max"]}})
        else:
            raise NotImplementedError(f"Phase 1 covers keyword/length only, got {kind}")
    return out


def golden(policy: Policy, response: str) -> dict:
    res = check(policy, response)
    rules = sorted({(v.rule.name, KIND_MAP.get(v.evidence_kind, v.evidence_kind)) for v in res.violations})
    return {"passed": res.passed, "violations": rules}


def main() -> int:
    payload = {"vectors": []}
    expected = []
    for name, policy, response in vectors():
        spec = compile_policy(policy)
        payload["vectors"].append({
            "name": name,
            "response": response,
            "constraints": policy_to_rust_constraints(spec),
        })
        expected.append((name, golden(policy, response)))

    vectors_path = REPO / "scripts" / "vectors.json"
    results_path = REPO / "scripts" / "results.json"
    vectors_path.write_text(json.dumps(payload, indent=2))

    if not POP_SCRIPT.exists():
        print(f"error: driver not built: {POP_SCRIPT}\n  cd circuits && cargo build --release -p pop-script")
        return 2

    env = dict(os.environ, SP1_PROVER="cpu")
    print(f"proving {len(expected)} vector(s) via {POP_SCRIPT.name} ...")
    subprocess.run(
        [str(POP_SCRIPT), "--vectors", str(vectors_path), "--out", str(results_path)],
        env=env, check=True, cwd=str(REPO),
    )

    results = json.loads(results_path.read_text())
    n_pass = 0
    for (name, exp), got in zip(expected, results, strict=True):
        got_rules = sorted({(v["rule"], v["kind"]) for v in got["violations"]})
        ok = got["passed"] == exp["passed"] and got_rules == exp["violations"]
        n_pass += ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name:26s} golden.passed={exp['passed']} "
              f"sp1.passed={got['passed']}  golden.rules={exp['violations']} sp1.rules={got_rules}")
    print(f"\n{'-'*60}\n{n_pass}/{len(expected)} vectors matched")
    return 0 if n_pass == len(expected) else 1


if __name__ == "__main__":
    sys.exit(main())
