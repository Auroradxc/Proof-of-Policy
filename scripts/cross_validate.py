#!/usr/bin/env python3
"""Phase 1-2 cross-validation: Python golden (policydsl) vs SP1.

For each test vector we:
  1. build a Policy and compute the reference decision via policydsl.evaluate
     (the golden; pattern_block judged by the compiled NFA == the contract);
  2. compile the policy to a ConstraintSpec and emit a Rust-side vectors.json
     (serde externally-tagged Constraint: KeywordBlock / LengthBound /
     PatternBlock) for the SP1 driver;
  3a. HOST CHECK (fast, all vectors): pop-script --check  → pop-types::evaluate
  3b. PROVE (real proofs, all vectors): pop-script            → guest ProofOutput
  4. assert passed + violated-rule set match the golden in both modes.

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
from policydsl import pii

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"

# python Violation.evidence_kind -> guest kind string
KIND_MAP = {"keyword": "keyword_block", "length": "length_bound", "pattern": "pattern_block"}


def vectors() -> list[tuple]:
    """Return (name, policy, response) triples. Inputs are ASCII-only."""
    base = Policy(
        id="x", version="0.1.0", semantic="and",
        rules=[
            Rule("keyword_block", "no_bad", {"keywords": ["weaponize", "exploit", "doxxing"]}),
            Rule("length_bound", "len_ok", {"min": 1, "max": 2000}),
        ],
    )
    pii_email = Policy(
        id="p1", version="0.1.0", semantic="and",
        rules=[Rule("pattern_block", "no_email", {"patterns": [pii.PII_PATTERNS["email"]]})],
    )
    pii_secret = Policy(
        id="p2", version="0.1.0", semantic="and",
        rules=[Rule("pattern_block", "no_secret", {"patterns": [pii.PII_PATTERNS["secret_key"]]})],
    )
    return [
        ("clean_pass", base,
         "The service processed your request and will reply shortly. Thank you."),
        ("keyword_hit", base,
         "Here is a step-by-step guide on how to exploit the login endpoint."),
        ("length_too_long", base, "x" * 2500),
        ("email_hit", pii_email, "My details: reach dev@example.com anytime."),
        ("email_clean", pii_email, "This guidance contains no addresses or mailboxes."),
        ("secret_hit", pii_secret, "Rotate the key sk-abcdefghijklmnopqrstuvwxyz now."),
        ("secret_clean", pii_secret, "All credentials have been rotated."),
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
        elif kind == "pattern_block":
            out.append({"PatternBlock": {
                "name": c["name"],
                "patterns": c["patterns"],
                "specs": c["nfa"]["compiled"],
            }})
        else:
            raise NotImplementedError(f"Phase 1-2 covers keyword/length/pattern only, got {kind}")
    return out


def golden(policy: Policy, response: str) -> dict:
    res = check(policy, response)
    rules = sorted({(v.rule.name, KIND_MAP.get(v.evidence_kind, v.evidence_kind))
                    for v in res.violations})
    return {"passed": res.passed, "violations": rules}


def run_pop(mode: str, vectors_path: Path, out_path: Path) -> None:
    args = [str(POP_SCRIPT)]
    if mode == "check":
        args.append("--check")
    args += ["--vectors", str(vectors_path), "--out", str(out_path)]
    env = dict(os.environ, SP1_PROVER="cpu")
    subprocess.run(args, env=env, check=True, cwd=str(REPO))


def compare(results: list, expected: list) -> tuple[int, list[str]]:
    ok_flags, detail = [], []
    for (name, exp), got in zip(expected, results, strict=True):
        got_rules = sorted({(v["rule"], v["kind"]) for v in got["violations"]})
        ok = got["passed"] == exp["passed"] and got_rules == exp["violations"]
        ok_flags.append(ok)
        detail.append((name, ok, exp, got))
    return sum(ok_flags), detail


def report(kind: str, ok_flags: list, detail: list) -> None:
    for (name, ok, exp, got) in detail:
        print(f"[{'PASS' if ok else 'FAIL'}] {kind:5s} {name:20s} "
              f"golden.passed={exp['passed']} sp1.passed={got['passed']}  "
              f"rules={exp['violations']} vs {[(v['rule'], v['kind']) for v in got['violations']]}")
    print(f"{kind}: {sum(ok_flags)}/{len(ok_flags)} matched")


def main() -> int:
    vectors_in = vectors()
    payload = {"vectors": []}
    expected = []
    for name, policy, response in vectors_in:
        spec = compile_policy(policy)
        payload["vectors"].append({
            "name": name,
            "response": response,
            "constraints": policy_to_rust_constraints(spec),
        })
        expected.append((name, golden(policy, response)))

    if not POP_SCRIPT.exists():
        print(f"error: driver not built: {POP_SCRIPT}\n  cd circuits && cargo build --release -p pop-script")
        return 2

    scripts = REPO / "scripts"
    vectors_path = scripts / "vectors.json"
    vectors_path.write_text(json.dumps(payload, indent=2))
    print(f"{len(expected)} vectors, mode: host-check (all) + real proofs (all)")

    results_check = scripts / "results_check.json"
    print("--- host check (pop-types::evaluate, no proof) ---")
    run_pop("check", vectors_path, results_check)
    rc = json.loads(results_check.read_text())
    n1, d1 = compare(rc, expected)
    report("check", [ok for _, ok, _, _ in d1], d1)

    results_prove = scripts / "results_prove.json"
    print("--- real proofs (SP1 guest) ---")
    run_pop("prove", vectors_path, results_prove)
    rp = json.loads(results_prove.read_text())
    n2, d2 = compare(rp, expected)
    report("prove", [ok for _, ok, _, _ in d2], d2)

    ok = n1 == len(expected) and n2 == len(expected)
    print("\n" + "=" * 60)
    print(f"RESULT: host {n1}/{len(expected)}  prove {n2}/{len(expected)}  {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
