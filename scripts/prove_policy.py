#!/usr/bin/env python3
"""Phase 3 transparent-mode demo / MVP gate.

Given a policy pack and a real agent response, prove the response satisfies the
policy inside SP1 and verify independently. Pipeline:
  pack.json --compile--> ConstraintSpec --serialize--> ProofRequest
  response.txt ------------------------------> pop-script (SP1 prove+verify)
and cross-check the committed ProofOutput against the Python golden
(policydsl.evaluate). Exit 0 iff the response is proven and the golden agrees.

Usage:
  SP1_PROVER=cpu python3 scripts/prove_policy.py \
      --pack policy_packs/eu_ai_act_v1.json \
      --response scripts/examples/eu_agent_reply.txt \
      [--out-dir scripts/examples/out] [--no-prove] [--expect pass|violate]

--expect: assert which outcome the golden should report (sanity guard).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

from policydsl.compile import compile_policy
from policydsl.evaluate import check
from policydsl.model import Policy, PolicyError, Rule
from policydsl.serialize import spec_to_rust_constraints

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
KIND_MAP = {"keyword": "keyword_block", "length": "length_bound", "pattern": "pattern_block"}


def load_policy(path: Path) -> Policy:
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = [
        Rule(kind=r["kind"], name=r.get("name", f"rule-{i}"), params=r.get("params", {}))
        for i, r in enumerate(data.get("rules", []))
    ]
    return Policy(id=data["id"], version=data.get("version", "0.1.0"),
                  description=data.get("description", ""), rules=rules,
                  semantic=data.get("semantic", "and"))


def golden(policy: Policy, response: str) -> dict:
    res = check(policy, response)
    rules = sorted({(v.rule.name, KIND_MAP.get(v.evidence_kind, v.evidence_kind))
                    for v in res.violations})
    return {"passed": res.passed, "violations": rules}


def run_pop(check_mode: bool, vectors: Path, out: Path) -> None:
    args = [str(POP_SCRIPT)]
    if check_mode:
        args.append("--check")
    args += ["--vectors", str(vectors), "--out", str(out)]
    subprocess.run(args, env=dict(os.environ, SP1_PROVER="cpu"), check=True, cwd=str(REPO))


def summarize(mode: str, exp: dict, got: dict) -> bool:
    got_rules = sorted({(v["rule"], v["kind"]) for v in got["violations"]})
    ok = got["passed"] == exp["passed"] and got_rules == exp["violations"]
    print(f"[{'PASS' if ok else 'FAIL'}] {mode:5s} passed golden={exp['passed']} "
          f"sp1={got['passed']}  rules golden={exp['violations']} sp1={got_rules}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", type=Path, required=True)
    ap.add_argument("--response", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, default=REPO / "scripts" / "examples" / "out")
    ap.add_argument("--expect", choices=["pass", "violate"], default=None)
    ap.add_argument("--no-prove", action="store_true", help="host-check only (skip SP1 proof)")
    args = ap.parse_args()

    policy = load_policy(args.pack)
    response = args.response.read_text(encoding="utf-8")
    exp = golden(policy, response)
    if args.expect == "pass" and not exp["passed"]:
        print(f"golden did NOT pass but --expect pass; violations={exp['violations']}")
        return 2
    if args.expect == "violate" and exp["passed"]:
        print("golden passed but --expect violate")
        return 2

    spec = compile_policy(policy)
    vectors = {"vectors": [{
        "name": policy.id,
        "response": response,
        "constraints": spec_to_rust_constraints(spec),
    }]}

    args.out_dir.mkdir(parents=True, exist_ok=True)
    vpath = args.out_dir / "vectors.json"
    vpath.write_text(json.dumps(vectors, indent=2))

    ok = True
    # 1) host check (fast, pop-types::evaluate)
    hout = args.out_dir / "host.json"
    run_pop(True, vpath, hout)
    ok &= summarize("check", exp, json.loads(hout.read_text())[0])

    # 2) real proof + independent verify
    if not args.no_prove:
        pout = args.out_dir / "proof.json"
        print(f"--- proving {policy.id} (SP1, ~1 min) ---")
        run_pop(False, vpath, pout)
        ok &= summarize("prove", exp, json.loads(pout.read_text())[0])
    else:
        print("(--no-prove: skipped SP1 proof)")

    print("\nRESULT: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (PolicyError, NotImplementedError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
