#!/usr/bin/env python3
"""Phase 4 private-mode demo / verification.

Checks the private pipeline end-to-end:
  - HOST CHECK: pop-script --check (pop-types::evaluate_private) vs the Python
    golden (policydsl.commit.private_output) — field-for-field, including the
    response commitment, per-violation evidence commitments, and redaction proof.
  - LEAK experiment: the public output the verifier sees must not contain the
    response text or the evidence fragments (only commitments).
  - UNFORGEABILITY/binding: commitments are deterministic and distinct across
    inputs; a redaction that differs outside the mask is rejected.
  - PROOF: the same private job is proven in SP1 and the committed outcome is
    re-checked (skip with --no-prove).

Usage:
  SP1_PROVER=cpu python3 scripts/private_demo.py [--no-prove]
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

from policydsl import commit, pii
from policydsl.compile import compile_policy
from policydsl.model import Policy, Rule
from policydsl.serialize import spec_to_rust_constraints

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"


def build_case() -> dict:
    policy = Policy("private-demo", "0.1", rules=[
        Rule("keyword_block", "no_bad", {"keywords": ["exploit", "doxxing"]}),
        Rule("length_bound", "len_ok", {"min": 1, "max": 2000}),
        Rule("pattern_block", "no_email", {"patterns": [pii.PII_PATTERNS["email"]]}),
    ])
    response = "Reach dev@example.com to continue; we will not doxxing anyone."
    spec = compile_policy(policy)
    mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], response)
    redacted = commit.redact(response, mask)
    golden = commit.private_output(spec, response, mask, redacted)
    vector = {
        "name": policy.id,
        "response": response,
        "constraints": spec_to_rust_constraints(spec),
        "private": True,
        "mask": mask,
        "redacted": redacted,
    }
    return {"policy": policy, "spec": spec, "response": response, "redacted": redacted,
            "mask": mask, "golden": golden, "vector": vector}


def run_pop(check_mode: bool, vectors: Path, out: Path) -> None:
    args = [str(POP_SCRIPT)]
    if check_mode:
        args.append("--check")
    args += ["--vectors", str(vectors), "--out", str(out)]
    subprocess.run(args, env=dict(os.environ, SP1_PROVER="cpu"), check=True, cwd=str(REPO))


def compare_private(mode: str, golden: dict, got: dict) -> bool:
    g_rules = sorted((v["rule"], v["kind"], v["evidence_commitment"]) for v in golden["violations"])
    s_rules = sorted((v["rule"], v["kind"], v["evidence_commitment"]) for v in got["violations"])
    checks = {
        "passed": got["passed"] == golden["passed"],
        "response_commitment": got["response_commitment"] == golden["response_commitment"],
        "violations": g_rules == s_rules,
        "redaction": (got["redaction"] or {}) == (golden["redaction"] or {}),
    }
    ok = all(checks.values())
    print(f"[{'PASS' if ok else 'FAIL'}] {mode:5s} "
          f"passed={got['passed']} commit={got['response_commitment'][:12]}… "
          f"rules={[(r, k) for r, k, _ in s_rules]} redaction={got['redaction']}")
    if not ok:
        for k, v in checks.items():
            if not v:
                print(f"   mismatch: {k} golden={golden.get(k)} got={got.get(k)}")
    return ok


def leak_experiment(case: dict, public_out: dict) -> bool:
    """The verifier-visible output must not contain response/evidence text."""
    blob = json.dumps(public_out)
    response = case["response"]
    leaks = [w for w in set(response.split()) if len(w) >= 4 and w in blob]
    # commitments are 64-hex and differ from the plaintext
    commit_ok = len(public_out["response_commitment"]) == 64
    commit_ok &= all(len(v["evidence_commitment"]) == 64 for v in public_out["violations"])
    not_plain = public_out["response_commitment"] != response
    ok = not leaks and commit_ok and not_plain
    print(f"[{'PASS' if ok else 'FAIL'}] leak      no response tokens in output={not leaks} "
          f"commitments_64hex={commit_ok} not_plaintext={not_plain}")
    return ok


def binding_experiment(case: dict, spec: dict) -> bool:
    """Commitments are deterministic and distinct across inputs; a redaction
    altering a non-masked position is rejected."""
    a = commit.commitment(case["response"])
    b = commit.commitment(case["response"] + "x")
    deterministic = a == commit.commitment(case["response"])
    distinct = a != b
    # tamper outside the mask -> redaction_ok False
    tampered = "Q" + case["redacted"][1:]
    forged_ok = commit.redaction_ok(case["response"], tampered, case["mask"])
    # a wrong mask (drop a position) must fail too
    ok = deterministic and distinct and (not forged_ok)
    print(f"[{'PASS' if ok else 'FAIL'}] binding   deterministic={deterministic} "
          f"distinct={distinct} forged_redaction_rejected={not forged_ok}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-prove", action="store_true")
    args = ap.parse_args()

    case = build_case()
    out_dir = REPO / "scripts" / "examples" / "out" / "private"
    out_dir.mkdir(parents=True, exist_ok=True)
    vectors = out_dir / "vectors.json"
    vectors.write_text(json.dumps({"vectors": [case["vector"]]}, indent=2))
    print("private vectors:", json.dumps(case["vector"])[:120], "...")

    ok = True

    hout = out_dir / "host.json"
    run_pop(True, vectors, hout)
    got = json.loads(hout.read_text())[0]
    ok &= compare_private("check", case["golden"], got)
    ok &= leak_experiment(case, got)
    ok &= binding_experiment(case, case["spec"])

    if not args.no_prove:
        pout = out_dir / "proof.json"
        print("--- proving private job (SP1, ~1 min) ---")
        run_pop(False, vectors, pout)
        got_p = json.loads(pout.read_text())[0]
        ok &= compare_private("prove", case["golden"], got_p)
        ok &= leak_experiment(case, got_p)
    else:
        print("(--no-prove: skipped SP1 proof)")

    print("\nRESULT: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
