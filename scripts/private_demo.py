#!/usr/bin/env python3
"""Phase 4 private-mode demo / verification (+ boundary hardening).

Checks the private pipeline end-to-end:
  - HOST CHECK: pop-script --check (pop-types::evaluate_private) vs the Python
    golden (policydsl.commit.private_output) — field-for-field, including the
    response commitment, evidence commitments, redaction proof, and the
    boundary property ``mask_covered`` (mask ⊆ genuine matches, enforced in-circuit).
  - NEGATIVE: a fabricated witness span (mask outside any real match) yields
    mask_covered=false.
  - LEAK: the verifier-visible output has no response/evidence text.
  - BINDING: commitments deterministic, distinct; forged redaction rejected.
  - EVIDENCE OPENING: a disclosed fragment verifies against its commitment.
  - PROOF: the same private job is proven in SP1 and re-checked (skip: --no-prove).

Usage: SP1_PROVER=cpu python3 scripts/private_demo.py [--no-prove]
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
    spans = commit.spec_spans(spec, response)
    golden = commit.private_output(spec, response, mask, redacted, spans)
    vector = {
        "name": policy.id,
        "response": response,
        "constraints": spec_to_rust_constraints(spec),
        "private": True,
        "mask": mask,
        "redacted": redacted,
        "spans": [list(s) for s in spans],
    }
    return {"policy": policy, "spec": spec, "response": response, "redacted": redacted,
            "mask": mask, "spans": spans, "golden": golden, "vector": vector}


def run_pop(check_mode: bool, vectors: Path, out: Path) -> None:
    args = [str(POP_SCRIPT)]
    if check_mode:
        args.append("--check")
    args += ["--vectors", str(vectors), "--out", str(out)]
    subprocess.run(args, env=dict(os.environ, SP1_PROVER="cpu"), check=True, cwd=str(REPO))


def compare_private(mode: str, name: str, golden: dict, got: dict) -> bool:
    g_rules = sorted((v["rule"], v["kind"], v["evidence_commitment"]) for v in golden["violations"])
    s_rules = sorted((v["rule"], v["kind"], v["evidence_commitment"]) for v in got["violations"])
    checks = {
        "passed": got["passed"] == golden["passed"],
        "response_commitment": got["response_commitment"] == golden["response_commitment"],
        "violations": g_rules == s_rules,
        "redaction": (got["redaction"] or {}) == (golden["redaction"] or {}),
    }
    ok = all(checks.values())
    print(f"[{'PASS' if ok else 'FAIL'}] {mode:5s} {name} passed={got['passed']} "
          f"rules={[(r, k) for r, k, _ in s_rules]} redaction={got['redaction']}")
    if not ok:
        for k, v in checks.items():
            if not v:
                print(f"   mismatch {k}: golden={golden.get(k)} got={got.get(k)}")
    return ok


def leak_experiment(case: dict, public_out: dict) -> bool:
    blob = json.dumps(public_out)
    leaks = [w for w in set(case["response"].split()) if len(w) >= 4 and w in blob]
    commit_ok = len(public_out["response_commitment"]) == 64
    commit_ok &= all(len(v["evidence_commitment"]) == 64 for v in public_out["violations"])
    ok = (not leaks) and commit_ok and public_out["response_commitment"] != case["response"]
    print(f"[{'PASS' if ok else 'FAIL'}] leak      no_tokens={not leaks} "
          f"commitments_64hex={commit_ok}")
    return ok


def binding_experiment(case: dict) -> bool:
    a = commit.commitment(case["response"])
    deterministic = a == commit.commitment(case["response"])
    distinct = a != commit.commitment(case["response"] + "x")
    forged_ok = commit.redaction_ok(case["response"], "Q" + case["redacted"][1:], case["mask"])
    ok = deterministic and distinct and not forged_ok
    print(f"[{'PASS' if ok else 'FAIL'}] binding   deterministic={deterministic} "
          f"distinct={distinct} forged_rejected={not forged_ok}")
    return ok


def evidence_experiment(case: dict) -> bool:
    bundle = commit.evidence_bundle(case["spec"], case["response"])
    ok_open = commit.verify_bundle(bundle) and len(bundle) == len(case["golden"]["violations"])
    # the disclosed commitment must equal the one in the proof output
    proof_comms = {v["evidence_commitment"] for v in case["golden"]["violations"]}
    bundled = {e["evidence_commitment"] for e in bundle}
    ok_bind = proof_comms == bundled
    # tampering breaks it
    bad = [dict(e) for e in bundle]
    bad[0]["evidence"] = "tampered"
    ok_reject = not commit.verify_bundle(bad)
    ok = ok_open and ok_bind and ok_reject
    print(f"[{'PASS' if ok else 'FAIL'}] opening   verified={ok_open} bound_to_proof={ok_bind} "
          f"tamper_rejected={ok_reject}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-prove", action="store_true")
    args = ap.parse_args()

    case = build_case()
    # negative case: fabricated witness span that does not cover the mask
    bad_vector = {**case["vector"], "name": "private-demo-badspan", "spans": [[0, 1]]}
    bad_golden = commit.private_output(case["spec"], case["response"], case["mask"],
                                       case["redacted"], [(0, 1)])

    out_dir = REPO / "scripts" / "examples" / "out" / "private"
    out_dir.mkdir(parents=True, exist_ok=True)

    check_vec = out_dir / "vectors_check.json"
    check_vec.write_text(json.dumps({"vectors": [case["vector"], bad_vector]}, indent=2))

    ok = True
    hout = out_dir / "host.json"
    run_pop(True, check_vec, hout)
    got = json.loads(hout.read_text())
    ok &= compare_private("check", "good", case["golden"], got[0])
    ok &= compare_private("check", "badspan", bad_golden, got[1])
    # the negative case must report mask_covered=false
    neg_ok = got[1]["redaction"]["mask_covered"] is False
    print(f"[{'PASS' if neg_ok else 'FAIL'}] negative  bad-span mask_covered=false (got "
          f"{got[1]['redaction']['mask_covered']})")
    ok &= neg_ok

    ok &= leak_experiment(case, got[0])
    ok &= binding_experiment(case)
    ok &= evidence_experiment(case)

    if not args.no_prove:
        pout = out_dir / "proof.json"
        prove_vec = out_dir / "vectors_prove.json"
        prove_vec.write_text(json.dumps({"vectors": [case["vector"]]}, indent=2))
        print("--- proving private job (SP1, ~1 min) ---")
        run_pop(False, prove_vec, pout)
        got_p = json.loads(pout.read_text())[0]
        ok &= compare_private("prove", "good", case["golden"], got_p)
        ok &= leak_experiment(case, got_p)
    else:
        print("(--no-prove: skipped SP1 proof)")

    print("\nRESULT: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
