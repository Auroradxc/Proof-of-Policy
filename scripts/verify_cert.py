#!/usr/bin/env python3
"""Phase 5: independently verify a Proof-of-Policy compliance certificate.

A third party, holding only public artefacts, checks:
  1. DSSE envelope signature (integrity/authenticity);
  2. policy_hash == sha256 of the policy pack compiled *now* (policy binding);
  3. the certificate digest is present in the anchor ledger and the ledger chain
     is intact (record-keeping / tamper-evidence);
  4. (with --proof) the SP1 proof verifies cryptographically and its committed
     outcome + vkey hash match the certificate.

Usage:
  python3 scripts/verify_cert.py --cert scripts/examples/out/cert_public/cert.json \
      --pack policy_packs/eu_ai_act_v1.json \
      --ledger scripts/examples/out/ledger.jsonl \
      [--proof scripts/examples/out/cert_public/proof.bin]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import anchor, cert
from policydsl.compile import compile_policy
from policydsl.model import Policy, Rule

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"


def load_policy(path: Path) -> Policy:
    d = json.loads(path.read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r.get("name", f"r{i}"), params=r.get("params", {}))
             for i, r in enumerate(d["rules"])]
    return Policy(d["id"], d.get("version", "0.1.0"), rules=rules)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", type=Path, required=True)
    ap.add_argument("--pack", type=Path, required=True)
    ap.add_argument("--ledger", type=Path, required=True)
    ap.add_argument("--proof", type=Path, default=None)
    args = ap.parse_args()

    env = json.loads(args.cert.read_text(encoding="utf-8"))
    results = []

    # 1) signature
    ok_sig, payload = cert.verify_envelope(env, cert.DEMO_KEY)
    results.append(("signature", ok_sig, "HMAC-SHA256 envelope verified" if ok_sig else "bad signature"))
    if not ok_sig or payload is None:
        print_fail(results)
        return 1

    # 2) policy binding
    spec = compile_policy(load_policy(args.pack))
    ok_pol = payload["policy_hash"] == spec["sha256"]
    results.append(("policy_hash", ok_pol,
                    f"{payload['policy_hash'][:16]}… vs {spec['sha256'][:16]}…"))

    # 3) anchor ledger
    ok_chain, reason = anchor.verify_ledger(args.ledger)
    digest = cert.cert_digest(payload)
    entry = anchor.find_anchor(args.ledger, digest)
    ok_anchor = ok_chain and entry is not None
    results.append(("anchor", ok_anchor, f"chain={reason} entry={'found' if entry else 'MISSING'}"))

    # 4) proof (optional, cryptographic) — prefer the verifier-only binary
    POP_VERIFY = REPO / "circuits" / "target" / "release" / "pop-verify"
    sidecar = Path(str(args.proof) + ".verify.json") if args.proof else None
    if (args.proof is not None and args.proof.exists() and sidecar is not None
            and sidecar.exists() and POP_VERIFY.exists()):
        out = args.proof.parent / "verify_only.json"
        subprocess.run([str(POP_VERIFY), "--meta", str(sidecar), "--out", str(out)],
                       check=True, cwd=str(REPO))
        v = json.loads(out.read_text())
        b = payload["binding"]
        results.append(("verify_only", bool(v.get("verified")),
                        f"pop-verify ({v.get('proof_mode')}, no prover)"))
        results.append(("public_values", v.get("public_values_sha256") == b.get("public_values_sha256"),
                        "committed public values match"))
        results.append(("vkey_hash", v.get("vkey_hash") == b.get("vkey_hash"), "vkey matches"))
    elif args.proof is not None and args.proof.exists():
        out = args.proof.parent / "verify_out.json"
        subprocess.run([str(POP_SCRIPT), "--verify", "--proof", str(args.proof), "--out", str(out)],
                       env=dict(os.environ, SP1_PROVER="cpu"), check=True, cwd=str(REPO))
        v = json.loads(out.read_text())
        ok_verified = bool(v.get("verified"))
        outcome = v.get("outcome", {})
        outcome.pop("name", None)
        outcome.pop("mode", None)
        ok_outcome = outcome == payload["outcome"]
        ok_vkey = v.get("vkey_hash") == payload["binding"]["vkey_hash"]
        ok_sha = sha256_file(args.proof) == payload["binding"]["proof_sha256"]
        results.append(("proof_verify", ok_verified, "SP1 proof verified (pop-script)"))
        results.append(("proof_outcome", ok_outcome, "committed outcome == certificate"))
        results.append(("proof_vkey", ok_vkey, "vkey hash matches"))
        results.append(("proof_sha256", ok_sha, "proof artifact hash matches"))
    elif payload["binding"]["proof_sha256"] is None:
        results.append(("proof", True, "certificate is unproven (host-check only) — skipped"))
    else:
        results.append(("proof", False, "certificate claims a proof but --proof not given"))

    ok_all = all(r[1] for r in results)
    print(f"certificate: {args.cert}")
    print(f"policy={payload['policy']['id']}@{payload['policy']['version']} mode={payload['mode']} "
          f"passed={payload['outcome'].get('passed')} ts={payload['ts']}")
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:14s} {detail}")
    print("\nRESULT: " + ("PASS" if ok_all else "FAIL"))
    return 0 if ok_all else 1


def print_fail(results) -> None:
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:14s} {detail}")
    print("\nRESULT: FAIL")


if __name__ == "__main__":
    sys.exit(main())
