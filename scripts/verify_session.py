#!/usr/bin/env python3
"""Independently verify a Proof-of-Policy end-to-end session bundle.

Given only public artefacts (session.json + ledger + optional proof), checks:
  1. the anchor ledger chain is intact (tamper-evident record-keeping);
  2. every certificate: DSSE signature valid + policy_hash recomputable from its
     policy pack + the certificate digest present in the ledger;
  3. streaming certificates form valid hash chains (per run);
  4. the zk-backed certificate's SP1 proof verifies cryptographically and its
     committed outcome / vkey hash / proof hash match the certificate.

Usage:
  python3 scripts/verify_session.py --session scripts/examples/out/e2e/session.json
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

from policydsl import anchor, cert  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.langchain_adapter import verify_chain  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402

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
    ap.add_argument("--session", type=Path, required=True)
    args = ap.parse_args()

    base = args.session.parent
    session = json.loads(args.session.read_text(encoding="utf-8"))
    ledger = base / session.get("ledger", "ledger.jsonl")
    entries = session["certificates"]
    results = []

    # 0) ledger chain
    ok_chain, reason = anchor.verify_ledger(ledger)
    results.append(("ledger_chain", ok_chain, reason))

    # policy hash cache
    spec_cache = {}
    def spec_for(pack: str):
        if pack not in spec_cache:
            spec_cache[pack] = compile_policy(load_policy(REPO / pack))
        return spec_cache[pack]

    # 1) per-certificate checks
    sig_ok = pol_ok = anch_ok = True
    kinds = {}
    for e in entries:
        env = e["envelope"]
        ok, payload = cert.verify_envelope(env, cert.DEMO_KEY)
        sig_ok &= ok
        if not ok or payload is None:
            pol_ok = anch_ok = False
            continue
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
        pol_ok &= payload["policy_hash"] == spec_for(e["policy_pack"])["sha256"]
        anch_ok &= anchor.find_anchor(ledger, cert.cert_digest(payload)) is not None
    results.append(("certificates_signature", sig_ok, f"{len(entries)} certs"))
    results.append(("certificates_policy_hash", pol_ok, f"{len(spec_cache)} pack(s)"))
    results.append(("certificates_anchored", anch_ok, "digest present in ledger"))

    # 2) streaming chains: split into runs at chain.index == 0
    groups, current = [], []
    for e in entries:
        if e["kind"] != "stream":
            continue
        payload = cert.envelope_payload(e["envelope"])
        chain = (payload.get("streaming") or {}).get("chain") or {}
        if chain.get("index") == 0 and current:
            groups.append(current); current = []
        current.append(e["envelope"])
    if current:
        groups.append(current)
    chain_ok = all(verify_chain(g) for g in groups) if groups else True
    results.append(("stream_chains", chain_ok, f"{len(groups)} run(s)"))

    # 3) zk proof
    zk_entries = [e for e in entries if e["kind"] == "zk"]
    zk_ok = True
    detail = "n/a"
    for e in zk_entries:
        payload = cert.envelope_payload(e["envelope"])
        proof_rel = e.get("proof")
        if proof_rel:
            proof = base / proof_rel
            out = base / "verify_out.json"
            subprocess.run([str(POP_SCRIPT), "--verify", "--proof", str(proof), "--out", str(out)],
                           env=dict(os.environ, SP1_PROVER="cpu"), check=True, cwd=str(REPO))
            v = json.loads(out.read_text())
            outcome = v.get("outcome", {})
            outcome.pop("name", None); outcome.pop("mode", None)
            zk_ok &= bool(v.get("verified"))
            zk_ok &= outcome == payload["outcome"]
            zk_ok &= v.get("vkey_hash") == payload["binding"]["vkey_hash"]
            zk_ok &= sha256_file(proof) == payload["binding"]["proof_sha256"]
            detail = "SP1 proof verified (outcome/vkey/hash)"
        else:
            zk_ok &= payload["binding"]["proof_sha256"] is None
            detail = "unproven (host-check only)"
    results.append(("zk_proof", zk_ok, detail))

    ok_all = all(r[1] for r in results)
    print(f"session: {args.session}")
    print(f"certificates by kind: {kinds}")
    for name, ok, det in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:24s} {det}")
    print("\nRESULT: " + ("PASS" if ok_all else "FAIL"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
