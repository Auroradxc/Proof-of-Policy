#!/usr/bin/env python3
"""Phase 5: issue a compliance certificate for a response, then anchor it.

Pipeline:
  pack + response --(public: SP1 proof / private: commitment proof)--> public values
  public values + policy_hash + vkey_hash + ts --(DSSE sign)--> cert.json
  cert digest --> anchor ledger (append-only, tamper-evident)

Usage:
  SP1_PROVER=cpu python3 scripts/issue_cert.py \
      --pack policy_packs/eu_ai_act_v1.json \
      --response scripts/examples/eu_agent_reply.txt \
      --out-dir scripts/examples/out/cert_public [--mode public|private] [--no-prove]
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

from policydsl import anchor, cert, commit
from policydsl.compile import compile_policy
from policydsl.model import Policy, Rule
from policydsl.serialize import spec_to_rust_constraints

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"


def load_policy(path: Path) -> Policy:
    d = json.loads(path.read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r.get("name", f"r{i}"), params=r.get("params", {}))
             for i, r in enumerate(d["rules"])]
    return Policy(d["id"], d.get("version", "0.1.0"), rules=rules)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_pop(args: list[str]) -> None:
    subprocess.run([str(POP_SCRIPT), *args], env=dict(os.environ, SP1_PROVER="cpu"),
                   check=True, cwd=str(REPO))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", type=Path, required=True)
    ap.add_argument("--response", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--mode", choices=["public", "private"], default="public")
    ap.add_argument("--proof-mode", choices=["core", "compressed", "groth16", "plonk"],
                    default="core", help="core (fast, default) or compressed for verifier-only audit")
    ap.add_argument("--ledger", type=Path, default=REPO / "scripts" / "examples" / "out" / "ledger.jsonl")
    ap.add_argument("--no-prove", action="store_true", help="host-check only (no SP1 proof)")
    args = ap.parse_args()

    policy = load_policy(args.pack)
    response = args.response.read_text(encoding="utf-8")
    spec = compile_policy(policy)
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    vector = {"name": policy.id, "response": response,
              "constraints": spec_to_rust_constraints(spec)}
    if args.mode == "private":
        patterns = [p for c in spec["constraints"] if c["kind"] == "pattern_block"
                    for p in c["patterns"]]
        mask = commit.mask_from_patterns(patterns, response) if patterns else []
        spans = commit.spec_spans(spec, response) if patterns else []
        vector.update({"private": True, "mask": mask,
                       "redacted": commit.redact(response, mask), "spans": spans})

    vectors = out_dir / "vectors.json"
    vectors.write_text(json.dumps({"vectors": [vector]}, indent=2))
    results = out_dir / "results.json"
    proof = out_dir / "proof.bin"

    if args.no_prove:
        run_pop(["--check", "--vectors", str(vectors), "--out", str(results)])
        vkey_hash = "unproven"
        proof_sha = None
        pv_sha = None
    else:
        cmd = ["--vectors", str(vectors), "--out", str(results), "--proof-out", str(proof)]
        if args.proof_mode != "core":
            cmd += ["--proof-mode", args.proof_mode]
        run_pop(cmd)
        meta = json.loads(Path(f"{proof}.meta.json").read_text())
        vkey_hash = meta["vkey_hash"]
        proof_sha = sha256_file(proof)
        pv_file = Path(f"{proof}.pv")
        pv_sha = sha256_file(pv_file) if pv_file.exists() else None

    got = json.loads(results.read_text())[0]
    outcome = {k: v for k, v in got.items() if k not in ("name", "mode")}
    payload = cert.build_payload(policy.id, policy.version, spec, args.mode, outcome,
                                 vkey_hash, proof_sha, public_values_sha256=pv_sha)
    env = cert.sign_payload(payload, cert.DEMO_KEY)
    (out_dir / "cert.json").write_text(json.dumps(env, indent=2))
    (out_dir / "payload.json").write_text(json.dumps(payload, indent=2))

    digest = cert.cert_digest(payload)
    entry = anchor.append_anchor(args.ledger, digest,
                                 {"policy": policy.id, "mode": args.mode, "proved": not args.no_prove})
    (out_dir / "anchor.json").write_text(json.dumps(entry, indent=2))

    print(f"policy_hash : {spec['sha256']}")
    print(f"vkey_hash   : {vkey_hash}")
    print(f"passed      : {outcome['passed']}")
    print(f"cert_digest : {digest}")
    print(f"anchor      : seq={entry['seq']} hash={entry['hash'][:16]}… ledger={args.ledger}")
    print(f"wrote       : {out_dir}/cert.json, payload.json, results.json" +
          ("" if args.no_prove else f", {proof.name}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
