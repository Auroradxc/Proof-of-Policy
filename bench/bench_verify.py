#!/usr/bin/env python3
"""Measure verification cost for saved Proof-of-Policy proofs.

Two numbers, because they differ by orders of magnitude:
  - **cold CLI** (`--verify`, one shot): includes constructing the SP1 prover
    client (~10 GB inits) — this is what a naive script pays;
  - **pure verify** (`--verify-reps N`): vkey setup once, then N verifications —
    the cryptographic verifier cost a verifier-only binary would pay.

Usage:
  python3 bench/bench_verify.py --proof path/to/proof.bin [--runs 3] [--reps 5]
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--proof", type=Path, action="append", required=True)
    ap.add_argument("--runs", type=int, default=3, help="cold CLI samples")
    ap.add_argument("--reps", type=int, default=5, help="reps for pure verify")
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "verify.json")
    args = ap.parse_args()

    rows = []
    for proof in args.proof:
        cold = []
        for _ in range(args.runs):
            t0 = time.perf_counter()
            subprocess.run([str(POP_SCRIPT), "--verify", "--proof", str(proof),
                            "--out", str(proof.parent / "verify_out.json")],
                           cwd=str(REPO), check=True, capture_output=True, text=True,
                           env={**__import__("os").environ, "SP1_PROVER": "cpu"})
            cold.append(time.perf_counter() - t0)
        vj = proof.parent / "verify_reps.json"
        subprocess.run([str(POP_SCRIPT), "--verify", "--proof", str(proof),
                        "--verify-reps", str(args.reps), "--out", str(vj)],
                       cwd=str(REPO), check=True, capture_output=True, text=True,
                       env={**__import__("os").environ, "SP1_PROVER": "cpu"})
        data = json.loads(vj.read_text())
        row = {
            "proof": str(proof.relative_to(REPO)) if str(proof).startswith(str(REPO)) else str(proof),
            "cold_cli_median_s": round(statistics.median(cold), 3),
            "setup_s": round(data["setup_seconds"], 3),
            "verify_median_ms": round(statistics.median(data["verify_times_seconds"]) * 1000, 2),
            "verify_reps": args.reps,
        }
        rows.append(row)
        print(f"{row['proof']}: cold CLI {row['cold_cli_median_s']}s · "
              f"setup {row['setup_s']}s · pure verify {row['verify_median_ms']} ms "
              f"(n={args.reps})")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rows, indent=2))
    md = ["# Verification cost (`pop-script --verify`)", "",
          "| proof | cold CLI (s) | vkey setup (s) | pure verify (ms) |",
          "|---|---:|---:|---:|"]
    for r in rows:
        md.append(f"| {r['proof']} | {r['cold_cli_median_s']} | {r['setup_s']} | "
                  f"{r['verify_median_ms']} |")
    md += ["",
           "> `cold CLI` includes constructing the SP1 prover client (heavy); `pure verify` is",
           "> vkey-setup once + N verifications — what a verifier-only binary would pay.",
           "> A verifier-only path (no prover construction) is future work."]
    (args.out.with_suffix(".md")).write_text("\n".join(md) + "\n")
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

