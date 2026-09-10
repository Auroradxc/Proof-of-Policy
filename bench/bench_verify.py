#!/usr/bin/env python3
"""测量「验证已存盘的 Proof-of-Policy 证明」要花多少代价。

报两个数，因为两者差了几个数量级：
  - **cold CLI**（``--verify`` 单发）：包含构造 SP1 prover client 的开销
    （约 10 GB 初始化）——这是「图省事直接调 CLI」的真实代价；
  - **pure verify**（``--verify-reps N``）：vkey setup 只做一次，然后连验 N 次
    ——这才是纯验证器（不构造 prover）该付的密码学验证成本。

结果写到 ``bench/results/verify.json``，并在同目录生成 .md 表格。

用法：
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
    """对每个证明分别测 cold CLI 与 pure verify，取中位数后落盘。"""
    ap = argparse.ArgumentParser()
    ap.add_argument("--proof", type=Path, action="append", required=True)
    ap.add_argument("--runs", type=int, default=3, help="cold CLI samples")
    ap.add_argument("--reps", type=int, default=5, help="reps for pure verify")
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "verify.json")
    args = ap.parse_args()

    rows = []
    for proof in args.proof:
        # 每次都新起进程，才能把「构造 prover client」的成本算进去
        cold = []
        for _ in range(args.runs):
            t0 = time.perf_counter()
            subprocess.run([str(POP_SCRIPT), "--verify", "--proof", str(proof),
                            "--out", str(proof.parent / "verify_out.json")],
                           cwd=str(REPO), check=True, capture_output=True, text=True,
                           env={**__import__("os").environ, "SP1_PROVER": "cpu"})
            cold.append(time.perf_counter() - t0)
        # --verify-reps：setup 一次 + 连验 N 次，得到纯验证成本
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

