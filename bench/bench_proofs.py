#!/usr/bin/env python3
"""Proof-of-Policy 的证明耗时与体积曲线（真实 SP1 证明）。

只在少数几个 (长度, 规则数) 采样点上：生成一次真实证明 → 量墙钟耗时、证明产物
大小与峰值内存 → 再验证一次。每条点都很贵（分钟级、数 GB 内存），所以样本极少；
需要铺很多点的 cycle 数扫描见 ``bench_cycles.py``。

结果写到 ``bench/results/proofs.json``，同时在同目录生成一份 .md 表格。

用法：
  SP1_PROVER=cpu python3 bench/bench_proofs.py [--out bench/results/proofs.json]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

# 用 /usr/bin/time -v 才能拿到峰值 RSS；没有就退化为不测内存
TIME_BIN = "/usr/bin/time" if Path("/usr/bin/time").exists() else None

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "bench"))

import bench_cycles as bc  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.serialize import spec_canonical_text  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
WORK = REPO / "bench" / "work"

# 采样点刻意很少：每点都要真出一次证明（分钟级 + 大内存），跑多了不现实
POINTS = [(200, 3), (200, 6), (1_000, 1)]


def main() -> int:
    """逐点出证明、量耗时/体积/内存并验证，最后落盘 JSON + Markdown。"""
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "proofs.json")
    args = ap.parse_args()

    WORK.mkdir(parents=True, exist_ok=True)
    rows = []
    for length, rc in POINTS:
        policy = bc.make_policy(rc, "pike")
        spec = compile_policy(policy)
        text = bc.response("the quick brown fox jumps", length)
        vp = WORK / "pv.json"
        op = WORK / "pr.json"
        proof = WORK / "proof.bin"
        vp.write_text(json.dumps({"vectors": [{
            "name": f"L{length}-R{rc}", "response": text,
            "spec_canonical": spec_canonical_text(spec)}]}))

        # 计时区间只包住出证这一条命令
        t0 = time.perf_counter()
        prefix = [TIME_BIN, "-v"] if TIME_BIN else []
        res = subprocess.run(prefix + [str(POP_SCRIPT), "--vectors", str(vp), "--out", str(op),
                                       "--proof-out", str(proof)],
                             cwd=str(REPO), check=True, capture_output=True, text=True,
                             env={**__import__("os").environ, "SP1_PROVER": "cpu"})
        # SP1_PROVER=cpu：本机无 GPU，固定 CPU 路径保证数字可复现/可比
        secs = time.perf_counter() - t0
        m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", res.stderr)
        peak_mb = round(int(m.group(1)) / 1024.0, 1) if m else None
        size = proof.stat().st_size

        # 顺手验一次，确认证明本身有效（否则耗时的数字没意义）
        vout = WORK / "verify.json"
        subprocess.run([str(POP_SCRIPT), "--verify", "--proof", str(proof), "--out", str(vout)],
                       cwd=str(REPO), check=True, capture_output=True, text=True,
                       env={**__import__("os").environ, "SP1_PROVER": "cpu"})
        verified = json.loads(vout.read_text()).get("verified")

        rows.append({"length": length, "rules": rc, "seconds": round(secs, 2),
                     "proof_bytes": size, "peak_rss_mb": peak_mb,
                     "verified": bool(verified)})
        print(f"L={length:>6} rules={rc}  {secs:6.1f}s  {size/1024:8.1f} KiB  "
              f"peakRSS={peak_mb} MB  verified={verified}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rows, indent=2))
    md = ["# Real SP1 proofs: wall time, artifact size, peak memory", "",
          "| length | rules | time (s) | proof (KiB) | peak RSS (MiB) | verified |",
          "|---:|---:|---:|---:|---:|:--|"]
    for r in rows:
        md.append(f"| {r['length']} | {r['rules']} | {r['seconds']} | "
                  f"{r['proof_bytes']/1024:.1f} | {r['peak_rss_mb']} | "
                  f"{'yes' if r['verified'] else 'NO'} |")
    (args.out.with_suffix(".md")).write_text("\n".join(md) + "\n")
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
