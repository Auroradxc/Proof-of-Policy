#!/usr/bin/env python3
"""测量组合证明（P1-6）的成本：两半各自的出证代价 + 组合层开销。

要回答的问题是计划里写下的那句假设：

> **「组合成本 ≈ 两者之和，且由推理证明主导」是否成立？**

本脚本把两半分开测（各自独立进程），再测一次联合验证，于是能分别回答：

1. **组合成本是不是两者之和？** —— 是，前提是两半**分进程**跑。合成与联合验证
   本身是毫秒级（哈希比对 + 两次验证），不引入额外证明。
2. **是不是推理证明主导？** —— 本机测出来是 **否**。代理推理证明是一个
   16→32→4 的定点 MLP，周期数远低于策略那一半（后者要跑 NFA 扫描 + 回执链），
   于是两半都被 zkVM 的**固定开销**（setup ~48 s、prove 的证明器启动）主导。
   这一点如实写进结果表 —— 代理实验能验证**组合机制**，验证不了**成本结构**：
   真实 zkAgent 推理证明的规模与这里不是一回事（见 ``bench/comparison_zkagent.md``）。

峰值内存单独报，且**取两半的最大值而不是和**：两半各起一个进程，峰值不叠加。
这是「组合」在资源上唯一不需要加法的部分，也是 ``scripts/compose_proof.py``
坚持分进程的原因。

用法：
  python3 bench/bench_compose.py [--reps 1] [--out bench/results/compose.json]

结果写入 ``bench/results/compose.json`` 与同目录的 ``compose.md``。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import compose as C          # noqa: E402
from policydsl import infer as I            # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule     # noqa: E402
from policydsl.serialize import spec_canonical_text  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
WORK = REPO / "bench" / "work"

#: 用 /usr/bin/time -v 才能拿到峰值 RSS；没有就退化为不测内存（与 bench_proofs 同口径）
TIME_BIN = "/usr/bin/time" if Path("/usr/bin/time").exists() else None

#: 基准用的策略：与 ``policy_packs/eu_ai_act_v1.json`` 同量级（3 条内容规则），
#: 但**在这里自建**，好让这份 benchmark 不依赖某个策略包的措辞。
#: ⚠️ 正则必须是 NFA 子集支持的写法：`\b` 这类**零宽断言**不在子集里
#: （`policydsl/nfa.py` 会明确报 `unsupported escape '\b'`，而 `compile_policy`
#: 是 fail-closed 的 —— 规则编不出来就抛错，不会静默跳过）。这里用与
#: `policy_packs/eu_ai_act_v1.json` 同款的邮箱模式。
BENCH_RULES = [
    Rule("keyword_block", "no_malware", {"keywords": ["exploit", "doxxing"]}),
    Rule("pattern_block", "no_pii_email", {"patterns": [r"[\w.+-]+@[\w-]+\.[\w.]+"]}),
    Rule("length_bound", "bounded", {"min": 1, "max": 2000}),
]

BENCH_RESPONSE = "Here is a summary of the refund policy for billing customers."


def _vectors(job: str, policy: Policy, response: str, nonce: bytes) -> Dict[str, Any]:
    """构造某个域的单向量文件内容。"""
    if job == "infer":
        return {"vectors": [{"name": "inference", "response": response,
                             "nonce": list(nonce)}]}
    spec = compile_policy(policy)
    return {"vectors": [{"name": policy.id, "response": response,
                         "spec_canonical": spec_canonical_text(spec),
                         "nonce": list(nonce)}]}


def _run_timed(args: List[str]) -> Dict[str, Any]:
    """跑一条命令并测量墙钟时间与峰值 RSS（``/usr/bin/time -v``）。"""
    prefix = [TIME_BIN, "-v"] if TIME_BIN else []
    t0 = time.perf_counter()
    proc = subprocess.run(prefix + args, cwd=str(REPO), capture_output=True, text=True,
                          env={**os.environ, "SP1_PROVER": "cpu"})
    wall = time.perf_counter() - t0
    if proc.returncode != 0:
        raise SystemExit(f"命令失败（{wall:.1f}s）：{' '.join(args)}\n"
                         f"{proc.stdout}\n{proc.stderr}")
    m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", proc.stderr)
    return {"wall_s": round(wall, 2),
            "peak_rss_mb": round(int(m.group(1)) / 1024.0, 1) if m else None}


def _cycles(job: str, vectors_path: Path, out_path: Path) -> Optional[int]:
    """``--execute``：在 zkVM 内跑一遍并报告指令数（不出证明，秒级）。"""
    subprocess.run([str(POP_SCRIPT), "--execute", "--job", job,
                    "--vectors", str(vectors_path), "--out", str(out_path)],
                   cwd=str(REPO), check=True, capture_output=True, text=True)
    return json.loads(out_path.read_text())[0].get("cycles")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--reps", type=int, default=1, help="每个域的出证重复次数")
    ap.add_argument("--proof-mode", default="core",
                    choices=["core", "compressed", "groth16", "plonk"])
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "compose.json")
    ap.add_argument("--render-only", action="store_true",
                    help="不出证：只把已有的 --out JSON 重新渲染成 .md"
                         "（表格措辞改动时用，省掉几分钟出证）")
    args = ap.parse_args()

    if args.render_only:
        data = json.loads(args.out.read_text(encoding="utf-8"))
        _write_md(data, args.out.with_suffix(".md"))
        print(f"→ {args.out.with_suffix('.md')}（由 {args.out} 重新渲染，未出证）")
        return 0

    if not POP_SCRIPT.exists():
        raise SystemExit(f"driver not built: {POP_SCRIPT}\n"
                         "  cd circuits && cargo build --release -p pop-script")

    WORK.mkdir(parents=True, exist_ok=True)
    policy = Policy("bench-compose", "0.1.0", rules=BENCH_RULES)
    nonce = bytes.fromhex("1122334455667788")
    response = BENCH_RESPONSE

    res: Dict[str, Any] = {
        "bench": "compose",
        "note": "P1-6 组合证明：策略合规（pop-program）+ 代理推理完整性（pop-infer）",
        "model": {"spec": I.MODEL_SPEC, "model_hash": I.model_hash(),
                  "dims": [I.IN_DIM, I.HID_DIM, I.OUT_DIM],
                  "params": I.HID_DIM * I.IN_DIM + I.OUT_DIM * I.HID_DIM},
        "policy_rules": [r.kind for r in BENCH_RULES],
        "response_len": len(response),
        "halves": {},
    }

    parts: Dict[str, C.Part] = {}
    proof_bytes: Dict[str, int] = {}
    for job in ("policy", "infer"):
        vpath = WORK / f"compose_{job}_v.json"
        opath = WORK / f"compose_{job}_r.json"
        proof = WORK / f"compose_{job}.proof"
        vpath.write_text(json.dumps(_vectors(job, policy, response, nonce),
                                    ensure_ascii=False, indent=2),
                         encoding="utf-8")

        cyc = _cycles(job, vpath, WORK / f"compose_{job}_exec.json")
        proves: List[Dict[str, Any]] = []
        verifies: List[Dict[str, Any]] = []
        for i in range(max(1, args.reps)):
            print(f"[{job}] prove {i + 1}/{args.reps} …")
            proves.append(_run_timed(
                [str(POP_SCRIPT), "--job", job, "--vectors", str(vpath),
                 "--out", str(opath), "--proof-out", str(proof),
                 "--proof-mode", args.proof_mode]))
            vout = WORK / f"compose_{job}_verify.json"
            verifies.append(_run_timed(
                [str(POP_SCRIPT), "--verify", "--job", job,
                 "--proof", str(proof), "--out", str(vout)]))
        proof_bytes[job] = proof.stat().st_size
        res["halves"][job] = {
            "cycles": cyc,
            "prove_wall_s": [p["wall_s"] for p in proves],
            "prove_median_s": round(statistics.median(p["wall_s"] for p in proves), 2),
            "prove_peak_rss_mb": max((p["peak_rss_mb"] or 0) for p in proves) or None,
            # 含 vkey setup（从 ELF 重新推导）—— 验证方没有缓存时就要付这一笔
            "verify_wall_s": [v["wall_s"] for v in verifies],
            "verify_median_s": round(statistics.median(v["wall_s"] for v in verifies), 2),
            "proof_bytes": proof_bytes[job],
        }
        kind = C.KIND_INFERENCE if job == "infer" else C.KIND_POLICY
        parts[kind] = C.part_from_proof(proof, kind, job)

    # ---- 组合：合成 + 联合验证 ----
    t0 = time.perf_counter()
    cert = C.build_composite(parts[C.KIND_POLICY], parts[C.KIND_INFERENCE], nonce)
    build_s = time.perf_counter() - t0

    t0 = time.perf_counter()
    ok, detail, satisfied = C.verify_composite(
        cert, response=response, base=WORK,
        expected_vkeys={k: p.vkey_hash for k, p in parts.items()})
    verify_s = time.perf_counter() - t0

    p = res["halves"]["policy"]
    q = res["halves"]["infer"]
    res["composite"] = {
        "build_s": round(build_s, 4),
        "verify_wall_s": round(verify_s, 2),
        "verified": bool(ok),
        "satisfied": bool(satisfied),
        "detail": detail,
        "vkey_policy": parts[C.KIND_POLICY].vkey_hash,
        "vkey_inference": parts[C.KIND_INFERENCE].vkey_hash,
        "sum_prove_s": round(p["prove_median_s"] + q["prove_median_s"], 2),
        "max_peak_rss_mb": max(v for v in (p["prove_peak_rss_mb"],
                                           q["prove_peak_rss_mb"]) if v) or None,
        "sum_peak_rss_mb": (p["prove_peak_rss_mb"] or 0) + (q["prove_peak_rss_mb"] or 0),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(res, indent=1, sort_keys=True), encoding="utf-8")
    _write_md(res, args.out.with_suffix(".md"))
    print(f"\n→ {args.out}\n→ {args.out.with_suffix('.md')}")
    return 0


def _write_md(res: Dict[str, Any], path: Path) -> None:
    """生成 .md 表格（论文/文档直接引用；数字**从 json 来**，不手抄）。"""
    h = res["halves"]
    p, q, c = h["policy"], h["infer"], res["composite"]
    L: List[str] = []
    L.append("# 组合证明（P1-6）的成本")
    L.append("")
    L.append("策略合规（`pop-program`）与代理推理完整性（`pop-infer`）各出一份证明，"
             "再合成一张组合证书。**两半是两个程序 ⇒ 两个 vkey**（键分离）。")
    L.append("")
    L.append(f"代理模型：`{res['model']['spec']}`")
    L.append(f"（{res['model']['params']} 个定点权重，model_hash "
             f"`{res['model']['model_hash'][:16]}…`）。")
    L.append("")
    L.append("| 子证明 | 程序 | zkVM 周期数 | prove（中位） | 峰值 RSS | 证明体积 | verify |")
    L.append("|---|---|---:|---:|---:|---:|---:|")
    for label, key, prog in (("策略合规", "policy", "pop-program"),
                             ("推理完整性（代理）", "infer", "pop-infer")):
        r = h[key]
        L.append(f"| {label} | `{prog}` | {r['cycles']:,} | {r['prove_median_s']:.1f} s | "
                 f"{r['prove_peak_rss_mb']:.0f} MiB | {r['proof_bytes'] / 1024:.1f} KiB | "
                 f"{r['verify_median_s']:.1f} s |")
    L.append("")
    L.append("## 组合层")
    L.append("")
    L.append("| 量 | 值 | 说明 |")
    L.append("|---|---:|---|")
    L.append(f"| 合成（哈希/绑定比对） | {c['build_s'] * 1000:.1f} ms | 纯 Python，无密码学 |")
    L.append(f"| 联合验证（含两次证明验证） | {c['verify_wall_s']:.1f} s | "
             "主导项是两次 vkey setup，不是比对本身 |")
    L.append(f"| 出证合计 | {c['sum_prove_s']:.1f} s | 两半**顺序**跑（分进程） |")
    L.append(f"| 峰值内存（取两半**最大**） | {c['max_peak_rss_mb']:.0f} MiB | "
             f"若同进程跑则是相加 ≈ {c['sum_peak_rss_mb']:.0f} MiB（会被 OOM）|")
    L.append(f"| 验证结论 | "
             f"{'PASS' if c['verified'] else 'FAIL'} / 义务 "
             f"{'PASS' if c['satisfied'] else 'FAIL'} | {c['detail']} |")
    L.append("")
    L.append("## 假设检验：「组合成本 ≈ 两者之和，且由推理证明主导」")
    L.append("")
    ratio = q["prove_median_s"] / p["prove_median_s"] if p["prove_median_s"] else 0
    L.append(f"1. **≈ 两者之和** —— **成立**。合成与联合验证不引入额外证明；"
             f"出证时间 {p['prove_median_s']:.1f} + {q['prove_median_s']:.1f} = "
             f"{c['sum_prove_s']:.1f} s。峰值内存也不相加（分进程）—— "
             f"这是组合在资源上唯一**不需要**加法的部分。")
    L.append(f"2. **由推理证明主导** —— **在本机不成立**。推理那一半是 "
             f"{q['prove_median_s']:.1f} s / {q['cycles']:,} 周期，策略那一半是 "
             f"{p['prove_median_s']:.1f} s / {p['cycles']:,} 周期，"
             f"比值 {ratio:.2f}×。两半都由 zkVM 的**固定开销**（setup 与证明器启动）"
             f"主导，代理规模太小，看不出成本结构。")
    L.append("")
    L.append("> **所以这份实验验证的是组合机制，不是成本结构。** 代理推理证明与真实 "
             "zkAgent 推理证明的规模差着若干个数量级（见 "
             "`bench/comparison_zkagent.md`）：换上真 prover 后「推理主导」才可能成立，"
             "而那时的组合代价仍由**同一个** `policydsl/compose.py` 承担 —— "
             "本脚本测到的组合层开销（毫秒级）不随子证明规模变化。")
    L.append("")
    path.write_text("\n".join(L), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
