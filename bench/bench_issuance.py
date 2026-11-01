#!/usr/bin/env python3
"""P1-13 签发完整性：不可能性 + 透明日志 + 抽样审计的检出概率。

本脚本把定理 F 的三件事变成可跑的数字：

* **F1（不可能性）**：运营方对违规交付**不签发**证书、也不追加日志。审计者若
  只抽「日志」，样本里根本没有这条违规 —— 检出率为 **0**。这不是实现缺陷，
  是「不行动」的对手就赢了。
* **F2（条件充分性）**：运营方在交付前把证书摘要追加到只追加日志，日志条目
  绑定被交付的 ``T``，验证者查包含证明。本脚本用
  :mod:`policydsl.evidence.transparency` 跑一个真实的小日志。
* **F3（抽样检出）**：从 **N 个交付**中无放回抽 ``s`` 个，违规 ``m`` 个：
  精确式 ``1 - C(N-m,s)/C(N,s)``；独立/有放回近似 ``1-(1-p)^m``，``p=s/N``。
  同时给 Monte Carlo 实测，检验两式。

**四个前提必须跟着数字一起读**（``docs/proofs/theorem-c-e-f.md`` §3.4、§3.7）：

1. **F-1**：没有外部义务 F-O（交付前必须追加），F2 不成立；本脚本只做机制演示。
2. **F-3**：日志条目必须绑定**被交付的** ``T``（回执/``B(n,T)``/``H(T)``）。只记
   ``H(cert)`` 时，运营方可以记一张「另一条 ``T``」的证书；本脚本用
   :func:`transparency.entry_hash` 的 ``binding`` 演示绑定前后差别。
3. **F-4**：抽样框必须是**交付**，不能是**日志**；只抽日志时 withholding 检出率 0。
4. **F-2（split-view）**：恶意日志可对不同审计者给不同视图；本脚本**不**实现
   gossip/一致性证明，因此「只追加」只在单一视图内成立。

另外如实标注：**检出 ≠ 阻止**（F-5）；独立性是模型假设，同源违规会让
``1-(1-p)^m`` 高估（F-4 的第 2 条）。

结果写到 ``bench/results/issuance.json`` 与同目录 ``.md``（``.md`` 是 JSON 的纯渲染，
``--render-only`` 可重新生成）。

用法：
  python3 bench/bench_issuance.py
  python3 bench/bench_issuance.py --deliveries 2000 --trials 500
  python3 bench/bench_issuance.py --render-only
"""

from __future__ import annotations

import argparse
import json
import math
import platform
import random
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "bench"))

import bench_proofs as bp  # noqa: E402
from policydsl.evidence import cert, transparency as T  # noqa: E402
from policydsl.privacy import commit  # noqa: E402

DEFAULT_N = 2000
DEFAULT_TRIALS = 500
DEFAULT_SEED = 20261101
P_GRID = (0.01, 0.02, 0.05, 0.10, 0.20)
M_GRID = (1, 10, 50, 100, 500)
CURVE_P = (0.01, 0.05, 0.10)
CURVE_M = (1, 2, 5, 10, 20, 50, 100, 200, 500)


# --------------------------------------------------------------------------- #
# 检出概率：精确式与近似
# --------------------------------------------------------------------------- #

def hypergeom_detect(n: int, m: int, s: int) -> float:
    """无放回：``1 - C(N-m,s)/C(N,s)``（精确）。

    ``N`` 个交付里 ``m`` 个违规，抽 ``s`` 个；一个都没抽到违规的概率是
    ``C(N-m,s)/C(N,s)``。边界：``s=0`` → 0；``N-m < s`` → 1（鸽巢）。
    """
    if s <= 0 or m <= 0:
        return 0.0
    if m >= n:
        return 1.0
    if n - m < s:
        return 1.0
    return 1.0 - math.comb(n - m, s) / math.comb(n, s)


def independent_detect(m: int, p: float) -> float:
    """独立/有放回：``1-(1-p)^m``。``p`` 用实际抽样比例 ``s/N`` 以可比。"""
    if m <= 0 or p <= 0:
        return 0.0
    if p >= 1:
        return 1.0
    return 1.0 - (1.0 - p) ** m


def monte_carlo_detect(n: int, m: int, s: int, trials: int, seed: int) -> float:
    """从 **交付** 框无放回抽样，命中任一违规即检出。

    违规位置固定为 ``0..m-1``；抽样位置在 ``0..N-1`` 上均匀 —— 位置本身不
    影响概率，固定它们只是为了让结果可复现。
    """
    if m <= 0 or s <= 0:
        return 0.0
    rng = random.Random(seed)
    violations = set(range(m))
    hits = 0
    for _ in range(trials):
        sample = rng.sample(range(n), min(s, n))
        if violations.intersection(sample):
            hits += 1
    return hits / trials


# --------------------------------------------------------------------------- #
# 模拟运营方：对违规交付不签发 / 不追加
# --------------------------------------------------------------------------- #

def simulate_operator(n: int, m: int) -> dict:
    """``m`` 条违规交付：运营方**不签发**、**不追加日志**；其余正常签发。

    返回交付视图（每条是否被签发）与日志视图（只含被签发的条目）。这是
    F1 的 withholding 对手：它不攻破任何哈希/签名，只是「不行动」。
    """
    log = T.TransparencyLog()
    delivered = []
    for i in range(n):
        is_violation = i < m
        digest = cert.sha256_hex(f"cert-{i}".encode())
        appended_index = None
        if not is_violation:
            appended_index = log.append(digest, binding=cert.sha256_hex(f"T-{i}".encode()))
        delivered.append({
            "id": i,
            "violation": is_violation,
            "cert_digest": None if is_violation else digest,
            "log_index": appended_index,
        })
    return {
        "delivered": delivered,
        "log": log,
        "delivered_count": n,
        "violations": m,
        "log_size": log.size,
        "log_root": log.root() if log.size else None,
    }


def audit_frames(n: int, m: int, p: float, trials: int, seed: int) -> dict:
    """同一审计率下，**交付框**与**日志框**的检出率对照（F-4 的机器演示）。"""
    s = max(1, round(p * n))
    sim = simulate_operator(n, m)
    delivered = sim["delivered"]
    log_entries = [d for d in delivered if d["log_index"] is not None]

    rng = random.Random(seed)
    delivery_hits = 0
    log_hits = 0
    # 日志框：抽日志条目，看它是否指向违规 —— withholding 的条目根本不在日志里，
    # 所以命中率恒为 0。这里仍实抽，是为了让「0」是跑出来的，不是写死的。
    for _ in range(trials):
        sample = rng.sample(delivered, s)
        if any(d["violation"] for d in sample):
            delivery_hits += 1
        if log_entries:
            log_sample = rng.sample(log_entries, min(s, len(log_entries)))
            if any(d["violation"] for d in log_sample):
                log_hits += 1
    return {
        "p": p,
        "s": s,
        "violations": m,
        "delivery_frame_mc": delivery_hits / trials,
        "log_frame_mc": log_hits / trials,
        "delivery_frame_exact": hypergeom_detect(n, m, s),
        "log_frame_exact": 0.0,
        "log_size": sim["log_size"],
        "log_root": sim["log_root"],
        "delivered_count": sim["delivered_count"],
        "trials": trials,
        "why_log_frame_is_zero": ("withholding 的交付没有日志条目，日志框样本里没有它；"
                                  "这不是抽样运气，是样本框错了（F-4）"),
    }


# --------------------------------------------------------------------------- #
# F-3：日志条目绑定被交付的 T
# --------------------------------------------------------------------------- #

def binding_demo() -> dict:
    """同一张证书、两件交付物：不绑定时日志「看起来没问题」，绑定时露馅。

    构造：运营方为 ``T0`` 出证并把摘要追加进日志；实际交付 ``T1``（违规），
    却把 ``T0`` 的日志条目/证明一起给验证者。

    * 不绑定（默认叶 = ``cert_digest``）：``verify_inclusion(cert_digest, proof)``
      通过，且**没有**任何字段能区分交付的是 ``T0`` 还是 ``T1`` —— 日志只说
      「这张证书存在」，不说「它是为 ``T1`` 的」；
    * 绑定（叶 = ``H(domain‖d‖B(n,T))``）：用 ``T1`` 的绑定重算叶，包含证明失败；
      只有 ``T0`` 的绑定能通过。
    """
    nonce = b"delivery-binding-demo"
    t0 = "The assistant did not disclose any personal data."
    t1 = "The assistant disclosed the customer's personal data."
    b0 = commit.response_binding(nonce, t0)
    b1 = commit.response_binding(nonce, t1)
    cert_digest = cert.sha256_hex(b"canonical certificate for T0")

    unbound = T.TransparencyLog()
    iu = unbound.append(cert_digest)
    proof_unbound = unbound.prove(iu)

    bound = T.TransparencyLog()
    ib = bound.append(cert_digest, binding=b0)
    proof_bound = bound.prove(ib)

    return {
        "cert_digest": cert_digest,
        "binding_T0": b0,
        "binding_T1": b1,
        "unbound": {
            "verifies_without_binding": bool(
                T.verify_inclusion(cert_digest, proof_unbound)),
            "leaf_equals_cert_digest": proof_unbound["leaf"] == cert_digest,
            "would_mismatch_if_T1_were_bound": (
                T.entry_hash(cert_digest, b1) != proof_unbound["leaf"]),
            "note": ("日志只承诺证书摘要；没有字段能区分交付的 T，"
                     "所以 T0/T1 都能「通过」（F-3 的缺口）"),
        },
        "bound": {
            "verifies_with_T0_binding": bool(
                T.verify_inclusion(cert_digest, proof_bound, binding=b0)),
            "verifies_with_T1_binding": bool(
                T.verify_inclusion(cert_digest, proof_bound, binding=b1)),
            "note": "叶子里含 B(n,T)；换成 T1 重算就对不上",
        },
    }


# --------------------------------------------------------------------------- #
# 主表 / 曲线
# --------------------------------------------------------------------------- #

def detection_table(n: int, trials: int, seed: int) -> list[dict]:
    rows = []
    for p in P_GRID:
        s = max(1, round(p * n))
        for m in M_GRID:
            if m > n:
                continue
            exact = hypergeom_detect(n, m, s)
            approx = independent_detect(m, s / n)
            mc = monte_carlo_detect(n, m, s, trials, seed)
            rows.append({
                "p": p,
                "s": s,
                "m": m,
                "exact_hypergeom": round(exact, 6),
                "independent_approx": round(approx, 6),
                "monte_carlo": round(mc, 6),
                "abs_error_exact_vs_mc": round(abs(exact - mc), 6),
                "abs_error_approx_vs_exact": round(abs(approx - exact), 6),
            })
    return rows


def detection_curve(n: int) -> dict:
    """固定 p、扫 m 的检出概率（精确式），供 .md 画 ASCII 曲线。"""
    out = {}
    for p in CURVE_P:
        s = max(1, round(p * n))
        out[str(p)] = [{"m": m, "detect": round(hypergeom_detect(n, m, s), 6)}
                       for m in CURVE_M if m <= n]
    return out


def m_for_confidence(p: float, delta: float = 0.01) -> int:
    """独立模型下达到 ``1-delta`` 检出所需的违规数：``m ≥ ln(δ)/ln(1-p)``。"""
    if p <= 0:
        return 0
    if p >= 1:
        return 1
    return math.ceil(math.log(delta) / math.log(1 - p))


# --------------------------------------------------------------------------- #
# 渲染
# --------------------------------------------------------------------------- #

def bar(x: float, width: int = 32) -> str:
    """把 [0,1] 的概率画成定宽条（ASCII），用于「曲线」。"""
    filled = int(round(max(0.0, min(1.0, x)) * width))
    return "█" * filled + "·" * (width - filled)


def render_md(data: dict) -> str:
    h = data.get("host") or {}
    m = data["model"]
    md = ["# 签发完整性：不可能性、透明日志与抽样检出（P1-13）", "",
          f"**量测机器**：{h.get('cpu_count')} 核 `{h.get('cpu_model') or '未知型号'}`，"
          f"内存 {(h.get('mem_total_mb') or 0)/1024:.1f} GiB"
          f"（`{h.get('hostname')}`，{h.get('platform')}）；Python {h.get('python')}。", "",
          "> **结论先行**：密码学层单独**不能**强制签发（F1）；在「交付前追加 + 只追加日志 + "
          "验证者查包含」的外部义务下，D7 对**被交付且被接受**的工件成立（F2）；"
          "抽样审计的检出率是 `1-(1-p)^m`（独立模型）或 "
          "`1 - C(N-m,s)/C(N,s)`（无放回精确式），但**样本框必须是交付，不能是日志**（F3/F-4）。", "",
          "## 模型", "",
          f"- 交付数 `N = {m['deliveries']}`，违规数 `m` 取 {m['m_grid']}；"
          f"抽样率 `p` 取 {m['p_grid']}；`s = round(pN)`（至少 1）。",
          f"- Monte Carlo：{m['trials']} 次/格，固定种子 `{m['seed']}`；违规位置固定为前 `m` 个。",
          "- 精确式 `1 - C(N-m,s)/C(N,s)`；近似式 `1-(1-p)^m`，其中 `p=s/N`。", "",
          "## F1：不可能性（不行动就赢）", "",
          f"运营方对前 `{data['f1']['violations']}` 条违规交付**不签发、不追加**；其余 "
          f"`{data['f1']['delivered_count'] - data['f1']['violations']}` 条正常签发。"
          f"日志最终 {data['f1']['log_size']} 条，根 "
          f"`{str(data['f1']['log_root'])[:16]}…`。", "",
          "| 抽样框 | 审计率 p | 抽 s | 检出率（精确） | 检出率（Monte Carlo） |",
          "|---|---:|---:|---:|---:|",
          f"| **交付**（正确框） | {data['f1']['p']:.2f} | {data['f1']['s']} | "
          f"{data['f1']['delivery_frame_exact']:.4f} | {data['f1']['delivery_frame_mc']:.4f} |",
          f"| **日志**（错误框） | {data['f1']['p']:.2f} | {data['f1']['s']} | "
          f"{data['f1']['log_frame_exact']:.4f} | {data['f1']['log_frame_mc']:.4f} |",
          "",
          f"> {data['f1']['why_log_frame_is_zero']}。这就是 F1 的形态："
          "「什么都不做」不需要攻破任何密码学假设。", "",
          "## F3：检出概率表（无放回精确式 vs 独立近似 vs Monte Carlo）", "",
          "| p | s | m | 精确 `1-C(N-m,s)/C(N,s)` | 独立 `1-(1-p)^m` | Monte Carlo | 精确 vs MC 绝对差 |",
          "|---:|---:|---:|---:|---:|---:|---:|"]
    for r in data["table"]:
        md.append(f"| {r['p']:.2f} | {r['s']} | {r['m']} | {r['exact_hypergeom']:.6f} | "
                  f"{r['independent_approx']:.6f} | {r['monte_carlo']:.6f} | "
                  f"{r['abs_error_exact_vs_mc']:.6f} |")
    md += ["", "两式在 `N ≫ m,s` 时接近；表里小 `N` 的差异是**正确**的，不是 bug。"
           "Monte Carlo 与精确式的差在抽样噪声内（每格 "
           f"{m['trials']} 次）。", "",
           "## 检出曲线（精确式，固定 p 扫 m）", ""]
    for p, pts in data["curve"].items():
        md += [f"**p = {float(p):.2f}**", "", "```"]
        for pt in pts:
            md.append(f"m={pt['m']:>4}  {pt['detect']:.4f}  {bar(pt['detect'])}")
        md += ["```", ""]

    md += ["### 达到 99% 检出所需的违规数（独立模型）", "",
           "| p | m（`ln(0.01)/ln(1-p)` 上取整） |", "|---:|---:|"]
    for p in P_GRID:
        md.append(f"| {p:.2f} | {m_for_confidence(p)} |")
    md += ["", "## F-3：日志条目不绑定交付物会怎样", "",
           "同一张证书摘要，先为 `T0` 追加，再把 `T1`（违规）交付出去：", "",
           "| 构造 | 无绑定验证 | 用 T0 的绑定验证 | 用 T1 的绑定验证 | 说明 |",
           "|---|---:|---:|---:|---|",
           f"| 默认叶（只记 `cert_digest`） | "
           f"{'✅' if data['binding']['unbound']['verifies_without_binding'] else '❌'} | "
           f"— | — | {data['binding']['unbound']['note']} |",
           f"| 绑定叶（`H(domain‖d‖B(n,T))`） | — | "
           f"{'✅' if data['binding']['bound']['verifies_with_T0_binding'] else '❌'} | "
           f"{'❌' if not data['binding']['bound']['verifies_with_T1_binding'] else '✅'} | "
           f"{data['binding']['bound']['note']} |",
           "", "默认叶那一行在**任何** T 下都通过：它的叶子里根本没有 T 的位置"
           f"（`leaf == cert_digest`：{'是' if data['binding']['unbound']['leaf_equals_cert_digest'] else '否'}）。"
           "这就是 F-3 说的「记的是另一条 T 的证书」——日志本身看不出来。", "", "## 实验前提（缺一条，上面的数字就不能这么读）", ""]
    for a in data["assumptions"]:
        md.append(f"- **{a['id']}**：{a['text']}")
    md += ["", "> **不可过度声明**：本脚本只量化**检出**，不建模**阻止**（罚则/经济激励，F-5）；"
           "违规同源时 `m` 不是独立事件数，独立模型会**高估**检出率（F-4 第 2 条）；"
           "日志的可用性与 split-view 不在本原型内（F-2/F-6）。", ""]
    return "\n".join(md) + "\n"


def dump(out_path: Path, data: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    out_path.with_suffix(".md").write_text(render_md(data), encoding="utf-8")


ASSUMPTIONS = [
    {"id": "F-1（外部义务）",
     "text": "F2 的充分性依赖 F-O：运营方**在交付前必须**追加日志。这不是密码学结论；"
             "没有它，F1 适用。本脚本演示机制，不提供强制力。"},
    {"id": "F-3（绑定被交付的 T）",
     "text": "日志条目必须绑定被交付的 `T`（`B(n,T)` / `H(T)` / 交付回执）。"
             "只记 `cert_digest` 时，运营方可记一张「另一条 T」的证书；见上面的绑定对照。"},
    {"id": "F-4（抽样框 = 交付）",
     "text": "样本必须从**被交付的工件**里抽，不能只抽日志；"
             "只抽日志时 withholding 检出率恒为 0。独立性/命中即检出也是模型假设。"},
    {"id": "F-2（split-view）",
     "text": "只追加只是对**单一视图**的承诺。恶意日志可给不同审计者不同树头；"
             "需要 gossip/一致性证明/监控。A10 已给一致性证明与 gossip 消息格式/验证，"
             "但仍不实现真实网络 gossip/跨审计者视图比较，故 F-2 仍是外部假设。"},
    {"id": "F-4 第 2 条（同源违规）",
     "text": "`m` 必须是**独立可检事件数**；一个根因导致一批违规时，"
             "`1-(1-p)^m` 会高估检出率。本脚本的 Monte Carlo 按独立位置抽样。"},
    {"id": "F-5（检出 ≠ 阻止）",
     "text": "本脚本只算「被发现」的概率，不算「被阻止」；后者取决于罚则与激励。"},
    {"id": "F-6（日志可用性）",
     "text": "验证者查包含证明要求日志可用；本原型在内存里，未建模不可用/延迟。"},
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--deliveries", type=int, default=DEFAULT_N,
                    help=f"交付数 N（默认 {DEFAULT_N}）")
    ap.add_argument("--trials", type=int, default=DEFAULT_TRIALS,
                    help=f"Monte Carlo 次数（默认 {DEFAULT_TRIALS}）")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--out", type=Path,
                    default=REPO / "bench" / "results" / "issuance.json")
    ap.add_argument("--render-only", action="store_true")
    args = ap.parse_args()

    if args.render_only:
        data = json.loads(args.out.read_text(encoding="utf-8"))
        args.out.with_suffix(".md").write_text(render_md(data), encoding="utf-8")
        print(f"→ {args.out.with_suffix('.md')}（由 {args.out} 重新渲染，未重采数据）")
        return 0

    n = args.deliveries
    if n < max(M_GRID):
        raise SystemExit(f"N={n} 小于最大 m={max(M_GRID)}；请调大 --deliveries 或调小网格")

    h = bp.host_info()
    host = {**h, "python": platform.python_version(), "os": platform.platform()}
    print(f"host={host['hostname']}  {host['cpu_count']} 核  "
          f"{host['mem_total_mb']/1024:.1f} GiB  Python {host['python']}")

    print("F-1 演示：withholding 对手，交付框 vs 日志框 …")
    f1 = audit_frames(n, 100, 0.05, args.trials, args.seed)
    print(f"  交付框 {f1['delivery_frame_exact']:.4f} vs 日志框 {f1['log_frame_exact']:.4f}")

    print("F-3 检出表 + Monte Carlo …")
    table = detection_table(n, args.trials, args.seed)
    curve = detection_curve(n)
    print(f"  {len(table)} 格")

    binding = binding_demo()
    if not (binding["bound"]["verifies_with_T0_binding"]
            and not binding["bound"]["verifies_with_T1_binding"]):
        raise SystemExit("绑定演示没有按预期失败/通过 —— 结论不成立")
    if not (binding["unbound"]["verifies_without_binding"]
            and binding["unbound"]["leaf_equals_cert_digest"]
            and binding["unbound"]["would_mismatch_if_T1_were_bound"]):
        raise SystemExit("不绑定叶的演示前提不成立 —— 构造有误")

    data = {
        "arm": "issuance-transparency",
        "host": host,
        "model": {
            "deliveries": n,
            "p_grid": list(P_GRID),
            "m_grid": list(M_GRID),
            "trials": args.trials,
            "seed": args.seed,
            "exact_formula": "1 - C(N-m,s)/C(N,s)",
            "independent_formula": "1 - (1-p)^m, p=s/N",
        },
        "f1": f1,
        "table": table,
        "curve": curve,
        "m_for_99pct": {f"{p:.2f}": m_for_confidence(p) for p in P_GRID},
        "binding": binding,
        "assumptions": ASSUMPTIONS,
        "notes": [
            "F1 不可能性、F3 检出表/曲线、F2 的透明日志原型均在本仓库可复现。",
            "只量化检出，不量化阻止（F-5）。",
            "不实现 split-view 防护（F-2）。",
        ],
    }
    dump(args.out, data)
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
