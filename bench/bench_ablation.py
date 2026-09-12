#!/usr/bin/env python3
"""匹配器消融：NFA(pike) vs 朴素回溯(naive) 在病理输入下的退化。

**要证的命题**：策略匹配里那一步「每个起点重新锚定跑一遍 NFA」的朴素实现是
``O(n²)``，会被对抗输入拖垮；pike 的线性扫描不会。这不是细节 —— 策略合规的
输入长度由**外部**决定（agent 回复、拼接会话），对手可以挑一段全是 ``a`` 的
回复，成本就成了攻击面。

**构造口径**（与 ``docs/dev-plan.md`` / ``docs/quadrant.md`` 记的一致，这里把它
固化成可复跑的脚本）：模式用 ``a+b``（不是 email —— email 上朴素实现的退化
更快被字符集失活截断，信噪比差），输入是 ``"a" * n``。模式要求 ``a+`` 后面跟
一个 ``b``，而整段输入没有 ``b``：朴素实现从每个起点吃掉整条 ``a`` 串、再在结尾
失败回溯，合计 ``Θ(n²)``；pike 一次线性扫描即判定不匹配。

不出证（走 ``pop-script --execute``），所以每个点只要几秒 —— 与 ``bench_cycles.py``
同一套执行路径，周期数可直接与那张表比。

结果写到 ``bench/results/ablation.json`` 与同目录的 ``.md``。

用法：
  python3 bench/bench_ablation.py
  python3 bench/bench_ablation.py --ns 100,200,400,800
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "bench"))

import bench_cycles as bc  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.serialize import spec_canonical_text  # noqa: E402

#: 病理模式与输入。``a+b`` 需要 ``a+`` 后跟 ``b``，而输入全是 ``a`` ⇒ 必然不匹配 ⇒ 扫到底。
PATTERN = "a+b"
#: 默认长度点。``a`` 的个数 —— 与旧表（100/200/400）对齐，便于看出倍率是否翻倍。
DEFAULT_NS = [100, 200, 400]
MODES = ["pike", "naive"]


def parse_ints(spec: str) -> list[int]:
    """``"100,200"`` → ``[100, 200]``。"""
    return [int(tok) for tok in spec.replace(";", " ").split() if tok]


def policy(mode: str) -> Policy:
    """单条 ``pattern_block`` 规则，只切换匹配模式 —— 消融的自变量只有这一个。"""
    return Policy("ablation", "1", rules=[
        Rule("pattern_block", "pat", {"patterns": [PATTERN], "match_mode": mode}),
    ])


def measure(n: int, mode: str) -> dict:
    """在长度 ``n`` 上跑一次，返回 ``{cycles, passed, ...}``。

    ``passed`` 必须是 ``True``：输入不命中模式，约束才会被完整扫描到底。
    命中的话就是命中即停的短路成本，与「最坏情况扫描」不是一回事 —— 那种点
    该报出来而不是悄悄混进比值里。
    """
    spec = compile_policy(policy(mode))
    out = bc.run_execute({
        "name": f"ablation-n{n}-{mode}",
        "response": "a" * n,
        "spec_canonical": spec_canonical_text(spec),
    })
    return {"n": n, "mode": mode, "cycles": out["cycles"], "passed": out.get("passed")}


def render_md(rows: list[dict], ratios: list[dict]) -> str:
    """渲染成 Markdown：先给一张 pike/naive 对照表，再给倍率。"""
    md = ["# Matcher ablation: pike (NFA) vs naive (per-start re-anchoring)", "",
          f"病理构造：模式 `{PATTERN}`，输入 `a` × `n`（无 `b` ⇒ 必然不匹配 ⇒ 扫到底）。",
          "走 `pop-script --execute`（不出证），与 `cycles.md` 同一执行路径。", "",
          "| n | pike (cycles) | naive (cycles) | 比值 | pike 周期/字符 | naive 周期/字符 |",
          "|---:|---:|---:|---:|---:|---:|"]
    by = {(r["n"], r["mode"]): r for r in rows}
    for n in sorted({r["n"] for r in rows}):
        p, q = by.get((n, "pike")), by.get((n, "naive"))
        if not p or not q:
            continue
        ratio = q["cycles"] / p["cycles"]
        md.append(f"| {n} | {p['cycles']:,} | {q['cycles']:,} | {ratio:.1f}× | "
                  f"{p['cycles']/n:.1f} | {q['cycles']/n:.1f} |")
    md += ["", "## 解读", "",
           "看最后两列（**每字符成本**），不要只看绝对值：", ""]
    for r in ratios:
        md.append(f"- n 从 {r['n_from']} 翻到 {r['n_to']}：pike 每字符 "
                  f"{r['pike_per_char_from']:.1f} → {r['pike_per_char_to']:.1f}"
                  f"（{r['pike_change_pct']:+.1f}%），naive 每字符 "
                  f"{r['naive_per_char_from']:.1f} → {r['naive_per_char_to']:.1f}"
                  f"（{r['naive_change_pct']:+.1f}%）")
    if ratios:
        last = ratios[-1]
        md += ["",
               f"**pike 每字符成本基本不变、naive 随 n 线性上升 ⇒ naive 的绝对代价是 "
               f"$O(n^2)$。** 到 n={last['n_to']} 时 naive 已是 pike 的 "
               f"{last['ratio']:.1f} 倍，且这个比值本身随 n 翻倍 —— 对手只要把回复写长，"
               "朴素实现的成本就二次增长。", "",
               "⚠️ 前提：两种模式的**判定语义必须完全等价**，否则比值没有意义。"
               "该前提由 `tests/test_ablation.py` 钉死（Python 与 Rust 两侧的 "
               "`match_search` ≡ `match_search_naive`）。"]
    return "\n".join(md) + "\n"


def main() -> int:
    """逐长度、逐模式量周期数，写 JSON + Markdown，并打印倍率。"""
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns", type=parse_ints, default=DEFAULT_NS,
                    help=f"逗号分隔的输入长度（`a` 的个数，默认 {DEFAULT_NS}）")
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "ablation.json")
    args = ap.parse_args()

    rows: list[dict] = []
    for n in args.ns:
        for mode in MODES:
            r = measure(n, mode)
            rows.append(r)
            print(f"n={n:>5} {mode:<6} cycles={r['cycles']:>12,}  passed={r['passed']}",
                  flush=True)

    bad = [r for r in rows if r.get("passed") is not True]
    if bad:
        raise SystemExit(f"这些点没有扫到底（passed != True），比值不可用：{bad}")

    by = {(r["n"], r["mode"]): r for r in rows}
    ns = sorted({r["n"] for r in rows})
    ratios = []
    for a, b in zip(ns, ns[1:]):
        p0, p1 = by.get((a, "pike")), by.get((b, "pike"))
        q0, q1 = by.get((a, "naive")), by.get((b, "naive"))
        if not (p0 and p1 and q0 and q1):
            continue
        ratios.append({
            "n_from": a, "n_to": b,
            "pike_per_char_from": p0["cycles"] / a, "pike_per_char_to": p1["cycles"] / b,
            "naive_per_char_from": q0["cycles"] / a, "naive_per_char_to": q1["cycles"] / b,
            "pike_change_pct": 100 * ((p1["cycles"] / b) / (p0["cycles"] / a) - 1),
            "naive_change_pct": 100 * ((q1["cycles"] / b) / (q0["cycles"] / a) - 1),
            "ratio": q1["cycles"] / p1["cycles"],
        })

    payload = {"pattern": PATTERN, "input": "a" * 1 + " × n", "rows": rows, "ratios": ratios}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    args.out.with_suffix(".md").write_text(render_md(rows, ratios), encoding="utf-8")
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    for r in ratios:
        print(f"n {r['n_from']}→{r['n_to']}: naive/pike = {r['ratio']:.1f}× "
              f"(pike 每字符 {r['pike_change_pct']:+.1f}%, naive {r['naive_change_pct']:+.1f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
