#!/usr/bin/env python3
"""流式路径的代价基准：采样网格是**逐字符**的，于是总代价是 ``Θ(L²)``。

**要证的命题**：``PoPCallbackHandler.on_llm_new_token`` 每收到一个字符，就对
**从 1 到当前长度的完整前缀**各判一次参考评估器（``_evaluate_prefix`` →
``AgentMonitor.generate_outcome`` → 全量重扫）。前缀长度随采样点线性增长，
求和即二次。这不是理论推导 —— 本脚本把它量出来。

**为什么值得单列一份**：这条路径的输入长度由**外部**决定（agent 回复），
所以「10k 字符的回复要多久」是个部署问题，不是一个渐近记号问题。而仓库里
曾有一句话把这个代价写成线性的（「~0.07 ms/字符，10k 字符约 0.7 s」）——
0.07 ms/字符 是 ``L≈200`` 的**瞬时值**，被当常数外推了。本脚本是那句话的
取证工具：``docs/modules/06-frameworks.md`` 与
``policydsl/adapters/langchain_adapter.py`` 的 docstring 引自这里。

**构造口径**：走**真实**的回调（``on_llm_new_token`` 逐字符喂），不自己
模拟采样循环 —— 那样量到的是「我以为的热路径」。文本用 ``"z" * L``：对
全部策略包都不命中，于是每个前缀都**扫到底**、判定也不翻转、只签第一张证书
（证书签发成本不在被测路径里）。命中即停的短路成本与「最坏情况全量重扫」
不是一回事，那种点该报出来而不是悄悄混进比值里 —— 脚本里有守卫。

**``semantic_demo_v1`` 不在表里**：含 ``semantic_bound`` 的包**流不了**。
``canonical_violations`` 只覆盖 7 类入电路规则，遇到委托给 ezkl 的那一类直接
``raise NotImplementedError``，而 ``on_llm_new_token`` 不接这个异常 —— 于是
第一个字符就崩。脚本把这条**当断言跑**（见 ``probe_unsupported``），
而不是悄悄跳过：边界本身要如实记进结果文件。

不出证（只跑参考评估器），所以全程几秒到几十秒。

结果写到 ``bench/results/streaming.json`` 与同目录的 ``.md``。

用法：
  python3 bench/bench_streaming.py
  python3 bench/bench_streaming.py --ns 500,1000,2000 --packs agent_tool_v1.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "bench"))

from bench_cycles import parse_ints  # noqa: E402  —— 只此一处定义，见 R18
from policydsl.adapters.agent import AgentMonitor  # noqa: E402
from policydsl.adapters.langchain_adapter import PoPCallbackHandler  # noqa: E402
from policydsl.core.model import Policy, Rule  # noqa: E402

#: 全部策略包。含 ``semantic_bound`` 的那个会被 ``probe_unsupported`` 单独处理。
PACKS = [
    "agent_content_v1.json", "agent_tool_v1.json", "eu_ai_act_v1.json",
    "finance_redaction_v1.json", "multiparty_demo_v1.json",
    "pii_redaction_v1.json", "semantic_demo_v1.json",
]
#: 流式路径跑不了的包 —— 「不能跑」不是「跳过」，是要被断言的边界。
UNSUPPORTED = {
    "semantic_demo_v1.json":
        "canonical_violations 对 semantic_bound 抛 NotImplementedError"
        "（承诺镜像只覆盖 7 类入电路规则；该 kind 委托给 ezkl 陪伴证明）",
}
#: 默认长度点。上限 2000 是**按包分别**判的：前缀一旦越过某个包的 ``length_bound.max``，
#: 那个点的判定就翻转为违规、多签一张证书，签发成本混进被测路径。各包上界不同
#: （1500 / 2000 / 没有），所以越界的 (包, L) **单点不测**并如实记进结果文件 ——
#: 而不是把整表的采样点压到最短的那个上界（那会让 ``agent_tool_v1`` 的 2000 也
#: 测不成，而那正是 P2 R9(b) 判据要用的基线点）。
DEFAULT_NS = [500, 1000, 2000]
RUN_ID = "bench"


def load_pack(name: str) -> Policy:
    """从 ``policy_packs/`` 读策略包。刻意复用生产侧的字段口径（同 tests 的加载器）。"""
    data = json.loads((REPO / "policy_packs" / name).read_text(encoding="utf-8"))
    return Policy(data["id"], data.get("version", "0.1.0"),
                  rules=[Rule(kind=r["kind"], name=r["name"], params=r.get("params", {}))
                         for r in data["rules"]])


def ceiling(pack: str) -> "int | None":
    """该包能安全采样的最大前缀长度；``None`` = 没有天花板。

    越过 ``length_bound.max`` 会翻转判定、多签一张证书，把签发成本混进被测
    路径 —— 那正是本基准唯一要排除的东西。「恰好没越过」不算保证：包一改
    （或被 R17a 补上界）这个前提就会悄悄失效，所以每次都从包里现读。
    """
    data = json.loads((REPO / "policy_packs" / pack).read_text(encoding="utf-8"))
    caps = [r.get("params", {}).get("max") for r in data["rules"]
            if r["kind"] == "length_bound"]
    caps = [c for c in caps if c is not None]
    if not caps:
        return None  # 没有上界 ⇒ 没有天花板（这正是 R17a 记的那件事）
    # 判据是 `lo <= n <= hi`（`evaluate.py` 的 length_bound 分支），所以**恰好等于**
    # 上界仍合规；翻转发生在 `n > hi` 的第一个采样点。这不省事：它把可用的最大
    # 采样点从 `ceil - 1` 抬到 `ceil`，正好是最值得量的一点。
    return min(caps)


def measure(pack: str, n: int) -> dict:
    """逐字符喂 ``n`` 个字符，返回 ``{seconds, certs}``。

    ``certs`` 必须是 **1**：只签第一张（首个前缀的判定）证书。多于 1 意味着
    判定中途翻转、后续前缀开始签证书 —— 那会把签发成本混进被测路径，
    该报出来而不是混进比值里。
    """
    handler = PoPCallbackHandler(AgentMonitor(load_pack(pack)), stream_step_chars=1)
    text = "z" * n
    t0 = time.perf_counter()
    for ch in text:
        handler.on_llm_new_token(ch, run_id=RUN_ID)
    dt = time.perf_counter() - t0
    return {"pack": pack, "n": n, "seconds": dt,
            "ms_per_char": 1000 * dt / n,
            "c_us_per_char_sq": 1e6 * dt / (n * (n + 1) / 2),   # 总代价 ≈ c·L²/2
            "certs": len(handler.stream_certificates)}


def probe_unsupported(pack: str) -> str:
    """确认 ``pack`` 在流式路径上**确实**抛异常，并返回异常文案。

    边界也要有守卫：如果哪天 ``canonical_violations`` 补上了这一 kind（或
    handler 学会干净地拒绝），这条探测会失败 —— 那时该把它从 ``UNSUPPORTED``
    里挪进表里，而不是让它继续挂在「已知例外」的名下。
    """
    handler = PoPCallbackHandler(AgentMonitor(load_pack(pack)), stream_step_chars=1)
    try:
        handler.on_llm_new_token("z", run_id=RUN_ID)
    except NotImplementedError as exc:
        return f"{type(exc).__name__}: {exc}"
    raise SystemExit(
        f"{pack} 本该在流式路径上抛 NotImplementedError，但它没抛 —— "
        "边界变了，请把它从 UNSUPPORTED 挪进成本表")


def render_md(rows: list[dict], unsupported: dict, skipped: list[dict],
              ns: list[int]) -> str:
    """渲染成 Markdown：先给成本表，再给「每字符成本随 L 翻倍」的读法。"""
    packs = [p for p in PACKS if p not in UNSUPPORTED]
    by = {(r["pack"], r["n"]): r for r in rows}
    skip_at = {(s["pack"], s["n"]): s for s in skipped}
    md = ["# 流式路径的代价：`Θ(L²)`", "",
          "逐字符喂 `\"z\" * L`（对全部包都不命中 ⇒ 每个前缀都扫到底、判定不翻转），",
          "走**真实**的 `PoPCallbackHandler.on_llm_new_token`，`stream_step_chars=1`。",
          "不出证，只跑参考评估器。", "",
          "| L | " + " | ".join(p.replace("_v1.json", "") for p in packs) + " |",
          "|---:|" + "---:|" * len(packs)]
    for n in sorted(ns):
        cells = []
        for p in packs:
            r = by.get((p, n))
            if r:
                cells.append(f"{r['seconds']*1000:,.0f} ms")
            elif (p, n) in skip_at:
                cells.append(f"— ⚠️ 越界（>{skip_at[(p, n)]['ceiling']}）")
            else:
                cells.append("—")
        md.append(f"| {n} | " + " | ".join(cells) + " |")
    md += ["", "## 每字符成本（ms/char）—— **看这一张**", "",
           "| L | " + " | ".join(p.replace("_v1.json", "") for p in packs) + " |",
           "|---:|" + "---:|" * len(packs)]
    for n in sorted(ns):
        cells = []
        for p in packs:
            r = by.get((p, n))
            cells.append(f"{r['ms_per_char']:.4f}" if r else "—")
        md.append(f"| {n} | " + " | ".join(cells) + " |")
    md += ["", "**读法**：L 拉长多少倍，每字符成本就跟着长多少倍 —— 下面每行都并排"
           "给出这两个倍率，直接对看即可。**若总代价是线性的，第二列那一栏应当基本"
           "不变**（每字符成本是常数）。它随 L 同步上升，就是 `Θ(L²)` 的样子。"
           "所以**不要把某个 L 上的「每字符」当常数去外推**。", ""]
    for p in packs:
        cells = [by[(p, n)] for n in sorted(ns) if (p, n) in by]
        if len(cells) < 2:
            continue
        first, last = cells[0], cells[-1]
        # 两个倍率并排写：L 长了多少倍、每字符成本就长了多少倍 —— 二次性的读法。
        md.append(f"- {p.replace('_v1.json', '')}：L ×{last['n']/first['n']:.1f}，"
                  f"每字符成本 {first['ms_per_char']:.4f} → {last['ms_per_char']:.4f} ms/char"
                  f"（×{last['ms_per_char']/first['ms_per_char']:.2f}）；"
                  f"拟合常数 {first['c_us_per_char_sq']:.3f} → "
                  f"{last['c_us_per_char_sq']:.3f} µs/char²")
    md += ["", "拟合常数 `c = 总耗时 / (L(L+1)/2)` 在各 L 上基本不变 —— 说明 "
           "`总耗时 ≈ c·L²/2` 这个模型站得住，二次性是量出来的、不是外推的。", ""]
    # 包间差按**实测**算，不写死倍数：换机器/换包这个数就变，写死了就是下一个
    # 「0.07 ms/字符」。比的是**同一个 L** 上各包的中位耗时 —— 否则最贵的取在
    # L=1500、最便宜的取在 L=500，比出来的是 L 的差不是包的差。
    widest = max((n for n in ns if any((p, n) in by for p in packs)), default=None)
    if widest is not None:
        same_l = sorted((by[(p, widest)] for p in packs if (p, widest) in by),
                        key=lambda r: r["ms_per_char"])
        if len(same_l) >= 2 and same_l[-1]["ms_per_char"] > same_l[0]["ms_per_char"]:
            top, bot = same_l[-1], same_l[0]
            md += [f"**包间差也是真的**：同为 {widest} 字符，最贵的 "
                   f"`{top['pack'].replace('_v1.json', '')}` 与最便宜的 "
                   f"`{bot['pack'].replace('_v1.json', '')}` 差 "
                   f"**{top['ms_per_char']/bot['ms_per_char']:.0f}×**（"
                   f"{top['ms_per_char']:.3f} vs {bot['ms_per_char']:.4f} ms/char）。"
                   "因为每个采样点要对**完整前缀**跑一遍**全部** pattern 的 NFA。"
                   "所以「流式要多久」**没有单一答案，必须连着策略包说**。", ""]
    md += [
           "**采样的上限逐包判，不是全表取最小**：前缀越过某个包的 `length_bound.max` 会"
           "翻转判定、多签一张证书，签发成本就混进被测路径 —— 那种 (包, L) **单点不测**，"
           "在表里标成「越界」并记进 `streaming.json` 的 `skipped`，**不是悄悄空着**。", ""]
    if skipped:
        md += ["| 越界的点 | 原因 |", "|---|---|"]
        md += [f"| `{s['pack']}` @ {s['n']} | {s['why']} |" for s in skipped]
        md += [""]
    md += ["顺带一个事实：`agent_tool_v1` 与 `pii_redaction_v1` **没有 `length_bound`**，"
           "它们的代价**没有天花板** —— 而后者正是表里最贵的（见 R17a）。", ""]
    if unsupported:
        md += ["## 流式路径跑不了的包（**边界，不是跳过**）", "",
               "| 包 | 症状 | 原因 |", "|---|---|---|"]
        for p, why in UNSUPPORTED.items():
            md.append(f"| `{p}` | `{unsupported[p]}` | {why} |")
        md += ["", "脚本把这一条**当断言跑**（`probe_unsupported`）：哪天它不再抛了，"
               "基准会当场失败，逼人把它挪进成本表 —— 而不是让它一直挂在"
               "「已知例外」的名下。", ""]
    md += ["## 引用这份结果的文档", "",
           "- `docs/modules/06-frameworks.md` §流式代价 —— 本表是那一段的数字来源",
           "- `policydsl/adapters/langchain_adapter.py` —— `PoPCallbackHandler` docstring",
           "- `docs/dev-plan.md` §5.7 —— R17b 的取证；P2 R9(b) 的前后对比基线", ""]
    return "\n".join(md) + "\n"


def main() -> int:
    """逐长度、逐包量耗时，写 JSON + Markdown，并打印每字符成本。"""
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns", type=parse_ints, default=DEFAULT_NS,
                    help=f"逗号分隔的输入长度（默认 {DEFAULT_NS}）")
    ap.add_argument("--packs", default=None,
                    help="逗号分隔的策略包文件名；缺省为全部 7 个")
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "streaming.json")
    args = ap.parse_args()

    wanted = args.packs.split(",") if args.packs else PACKS
    unknown = [p for p in wanted if p not in PACKS]
    if unknown:
        raise SystemExit(f"未知策略包：{unknown}（可选：{PACKS}）")

    unsupported = {p: probe_unsupported(p) for p in wanted if p in UNSUPPORTED}
    skipped: list[dict] = []
    rows: list[dict] = []
    for pack in wanted:
        if pack in UNSUPPORTED:
            print(f"{pack:<26} 不支持：{unsupported[pack]}", flush=True)
            continue
        ceil = ceiling(pack)
        if ceil is not None:
            for n in [n for n in args.ns if n > ceil]:
                skipped.append({"pack": pack, "n": n, "ceiling": ceil,
                                "why": f"n > length_bound.max={ceil} ⇒ 判定会在上界处"
                                       f"翻转、多签一张证书"})
                print(f"{pack:<26} L={n:>5}  跳过：越过 length_bound.max={ceil}",
                      flush=True)
        for n in [n for n in args.ns if ceil is None or n <= ceil]:
            r = measure(pack, n)
            rows.append(r)
            print(f"{pack:<26} L={n:>5}  {r['seconds']*1000:>9,.1f} ms  "
                  f"{r['ms_per_char']:.4f} ms/char  c={r['c_us_per_char_sq']:.3f} µs/char²",
                  flush=True)

    bad = [r for r in rows if r["certs"] != 1]
    if bad:
        raise SystemExit(
            f"这些点在流式过程中判定翻转了（certs != 1），签发成本混进了被测路径，"
            f"每字符成本不可比：{[(r['pack'], r['n'], r['certs']) for r in bad]}")

    payload = {"ns": list(args.ns), "rows": rows, "unsupported": unsupported,
               "skipped": skipped,
               "note": "逐字符喂 'z'*L，走真实 on_llm_new_token，stream_step_chars=1"}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    args.out.with_suffix(".md").write_text(
        render_md(rows, unsupported, skipped, list(args.ns)), encoding="utf-8")
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
