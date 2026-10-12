#!/usr/bin/env python3
"""规模化评测（WP1，决定项 D5/D6）：**把可行域边界整张量出来**，而不是量几个点。

## 和 `bench_proofs.py` 的分工

`bench_proofs.py` 回答的是「给这几个点，每点的耗时/内存是多少」—— 一张**表**。
本文件回答的是「**在这台机器上，哪些点根本跑不出来**」—— 一张**边界**。两者
要的机器和时间不是一个量级：

| | `bench_proofs.py` | `bench_scale.py` |
|---|---|---|
| 点数 | 6 | 规则 × 长度 × 证明档，几十点 |
| 时长 | ~15 min | **几小时**（本机），64 GB 机器上更长 |
| 失败 | 意外 | **预期之内，且是主结论** |
| 中断 | 重跑 | **必须能续跑**（几小时的活不能因为一条 SSH 断了就重来） |

四条差异各自对应下面一个机制：**续跑**、**预算闸**、**起飞前内存体检**、
**边界渲染**。缺任何一条，这个脚本在真机上都会以「跑了一下午、什么都没留下」
收场。

## 为什么把「隐私模式」从矩阵里拿掉（**诚实说明，不是遗漏**）

`docs/tdsc-plan.md` 的矩阵写的是 `patterns × length × mode {public, private,
private-policy} × proof {core, groth16}`。真去核了一遍 CLI：**`pop-script` 没有
`--mode`** —— 只有 ``--vectors/--out/--proof-out/--proof-mode/--verify/--check``
（见 `bench_proofs.py` 的 `run_point`）。公私之别住在**会话层**
（`AgentMonitor(policy, mode=…)`、`demo_e2e.py --mode`），不进 zkVM。

所以本文件**只量 prover 侧**（规则数 × 长度 × 证明档）——它是内存墙的所在。
隐私模式那一维要么在会话层单独量（WP4），要么等 `--mode` 真的接进 `pop-script`
之后再加进来。**在矩阵里摆一个量不到的维度，就是在给一张假表留位置。**

## 起飞前的三个闸（都是**事先写死**的判据，不是跑完再解释）

1. **内存体检**：每个证明档有各自的最低内存（:data:`MODE_MIN_MEM_MB`，出处见注释）。
   低于就**不跑**，直接记一行 `skipped: …` —— 而不是花 20 分钟去换一个 SIGKILL。
   这条正是 D5（groth16 必须成为交付档）能不能兑现的**第一道现实检验**。
2. **预算闸**：`--budget-min`。超了就把剩下的点标成 `未跑（预算用尽）`，
   **如实写在结果文件里**，不假装矩阵跑完了。
3. **平铺体检**（与 `bench_proofs.py`/`bench_cycles.py` 同口径）：平铺后的文本
   若命中规则会短路，cycle 数偏低。对着一个短路的点读成本曲线，结论就是错的。
   所以在花掉几小时之前先挡住。

## 与 `docs/reproduce.md` §4½ 云机 runbook 的关系

那份 runbook 是**操作步骤**，本文件是**跑那个步骤的工具**。三件事以 runbook 为准，
本文件只负责把它变成代码里的闸：内存需求（:data:`MODE_MIN_MEM_MB`）、
跨机不可并列（:func:`load_previous` 会**拒绝**往别的机器量出的文件里追加）、
以及 **出证必须串行**（同机不要并行开两个，每个进程固定地板 ~10.15 GiB，
并行只会互相推向 OOM 并污染峰值内存读数 —— 本文件**故意不提供并行选项**）。

## 用法

    # 本机（12 GB）：只会跑得动 core 的左上角，groth16 档会被跳过并如实记录
    SP1_PROVER=cpu python3 bench/bench_scale.py

    # 租来的大机器（≥64 GB / ≥32 核，D6）——注意 --out 换名，别与本机的表混
    SP1_PROVER=cpu python3 bench/bench_scale.py \
        --out bench/results/scale-cloud.json \
        --proof-modes core,groth16 --budget-min 600

    # 续跑（默认行为）：已经量成功的点直接跳过
    SP1_PROVER=cpu python3 bench/bench_scale.py --out bench/results/scale-cloud.json

    # 只重出报告，不跑证明
    python3 bench/bench_scale.py --out bench/results/scale-cloud.json --render-only

结果写到 ``bench/results/scale.{json,md}``（或 `--out` 指定的名字）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "bench"))

import bench_cycles as bc  # noqa: E402
import bench_proofs as bp  # noqa: E402

# --------------------------------------------------------------------------
# 矩阵（D6：租 ≥64 GB / ≥32 核，跑满）
# --------------------------------------------------------------------------

#: 长度档。200 = 一句话；2k = 一段；10k = 长回复；50k = 已是本机绝对跑不动的量级。
#: 保留 50k 是**故意的**：边界表要有"跑不动"的那一侧，否则它只是一张成本表。
LENGTHS = [200, 2_000, 10_000, 50_000]

#: 规则数档。1 = 地板；2/3 = 本机 OOM 区（EU AI Act 策略包正好 3 条）；6 = 大策略包。
RULES = [1, 2, 3, 6]

#: 证明档。`core` 是本机唯一跑得动的；`groth16` 是**唯一隐藏见证的档**
#: （`docs/sp1-zk-audit.md`：SP1 官方安全模型明示 core/compressed 的
#: individual STARK proofs 不满足零知识性质）。D5 要保留标题里的
#: zero-knowledge，就**必须**有 groth16 的数。
PROOF_MODES = ["core", "groth16"]

#: 各证明档的最低内存要求（MiB）。**两个数都不是本脚本估的**，出处如下：
#:
#: * `groth16`/`plonk` = **64 GiB**：`docs/reproduce.md` §4½ 的云机 runbook 写的是
#:   「≥64 GB，硬需求、实测」——本机 12 GB 上 compressed/groth16 分别峰值
#:   11.0 / 11.07 GB 被 OOM 杀，**那是撞到天花板被杀的位置，不是真实需求**。
#:   `docs/sp1-zk-audit.md` 记的官方下限是 16 GB，但本机连验证它的机会都没有
#:   （12 GB 先死）。所以取**已实测够用**的那一个：64 GiB。
#: * `core` = **16 GiB**：runbook 对全矩阵的粗估，原文自己标了「**未实测**」。
#:   本脚本**照抄这个不确定性**——它只用来决定「值不值得开跑」，不是结论。
MODE_MIN_MEM_MB = {
    "core": 16 * 1024,
    "compressed": 64 * 1024,
    "groth16": 64 * 1024,
    "plonk": 64 * 1024,
}

#: 峰值内存的可复现性（`bench/results/proofs.md`：墙上耗时 ±10%，峰值内存 ±1%）。
#: 续跑判据用它做容差：主机内存变了超过这个比例，**已量到的行作废**——
#: 因为整张表的自变量之一就是「机器有多少内存」。
HOST_MEM_TOLERANCE = 0.05


def parse_int_list(spec: str) -> list[int]:
    """``"200,2000"`` → ``[200, 2000]``。"""
    return [int(tok) for tok in spec.replace(";", ",").split(",") if tok.strip()]


def parse_str_list(spec: str) -> list[str]:
    """``"core,groth16"`` → ``["core", "groth16"]``。"""
    return [tok.strip() for tok in spec.replace(";", ",").split(",") if tok.strip()]


def matrix(lengths: list[int], rules: list[int], modes: list[str]) -> list[tuple[int, int, str]]:
    """展开成 ``[(length, rules, proof_mode), …]``。

    **顺序有讲究**：证明档在外层、长度在内层。一趟里先跑完一个档的所有长度，
    再换档 —— 换档的开销（首次编译/加载 pk）只付一次，而且同档的点连在一起，
    温度/页缓存这类漂移对**档内比较**的影响最小。
    """
    return [(L, rc, m) for m in modes for L in lengths for rc in rules]


# --------------------------------------------------------------------------
# 续跑
# --------------------------------------------------------------------------


def row_key(row: dict) -> tuple:
    """一行的身份：``(length, rules, proof_mode, 旋钮)``。

    **把旋钮也算进身份**：同一组 `SP1_WORKER_*` 不同就是不同的点，
    不能拿旋钮下的成绩去顶默认档的行（`bench_proofs.py` 的边结论句写的是
    「默认 prover 选项下」，混进旋钮那句话就不成立了）。
    """
    knobs = row.get("knobs") or {}
    return (row.get("length"), row.get("rules"), row.get("proof_mode"),
            tuple(sorted(knobs.items())))


def load_previous(path: Path) -> dict[tuple, dict]:
    """读旧结果里**可信**的行，返回 ``{key: row}``。

    两道门，对应 `docs/reproduce.md` §4½ 的两条跨机口径：

    1. **换了机器就拒绝追加**（`:func:`assert_same_host`）。runbook 第 1 条：「云机的
       数字不能与本机那张表并列读数 —— 同一组采样点换台机器就是**另一张表**」。
       这条光靠写文档拦不住，所以做进代码：主机指纹不同就报错，让你换 `--out`。
       **报错而不是警告**：追加进去的后果是一份事后没人能解释的表。
    2. **同一台机器但内存变了 ⇒ 已量到的成功行作废**。本表的自变量之一就是
       「机器有多少内存」（跑得动哪些点直接由它决定），内存变了两张表就不是一张。
    失败行（OOM/skipped）**不**进续跑缓存 —— 换台机器重跑正是要推翻它们。
    """
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}   # 半截文件（上次被 Ctrl-C 掐断）不当作证据，重跑就是
    prev_host = doc.get("host") or {}
    assert_same_host(prev_host, path)
    prev_mem = prev_host.get("mem_total_mb")
    now_mem = bp.host_info().get("mem_total_mb")
    if prev_mem and now_mem:
        drift = abs(now_mem - prev_mem) / prev_mem
        if drift > HOST_MEM_TOLERANCE:
            print(f"⚠️ 主机内存变了 {prev_mem} → {now_mem} MB（{drift:.1%}）"
                  f"，旧的**成功**行已作废（本表的自变量之一就是内存大小）")
            return {}
    out: dict[tuple, dict] = {}
    for row in doc.get("rows", []):
        if row.get("ok"):
            out[row_key(row)] = row
    return out


def assert_same_host(prev_host: dict, path: Path) -> None:
    """旧文件是**另一台机器**量的话，拒绝往里追加。见 :func:`load_previous` 第 1 条。

    比的是 ``hostname + cpu_count``：型号也顺手比一下，但**不**因为型号不同就拦
   （同一台云机重开可能报不同的型号串），只在 hostname 相同而核数/型号变了时警告。
    """
    if not prev_host:
        return
    now = bp.host_info()
    old_name, new_name = prev_host.get("hostname"), now.get("hostname")
    old_cpu, new_cpu = prev_host.get("cpu_count"), now.get("cpu_count")
    if old_name and new_name and old_name != new_name:
        raise SystemExit(
            f"✗ {path} 是主机 `{old_name}` 量的，当前是 `{new_name}`。\n"
            f"  跨机数字不可并列（docs/reproduce.md §4½ 第 1 条）。换 --out，"
            f"例如 bench/results/scale-cloud.json")
    if old_cpu and new_cpu and old_cpu != new_cpu:
        print(f"⚠️ 同一主机但核数变了 {old_cpu} → {new_cpu}：耗时不可比，"
              f"续跑只在内存维度上还有意义")


# --------------------------------------------------------------------------
# 起飞前的闸
# --------------------------------------------------------------------------


def preflight_mode(mode: str, host: dict) -> str | None:
    """这个证明档在这台机器上能不能跑。返回 ``None`` = 能；否则是**原因**。

    只看一件事：该档的最低内存（:data:`MODE_MIN_MEM_MB`，出处见那里的注释）。
    **不看耗时** —— 耗时超预算是 `--budget-min` 的事，两件事要分开报，
    否则「跑不完」和「跑不动」会混成同一个结论。
    """
    need = MODE_MIN_MEM_MB.get(mode)
    if need is None:
        return None                     # 不认识的档不拦，让 SP1 自己报错
    mem = host.get("mem_total_mb")
    if mem is None:
        return f"读不到 MemTotal，无法确认 {mode} 是否满足内存要求"
    if mem < need:
        return (f"{mode} 需约 {need} MB，本机只有 {mem} MB"
                + ("（D5 的交付档在这台机器上不可能兑现）" if mode != "core" else ""))
    return None


def preflight_corpus(length: int, corpus_text: str) -> str | None:
    """平铺后的语料会不会**命中规则**（命中⇒短路⇒cycle 数偏低）。"""
    hits = bc.trips(bc.text_of_length(corpus_text, length))
    if hits:
        return (f"平铺语料命中 {[f'{r}: {ev}' for r, ev in hits]}，"
                f"会比较成本曲线偏低。换 --corpus")
    return None


# --------------------------------------------------------------------------
# 渲染
# --------------------------------------------------------------------------


def _fmt(v, dash: str = "—") -> str:
    return dash if v is None else str(v)


def render_frontier(rows: list[dict], lengths: list[int], rules: list[int],
                    modes: list[str]) -> str:
    """边界表：每个 (证明档, 长度) 一行，规则数列给出「可行/不可行 + 峰值内存」。

    读法：**这一行的重点不是耗时，是那些 ✗**。✗ 的位置就是内存墙的形状，
    也是 WP1 要推到的地方。
    """
    idx = {row_key(r): r for r in rows}
    lines: list[str] = []
    for mode in modes:
        lines.append(f"\n### 证明档 `{mode}`\n")
        header = "| 长度 | " + " | ".join(f"{rc} 条规则" for rc in rules) + " |"
        lines.append(header)
        lines.append("|---|" + "---|" * len(rules))
        for L in lengths:
            cells: list[str] = []
            for rc in rules:
                row = idx.get((L, rc, mode, ()))
                if row is None:
                    cells.append("·")               # 没跑（预算/续跑没覆盖到）
                elif row.get("ok"):
                    cells.append(f"✓ {_fmt(row.get('seconds'))}s / "
                                 f"{_fmt(row.get('peak_rss_mb'))} MB")
                else:
                    cells.append(f"✗ {row.get('error', '失败')}")
            lines.append(f"| {L} | " + " | ".join(cells) + " |")
    lines.append("\n`✓` 出证成功并通过验证；`✗` 失败（原因照抄）；`·` 没跑到（预算用尽或"
                 "本档在本机被跳过）。**峰值内存是这一列的主量**，耗时只作参考"
                 "（`bench/results/proofs.md`：墙上耗时 ±10%、峰值内存 ±1%）。")
    return "\n".join(lines)


def render_conclusion(rows: list[dict], rules: list[int], modes: list[str]) -> str:
    """自动生成结论句。**只从数据里说得出的话，一句多的都不写。**

    这条纪律的理由：边界表最终会被抄进论文，而自动生成的句子会连同它的前提
    （哪台机器、哪个档）一起被抄走 —— 手写一句「64 GB 上能跑满」很容易在本机
    的表上被读成结论。所以这里的原则是**数据不足就明说数据不足**。
    """
    ok = [r for r in rows if r.get("ok")]
    if not ok:
        return "没有任何点成功 —— 这一轮没有可用的结论，见上面的失败原因。"
    mems = [r["peak_rss_mb"] for r in ok if r.get("peak_rss_mb")]
    max_rc = max(r["rules"] for r in ok)
    max_len = max(r["length"] for r in ok)
    parts = [
        f"本轮成功 {len(ok)} 个点；已量到的可行域到 **{max_rc} 条规则 × "
        f"{max_len} 字符** 为止。",
    ]
    if mems:
        parts.append(f"成功点的峰值常驻在 {min(mems):.0f}–{max(mems):.0f} MB 之间。")
    unrun = [r for r in rows if not r.get("ok") and "预算用尽" in (r.get("error") or "")]
    if unrun:
        parts.append(f"**{len(unrun)} 个点因预算用尽未跑**，矩阵不完整，"
                     f"上表里的 `·` 不能读成「不可行」。")
    skipped = [r for r in rows if not r.get("ok") and "skipped" in (r.get("error") or "")]
    if skipped:
        parts.append(f"另有 {len(skipped)} 个点因机器不满足证明档要求被跳过。")
    unmeasured = [m for m in modes
                  if not any(r["proof_mode"] == m and r.get("ok") for r in rows)]
    if unmeasured:
        parts.append(f"证明档 {unmeasured} **一个点都没量到** —— 若 D5 要靠它兑现，"
                     f"这张表还不能支撑那一句。")
    return " ".join(parts)


def dump(out: Path, rows: list[dict], host: dict, axes: dict) -> None:
    doc = {
        "host": host,
        "axes": axes,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "rows": rows,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")

    md = [
        "# 规模化评测：可行域边界（WP1）",
        "",
        f"- 主机 `{host.get('hostname')}`：{host.get('cpu_count')} 核 / "
        f"{_fmt(host.get('mem_total_mb'))} MB，{host.get('cpu_model')}",
        f"- 矩阵：长度 {axes['lengths']} × 规则 {axes['rules']} × 证明档 "
        f"{axes['proof_modes']}",
        f"- 生成时间：{doc['generated_at']}",
        "",
        "> **隐私模式（public/private）不在本表里**：`pop-script` 没有 `--mode`，"
        "公私之别住在会话层，不进 zkVM。见本文件头部说明。",
        "",
        "## 边界表",
        render_frontier(rows, axes["lengths"], axes["rules"], axes["proof_modes"]),
        "",
        "## 结论",
        "",
        render_conclusion(rows, axes["rules"], axes["proof_modes"]),
        "",
    ]
    out.with_suffix(".md").write_text("\n".join(md), encoding="utf-8")


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "scale.json")
    ap.add_argument("--lengths", type=parse_int_list, default=LENGTHS)
    ap.add_argument("--rules", type=parse_int_list, default=RULES)
    ap.add_argument("--proof-modes", type=parse_str_list, default=["core"],
                    help="逗号分隔。`groth16` 需 ≥16 GiB，低于此值会被跳过并如实记录"
                         "（跳过不报错：D5 的兑现与否**本来就是**这块要给出的事实）。")
    ap.add_argument("--corpus", default="demo",
                    help="与 bench_proofs.py 同口径（默认 demo：真实跑出来的工件文本）")
    ap.add_argument("--budget-min", type=float, default=None,
                    help="墙上时间预算（分钟）。超了就把剩下的点标成「未跑（预算用尽）」"
                         "**并如实写进结果文件**，不假装矩阵跑完了。默认不限。")
    ap.add_argument("--render-only", action="store_true",
                    help="不跑证明，只用 --out 里已有的 rows 重出 .md")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.render_only:
        doc = json.loads(args.out.read_text(encoding="utf-8"))
        dump(args.out, doc.get("rows", []), doc.get("host") or bp.host_info(),
             doc.get("axes") or {"lengths": args.lengths, "rules": args.rules,
                                 "proof_modes": args.proof_modes})
        print(f"re-rendered {args.out.with_suffix('.md')}")
        return 0

    host = bp.host_info()
    axes = {"lengths": args.lengths, "rules": args.rules,
            "proof_modes": args.proof_modes}
    print(f"host={host['hostname']}  {host['cpu_count']} 核  "
          f"{_fmt(host.get('mem_total_mb'))} MB")

    # 档能不能跑，先定下来；跳过的档照样进 rows（一行的缺席也是一种结论）
    skip_reason: dict[str, str | None] = {}
    for mode in args.proof_modes:
        skip_reason[mode] = preflight_mode(mode, host)
        if skip_reason[mode]:
            print(f"⏭  证明档 {mode}：{skip_reason[mode]}")

    loaded = bc.load_corpus(args.corpus)
    corpus_text = loaded.text
    print(f"corpus={args.corpus}  {len(corpus_text)} 字符")
    for L in args.lengths:
        bad = preflight_corpus(L, corpus_text)
        if bad:
            raise SystemExit(f"L={L}：{bad}")

    prev = load_previous(args.out)
    if prev:
        print(f"续跑：{len(prev)} 个已成功的点会被跳过")

    rows: list[dict] = list(prev.values())
    done = set(prev)
    deadline = (time.time() + args.budget_min * 60) if args.budget_min else None
    started = time.time()

    for length, rc, mode in matrix(args.lengths, args.rules, args.proof_modes):
        key = (length, rc, mode, ())
        if key in done:
            print(f"↷  L={length:>6} rules={rc} {mode}：已有成功记录，跳过", flush=True)
            continue
        if skip_reason.get(mode):
            rows.append({"length": length, "rules": rc, "proof_mode": mode, "ok": False,
                         "error": f"skipped：{skip_reason[mode]}"})
            continue
        if deadline and time.time() > deadline:
            rows.append({"length": length, "rules": rc, "proof_mode": mode, "ok": False,
                         "error": "未跑（预算用尽）"})
            continue

        print(f"\n=== L={length} rules={rc} mode={mode}（真实证明，分钟级）===", flush=True)
        row = bp.run_point(length, rc, corpus_text, mode)
        row["elapsed_min"] = round((time.time() - started) / 60, 2)
        rows.append(row)
        # 先落盘再打印：几小时的活，断了也不丢已量到的点
        dump(args.out, rows, host, axes)
        if row.get("ok"):
            print(f"✓ {row['seconds']:6.1f}s  {row['proof_bytes']/1024:8.1f} KiB  "
                  f"peakRSS={row['peak_rss_mb']} MB  verified={row['verified']}  "
                  f"passed={row['passed']}", flush=True)
        else:
            print(f"✗ 失败：{row.get('error')}（耗时 {row.get('seconds')}s）", flush=True)

    dump(args.out, rows, host, axes)
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
