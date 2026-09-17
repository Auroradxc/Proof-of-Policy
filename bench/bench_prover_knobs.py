#!/usr/bin/env python3
"""SP1 prover 旋钮矩阵（R11）：**能不能把那条 ~10.15 GiB 的地板压低一点**，且证明仍然有效。

## 为什么只能从环境变量下手

SP1 的 prover 选项**没有 CLI**：``pop-script`` 只认 ``--vectors/--out/--proof-out/
--proof-mode/--verify/--check``。旋钮全在 ``SP1_WORKER_*`` 一族环境变量里，由
``sp1-prover-6.7.0/src/worker/config.rs`` 的 ``SP1WorkerConfig::new`` 读入。

**它们确实在本仓的路径上**（读代码确认，不是猜的）：``SP1_PROVER=cpu`` 走
``sp1-sdk-6.7.0/src/blocking/cpu/mod.rs`` 的 ``CpuProver::new_with_opts_and_machine``
→ ``cpu_worker_builder_with_machine`` → ``SP1LocalNodeBuilder::from_worker_client_builder``
→ ``builder.rs`` 里的 ``SP1WorkerConfig::new``。所以这些变量不是给别的 prover 用的。

默认值（同上文件末尾的常量，抄在这里省得每次去翻）：

    NUM_SPLICING_WORKERS=2  SPLICING_BUFFER_SIZE=2  MAX_REDUCE_ARITY=4
    NUM_CORE_WORKERS=4      CORE_BUFFER_SIZE=4      NUM_SETUP_WORKERS=2
    SETUP_BUFFER_SIZE=2     NORMALIZE_PROGRAM_CACHE_SIZE=5
    NUM_PREPARE_REDUCE_WORKERS=4   PREPARE_REDUCE_BUFFER_SIZE=4
    NUM_RECURSION_EXECUTOR_WORKERS=4  RECURSION_EXECUTOR_BUFFER_SIZE=4
    NUM_RECURSION_PROVER_WORKERS=8    RECURSION_PROVER_BUFFER_SIZE=8
    NUM_DEFERRED_WORKERS=4            DEFERRED_BUFFER_SIZE=2
    VERIFY_INTERMEDIATES=true         USE_FIXED_PK=false

⚠️ 这些名字里的 ``BUFFER_SIZE`` **不是字节数**，是通道容量（元素个数）。所以这一族
旋钮改的是**并发度与在途数据量**，不是某个缓冲区的大小。峰值常驻随之涨落的是
「同时在飞的 worker 各自持有的那份工作集」——**若本次证明只有一个 shard，把 worker
数降到 1 就不会省下任何东西**（没有第二个 worker 的工作集可以省）。这正是本实验要
量出来的事之一，别在跑之前就先下结论。

> **实测结果（2026-09-17）：上面那句猜测被证伪了。** `NUM_CORE_WORKERS` 4→1
> 省下 **1.14 GiB（−10.9%）**，而只把通道容量压到 1、worker 数不动则**一点没省**
> （+0.66%）。所以占内存的是 **worker 数**（同时在飞的工作集份数），不是通道容量。
> 结论在 `bench/results/prover_knobs.md`；这句「先猜、后证伪」保留在这里，是因为
> 它正是这个实验存在的理由 —— 猜错的那一半比猜对的那一半更有信息量。

## 为什么要跑两遍基线

本文件的方法是「同一点、换旋钮、比峰值常驻」。而 ``bench_proofs.py`` 的取样记录
已经写明：**墙上耗时不可复现（±10%），峰值内存可复现（±1%）**。±1% 的底噪意味着
**任何小于 1% 的差都读不出来**，而门槛定在 5% —— 那还是需要一个**当轮**的基线，
而不是拿结果文件里旧一轮的 10389 MB 当分母（换一轮机器状态就可能偏出 1%）。
所以基线的**同一份配置在矩阵首尾各跑一次**，两头都报出来。

## 判据（计划 §2 的 P2 表，事先写死）

- **任一配置把地板压低 ≥5% 且 ``--verify`` 仍通过 ⇒ 写成推荐配置；**
- **一个都没降 ⇒ 照样记进结果文件**（这就是结论：「本机这条地板压不动」）；
- 被 OOM 杀 ⇒ 如实记录（本实验全是**降**内存的方向，预期不会）。

5% 是相对**当轮基线**的两头均值算的，不是相对旧轮的历史值。

## 用法

    SP1_PROVER=cpu python3 bench/bench_prover_knobs.py            # 6 轮，每轮 ~2 min
    SP1_PROVER=cpu python3 bench/bench_prover_knobs.py --only default,low-concurrency

结果写到 ``bench/results/prover_knobs.{json,md}``。
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

#: 采样点。**刻意选最小的那个真点** `(200, 1)`：它已经坐在那条地板上
#: （10,389 MB），而规模每涨一档只是沿着两级台阶往上走，对「地板能不能降」
#: 这个问题不提供新信息 —— 却要多花几分钟、还可能 OOM。所以矩阵只在最小点上跑。
POINT = (200, 1)

#: 矩阵。第一项与最后一项**是同一份配置**（当轮基线，一头一尾）。
#:
#: ``low-concurrency`` 把能降的 worker 数/通道容量一起降到底，用来回答「worker 一族
#: 到底占不占内存」这个是非题；``few-core-workers`` 与 ``tiny-buffers`` 各拆一半，
#: 是为了在「它不降」的时候还能说清是**哪一半**不降。
CONFIGS: list[tuple[str, dict]] = [
    ("default", {}),
    ("no-verify-intermediates", {"SP1_WORKER_VERIFY_INTERMEDIATES": "false"}),
    ("few-core-workers", {"SP1_WORKER_NUM_CORE_WORKERS": "1",
                          "SP1_WORKER_CORE_BUFFER_SIZE": "1"}),
    ("tiny-buffers", {  # worker 数不动，只把通道容量压到最小
        "SP1_WORKER_CORE_BUFFER_SIZE": "1",
        "SP1_WORKER_SETUP_BUFFER_SIZE": "1",
        "SP1_WORKER_SPLICING_BUFFER_SIZE": "1",
        "SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE": "1",
        "SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE": "1",
        "SP1_WORKER_PREPARE_REDUCE_BUFFER_SIZE": "1",
        "SP1_WORKER_DEFERRED_BUFFER_SIZE": "1",
    }),
    ("low-concurrency", {  # 全部降到 1——包括递归证明那 8 个 worker
        "SP1_WORKER_NUM_CORE_WORKERS": "1",
        "SP1_WORKER_CORE_BUFFER_SIZE": "1",
        "SP1_WORKER_NUM_SETUP_WORKERS": "1",
        "SP1_WORKER_SETUP_BUFFER_SIZE": "1",
        "SP1_WORKER_NUM_SPLICING_WORKERS": "1",
        "SP1_WORKER_SPLICING_BUFFER_SIZE": "1",
        "SP1_WORKER_NUM_RECURSION_PROVER_WORKERS": "1",
        "SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE": "1",
        "SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS": "1",
        "SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE": "1",
        "SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS": "1",
        "SP1_WORKER_PREPARE_REDUCE_BUFFER_SIZE": "1",
        "SP1_WORKER_NUM_DEFERRED_WORKERS": "1",
        "SP1_WORKER_DEFERRED_BUFFER_SIZE": "1",
    }),
    ("default-again", {}),
]

#: 「地板压低」的门槛。**事先定死**，跑完不改口径（计划 §2 的 P2 表）。
THRESHOLD = 0.05


def render_md(rows: list[dict], host: dict | None, threshold: float,
              complete: bool = True) -> str:
    """把矩阵渲染成 Markdown，并**由数据现推**结论（不写死「降了/没降」）。

    ``complete=False`` 用于**跑到一半的中途落盘**：那时表里只有前几轮，最后由
    :func:`envelope` 给出的那几句结论会变成**没有根据的断言**（第一轮永远是
    ``default``，而 ``default`` 天然不可能是「降下来的配置」，于是半截数据也会
    渲染出「一个都没降」）。所以中途只出表、不出结论。
    """
    md = ["# SP1 prover 旋钮矩阵：这条地板压得动吗（R11）", ""]
    if host:
        md += [f"**量测机器**：{host.get('cpu_count')} 核 "
               f"`{host.get('cpu_model') or '未知型号'}`，"
               f"内存 {(host.get('mem_total_mb') or 0)/1024:.1f} GiB"
               f"（`{host.get('hostname')}`，{host.get('platform')}）。"
               "⚠️ **地板是 prover 的固定开销，但「压不压得动」是这台机器的结论** —— "
               "换机器要重跑。", ""]
    md += [f"采样点 **`L={POINT[0]}, rules={POINT[1]}`**（本仓最小的真点，已坐在那条地板上）。"
           "峰值内存由 `/usr/bin/time -v` 量取，**每轮一个独立子进程**；"
           "每轮出完证再用 `pop-script --verify` 独立验一次。", "",
           "| # | 配置 | 旋钮 | peak RSS (MiB) | 相对当轮基线 | 耗时 (s) | shard | 已验 | passed |",
           "|---:|:--|:--|---:|---:|---:|---:|:--|:--|"]
    base = baseline_mb(rows)
    for i, r in enumerate(rows, 1):
        if not r.get("ok"):
            md.append(f"| {i} | `{r['config']}` | `{knob_str(r['knobs'])}` | — | — | "
                      f"{r['seconds']} | — | — | {r['error']} |")
            continue
        delta = (f"{(r['peak_rss_mb'] / base - 1) * 100:+.2f}%" if base else "—")
        shards = r.get("shards")
        md.append(f"| {i} | `{r['config']}` | `{knob_str(r['knobs'])}` | "
                  f"{r['peak_rss_mb']:,.0f} | {delta} | {r['seconds']:.1f} | "
                  f"{shards if shards is not None else '?'} | "
                  f"{'yes' if r['verified'] else '**NO**'} | "
                  f"{r['passed'] if r['passed'] is not None else '?'} |")
    md += shard_note(rows)
    md += envelope(rows, base, threshold, complete)
    return "\n".join(md) + "\n"


def shard_note(rows: list[dict]) -> list[str]:
    """``shard`` 那一列全空时，说清「空」是**信息不可得**，不是数丢了。

    由数据现推：只有整列都没数出来才加这段话。若哪天有人真拿到了 shard 数，
    这段话自动消失 —— 不会变成一句和表对不上的注释。
    """
    ok = [r for r in rows if r.get("ok")]
    if not ok or any(r.get("shards") is not None for r in ok):
        return []
    return ["", "⚠️ **`shard` 那一列的 `?`：这一列本轮一个都没数出来** —— 不是漏了。"
            "SP1 只在日志级别含 debug 时才打印 shard 边界"
            "（`sp1-prover-6.7.0/src/worker/controller/splicing.rs:204` 的 "
            "`tracing::debug!(\"starting new shard …\")`），而未设 `RUST_LOG` 时"
            "默认级别是 `off`（`sp1-core-machine-6.7.0/src/utils/logger.rs:22`）。"
            "真出证是本实验的主量测，为拿这一列去开 debug 日志会**改变被量的东西**"
            "（日志本身要内存、要时间），所以宁可让它空着。"
            "⚠️ **空着并不挡结论**：本轮量出来的是「**谁**在占内存」—— 是 worker 数"
            "（上表 `NUM_CORE_WORKERS` 那一行），不是 shard 数。dev-plan §5.7.17 记了"
            "这一点，并逐句标明哪句是**量到的**、哪句是**推的**。"]


def knob_str(knobs: dict) -> str:
    """旋钮的紧凑写法：去掉 ``SP1_WORKER_`` 前缀（表里每行都带就只是噪声）。"""
    if not knobs:
        return "（默认）"
    return " ".join(f"{k.removeprefix('SP1_WORKER_')}={v}" for k, v in knobs.items())


def is_complete(rows: list[dict]) -> bool:
    """矩阵跑完了吗：``CONFIGS`` 里**每一个**名字都有一行。

    用来把「中途落盘的那一份」与「跑完的那一份」分开 —— 两者的文件名一样，
    长相也几乎一样，只有结论段该不该出现不同。``--only`` 跑的是子集，所以它
    永远不算跑完。
    """
    got = {r.get("config") for r in rows}
    return all(name in got for name, _ in CONFIGS)


def baseline_mb(rows: list[dict]) -> float | None:
    """当轮基线 = 首尾两次 ``default`` 的均值。

    用均值而不是取第一次：两次之间隔了四五轮真证明，机器状态（页缓存、碎片）会漂，
    均值把漂移摊到两头。只有一个能读时就用那一个（跑了一半被中断的情况）。
    """
    vals = [r["peak_rss_mb"] for r in rows
            if r.get("ok") and r["config"] in ("default", "default-again")]
    return sum(vals) / len(vals) if vals else None


def envelope(rows: list[dict], base: float | None, threshold: float,
             complete: bool = True) -> list[str]:
    """**由数据现推**结论段。判据事先写死（≥5% 即推荐），但「降没降」不许写死。

    ``complete=False``（中途落盘）时只写「跑到一半」，不写结论 —— 见
    :func:`render_md` 的说明。中途文件也会躺在 ``bench/results/`` 里被人打开，
    一句没有数据支撑的「一个都没降」比没有结论更坏。
    """
    ok = [r for r in rows if r.get("ok")]
    if not ok or base is None:
        return ["", "（还没量到基线，结论段暂缺）"]
    vals = [r["peak_rss_mb"] for r in rows
            if r.get("ok") and r["config"] in ("default", "default-again")]
    spread = (max(vals) - min(vals)) / base if len(vals) > 1 else 0.0
    winners = [r for r in ok
               if r["config"] not in ("default", "default-again")
               and r["verified"] and r["peak_rss_mb"] <= base * (1 - threshold)]
    bad = [r for r in ok if not r["verified"]]

    out = ["", "## 解读", "",
           f"**当轮基线 {base:,.0f} MiB**"
           + (f"（首尾两次 default 相差 {spread*100:.2f}%）" if len(vals) > 1 else "（只量到一次）")
           + f"，判据是「压低 ≥{threshold:.0%}」（即 ≤{base*(1-threshold):,.0f} MiB）。", ""]
    if spread > 0:
        out += [f"> 读法：**这条 ±{spread*100/2:.2f}% 的底噪就是本次的分辨率** —— "
                "小于它的差不能当成信号，无论正负。", ""]
    if bad:
        out += ["⚠️ 有配置**验不过**：" + ", ".join(f"`{r['config']}`" for r in bad)
                + "。那几行的时间与内存数字都不作数。", ""]
    if not complete:
        out += ["**⚠️ 矩阵还没跑完** —— 这一份是中途落盘的，上面只有 "
                f"{len(ok)} 行。判据是拿**当轮基线**去比**非默认配置**，而跑到一半时"
                "非默认配置还没量到：此时写「一个都没降」是一句**没有根据**的话"
                "（第一行永远是 `default`，它天然不可能是「降下来的配置」）。"
                "所以这一段到此为止，跑完再看。", ""]
    elif winners:
        out += ["**降下来的配置**（≥门槛且证明仍有效）：", ""]
        for r in winners:
            out.append(f"- `{r['config']}`：{r['peak_rss_mb']:,.0f} MiB"
                       f"（{(r['peak_rss_mb']/base-1)*100:+.2f}%，"
                       f"{r['seconds']:.1f} s）—— `{knob_str(r['knobs'])}`")
        out += ["", "⇒ **写成推荐配置**（判据是事先定的，不是事后挑的）。", ""]
        if len(winners) > 1:
            # 多个配置都过门槛时，推荐**旋钮最少**的那一个：多出来的那些旋钮要么没用、
            # 要么只是把同一件事换个说法，而每多动一个都多一分「顺带影响别的路径」的
            # 风险。哪一个是「最少」由数据点出来，不写死名字。
            minimal = min(winners, key=lambda r: len(r["knobs"]))
            others = [r for r in winners if r is not minimal]
            spread = "、".join(
                f"`{r['config']}` {(r['peak_rss_mb'] - minimal['peak_rss_mb']) / base * 100:+.2f}%"
                for r in others)
            out += [f"其中**旋钮最少**的是 `{minimal['config']}`（{len(minimal['knobs'])} 个）"
                    f"—— **推荐从它开始**。其余几个都是它的超集，与它相差 {spread}："
                    f"都远小于 {threshold:.0%} 的门槛，即「多加的那些旋钮既没帮上忙、"
                    "也没明显碍事」；而**动得越少，越不会顺带影响别的路径**"
                    "（别的证明模式、别的 shard 数）。", ""]
    else:
        out += [f"**没有任何配置把地板压低 {threshold:.0%}。** 这不是「没量到东西」—— "
                "它本身就是结论：", "",
                "**在这台机器、这个点上，`SP1_WORKER_*` 这一族旋钮动不了这条地板。**"
                "这一族改的是「同时在飞的几份工作集」（worker 数 × 通道容量）；"
                "把 worker 数降到 1 就已经是「只有一份工作集」的极端，再往下没有可省的。", "",
                "⚠️ **它否定的只是这一族旋钮，不等于「地板不可压」。** 其它手段"
                "（`SHARD_SIZE`、换证明模式、换机器）**不在本实验的射程里**，"
                "本文件对它们的强弱一个字都没说。", "",
                "⇒ 已知的、有证据的结论只有一条：**在这一族旋钮里想「更大能证」，没有便宜可捡**。"
                "配 `bench/results/proofs.md` 的边界结论一起读。", ""]
    out += ["## 复跑", "",
            "```", "SP1_PROVER=cpu python3 bench/bench_prover_knobs.py", "```", "",
            "旋钮名字与默认值出自 `sp1-prover-6.7.0/src/worker/config.rs`；"
            "「它们在本仓路径上」由 `sp1-sdk-6.7.0/src/blocking/cpu/mod.rs` 的 "
            "`CpuProver` → `SP1LocalNodeBuilder` 链路确认。"]
    return out


def dump(out_path: Path, rows: list[dict], host: dict | None,
         complete: bool = False) -> None:
    """每轮之后落盘 —— 被中断也不丢已经花掉的那几分钟。

    ``complete`` 默认 ``False``（中途落盘）：JSON 照写（数据就是数据，写到哪算哪），
    但 ``.md`` 的结论段按下不表，见 :func:`render_md`。
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(
        {"host": host, "point": {"length": POINT[0], "rules": POINT[1]},
         "threshold": THRESHOLD, "rows": rows}, indent=2), encoding="utf-8")
    out_path.with_suffix(".md").write_text(render_md(rows, host, THRESHOLD, complete),
                                           encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path,
                    default=REPO / "bench" / "results" / "prover_knobs.json")
    ap.add_argument("--corpus", default="demo", help="同 bench_proofs.py")
    ap.add_argument("--only", default=None,
                    help="只跑名字匹配的配置（逗号分隔），用于补跑某一两轮")
    ap.add_argument("--render-only", action="store_true",
                    help="不跑任何证明，只把已有的 --out JSON 重新渲染成 .md。"
                         "改措辞/加外部指引时用它 —— 重跑一轮真证明要十几分钟，"
                         "为一句排版付这个代价没有道理。")
    args = ap.parse_args()

    if args.render_only:
        if not args.out.exists():
            raise SystemExit(
                f"{args.out} 不存在：--render-only 渲染的是**已经量到**的行，"
                "它不产生数据。先跑一遍矩阵（分钟级 × 轮数）。")
        data = json.loads(args.out.read_text(encoding="utf-8"))
        full = is_complete(data["rows"])
        md_path = args.out.with_suffix(".md")
        md_path.write_text(render_md(data["rows"], data.get("host"), data["threshold"], full),
                           encoding="utf-8")
        print(f"从 {args.out} 渲染 {len(data['rows'])} 行 → {md_path}（未跑任何证明）"
              f"｜矩阵{'跑完了' if full else '**没跑完**（结论段不写）'}")
        return 0

    configs = CONFIGS
    if args.only:
        want = [s.strip() for s in args.only.split(",") if s.strip()]
        configs = [(n, e) for n, e in CONFIGS if n in want]
        if not configs:
            raise SystemExit(f"--only 没匹配到任何配置，可选项：{[n for n, _ in CONFIGS]}")

    host = bp.host_info()
    print(f"host={host['hostname']}  {host['cpu_count']} 核  "
          f"{host['mem_total_mb']/1024:.1f} GiB  点={POINT}  轮数={len(configs)}")

    loaded = bc.load_corpus(args.corpus)
    corpus_text = loaded.text
    if bc.trips(bc.text_of_length(corpus_text, POINT[0])):
        raise SystemExit("语料在 L=200 上命中规则，会短路；换 --corpus")

    rows: list[dict] = []
    for i, (name, knobs) in enumerate(configs, 1):
        print(f"\n=== [{i}/{len(configs)}] {name}  {knob_str(knobs)} "
              f"（真实证明，分钟级）===", flush=True)
        row = bp.run_point(*POINT, corpus_text, "core", extra_env=knobs or None)
        row["config"] = name
        row.setdefault("knobs", knobs)
        rows.append(row)
        dump(args.out, rows, host)     # 先落盘再打印：中断也不丢
        if row["ok"]:
            print(f"  {name:26s} {row['seconds']:6.1f}s  "
                  f"peakRSS={row['peak_rss_mb']:,.0f} MB  "
                  f"shards={row.get('shards')}  "
                  f"verified={row['verified']}  passed={row['passed']}", flush=True)
        else:
            print(f"  {name:26s} 失败：{row['error']}", flush=True)

    # 全部跑完，最后再落一次盘：这一次才带结论段。中途那几次只写表。
    # 「跑完」的判据只此一处（`is_complete`）—— `--only` 跑的是子集，因此不算跑完，
    # 子集上的「一个都没降」同样是没根据的话。
    dump(args.out, rows, host, complete=is_complete(rows))

    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    base = baseline_mb(rows)
    if base:
        print(f"当轮基线 {base:,.0f} MiB，门槛 {base*(1-THRESHOLD):,.0f} MiB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
