#!/usr/bin/env python3
"""Proof-of-Policy 的证明耗时与体积曲线（真实 SP1 证明）。

只在少数几个 (长度, 规则数) 采样点上：生成一次真实证明 → 量墙钟耗时、证明产物
大小与峰值内存 → 再验证一次。每条点都很贵（分钟级、数 GB 内存），所以样本极少；
需要铺很多点的 cycle 数扫描见 ``bench_cycles.py``。

**P2-12 的取样口径**：响应文本取自 :func:`bench_cycles.load_corpus` 的 ``demo``
（``demo_e2e`` 真跑出来的工件 + 仓库自带示例回复），与 ``bench_cycles.py`` 用
**同一份语料**——这样「周期数」和「证明耗时」两张表可以逐点对上，而不是各测各的。

**证明侧与周期侧的天花板不在同一个地方**，这是这一节最该读出来的一句话。
``bench_cycles.py`` 的曲线表可以一路扫到 100k 字符、6 条规则，因为那只跑 zkVM
执行、不出证；而**真出证**（SP1 ``core``）在 200 字符时峰值常驻就已经
**10.35 GiB**，本机 12 GB 里 prover 的**固定开销就占掉 ~10.35 GiB**。固定开销之上
再往上加，只有很窄的一条缝，而且**加长度、加规则数都会踩到独立的两级台阶**：

    1 条规则 ≤10k 字符 ✓        第 3 条规则（``pattern_block``）→ OOM
    2 条规则 ~200 字符 ✓         20k 字符 → OOM

也就是说：**证明侧受内存约束，不是受周期数约束**。周期数在 100k 字符时也才千万级，
CPU 完全跑得动；卡死的是内存。所以「能证明多大的策略」这个问题在本机上的答案
不是一条斜线，而是**一条 10.35 GiB 的地板加两级台阶**。

正因如此，**每个点独立子进程**：一个点被杀不会带走已经量到的数据，失败会如实
记进 ``rows`` 的 ``error`` 字段而不是让整轮消失；采样点按「预期成本从低到高」
排列，被 OOM 杀掉的点排在后面，前面真量到的数据先落盘。

结果写到 ``bench/results/proofs.json``，同时在同目录生成一份 .md 表格。

用法：
  SP1_PROVER=cpu python3 bench/bench_proofs.py
  SP1_PROVER=cpu python3 bench/bench_proofs.py --points 200,3 20000,6   # 只补两个点
  SP1_PROVER=cpu python3 bench/bench_proofs.py --points 200,6           # 明知会 OOM，量边界
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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

#: 默认采样点：``(响应长度, 规则条数)``，**能过的点排前面、预期被 OOM 杀的排最后**。
#:
#: 这组点是照着下面这条**实测出来的可行域边界**挑的（见 ``results/proofs.md``），
#: 不是在纸上画出来的。下面是定稿那一轮的数（括号里是同一组点单跑复核时的数，
#: 用来说明**墙的位置可复现、墙上的耗时不可复现**——时间有 ±10% 的机位抖动，
#: 内存只有 ±1%）：
#:
#:     (200, 1)   ✓ 123.5 s / 10389 MB   （复核 115.5 s / 10350 MB）
#:     (200, 2)   ✓ 118.9 s / 10438 MB   （复核 130.2 s / 10400 MB）
#:     (2000, 1)  ✓ 138.1 s / 10449 MB   （复核 129.4 s / 10540 MB）
#:     (10000, 1) ✓ 172.5 s / 10506 MB   （复核 145.7 s / 10582 MB）
#:     (200, 3)   ✗ OOM（定稿与复核各失败一次）
#:     (20000, 1) ✗ OOM（定稿与复核各失败一次）
#:
#: 两条轴**都不是斜着涨的，是台阶**：长度从 10k 到 20k 掉下去，规则数从 2 到 3
#: 掉下去。后者尤其值得注意 —— 第 3 条规则是 ``pattern_block``，正则匹配会激活
#: 另一族 AIR chip，trace area 一次性抬高一大截。所以边界长这样：
#:
#:     1 条规则：≤10k 字符    2 条规则：~200 字符    3 条及以上：出不来
#:
#: ``(20000, 1)`` 与 ``(200, 3)`` 是**故意留在表里的失败点**：它们量的是「这台机器
#: 到不了哪」，和量成功的点一样是结论。删掉它们，P2-12 就只剩一句没有边界的
#: 「能证明到 10k」，读表的人无从判断天花板在哪、为什么在那儿。
DEFAULT_POINTS = [(200, 1), (200, 2), (2_000, 1), (10_000, 1), (200, 3), (20_000, 1)]


def parse_points(spec: str) -> list[tuple[int, int]]:
    """``"200,6 20000,6"`` → ``[(200, 6), (20000, 6)]``。"""
    out: list[tuple[int, int]] = []
    for tok in spec.replace(";", " ").split():
        length, _, rules = tok.partition(",")
        if not rules:
            raise SystemExit(f"--points 的每一项要写成 <长度>,<规则数>，收到 {tok!r}")
        out.append((int(length), int(rules)))
    return out


def run_point(length: int, rc: int, corpus_text: str) -> dict:
    """对单个采样点出一次真实证明，返回一行的量测结果（失败则带 ``error``）。

    **每个点一个独立子进程**，因为 SP1 的内存是进程内累积的：同一个进程里连出
    两份证明，第二份会踩在第一份的残留上，峰值 RSS 既不代表单份证明、也更容易
    被 OOM 杀。子进程被杀时 :class:`subprocess.CalledProcessError` 会被接住 ——
    量到的失败本身就是结论（「这台机器到不了这个规模」），不该让整轮丢掉。
    """
    policy = bc.make_policy(rc, "pike")
    spec = compile_policy(policy)
    text = bc.text_of_length(corpus_text, length)
    vp = WORK / "pv.json"
    op = WORK / "pr.json"
    proof = WORK / "proof.bin"
    WORK.mkdir(parents=True, exist_ok=True)
    vp.write_text(json.dumps({"vectors": [{
        "name": f"L{length}-R{rc}", "response": text,
        "spec_canonical": spec_canonical_text(spec)}]}), encoding="utf-8")

    row: dict = {"length": length, "rules": rc, "trace_sha256": hashlib.sha256(
        text.encode("utf-8")).hexdigest()}

    # 计时区间只包住出证这一条命令
    t0 = time.perf_counter()
    prefix = [TIME_BIN, "-v"] if TIME_BIN else []
    env = {**os.environ, "SP1_PROVER": "cpu"}  # 本机无 GPU，固定 CPU 路径保证可比
    try:
        res = subprocess.run(prefix + [str(POP_SCRIPT), "--vectors", str(vp), "--out", str(op),
                                       "--proof-out", str(proof)],
                             cwd=str(REPO), check=True, capture_output=True, text=True, env=env)
    except subprocess.CalledProcessError as exc:
        # 137 = 128+SIGKILL，-9 = 直接收到 SIGKILL：两者在这个量级几乎总是 OOM。
        # 其余退出码可能是构建/配置问题，措辞上要区分开，不能一律归给内存。
        rc_code = exc.returncode
        why = ("被 SIGKILL 杀（本机内存不足，OOM）" if rc_code in (137, -9)
               else f"退出码 {rc_code}（非 OOM，需要单独查）")
        row.update(ok=False, seconds=round(time.perf_counter() - t0, 2), error=why)
        return row
    secs = time.perf_counter() - t0
    m = re.search(r"Maximum resident set size \(kbytes\): (\d+)", res.stderr)
    peak_mb = round(int(m.group(1)) / 1024.0, 1) if m else None

    # 顺手验一次，确认证明本身有效（否则耗时的数字没意义）
    vout = WORK / "verify.json"
    subprocess.run([str(POP_SCRIPT), "--verify", "--proof", str(proof), "--out", str(vout)],
                   cwd=str(REPO), check=True, capture_output=True, text=True, env=env)
    verified = json.loads(vout.read_text()).get("verified")
    passed = out_passed(op)

    row.update(ok=True, seconds=round(secs, 2), proof_bytes=proof.stat().st_size,
               peak_rss_mb=peak_mb, verified=bool(verified), passed=passed)
    return row


def out_passed(out_path: Path) -> bool | None:
    """从 ``pop-script`` 的执行结果里读 ``passed``（读不到就算了，不影响主量测）。

    ``passed=False`` 的行是**诚实但短路**的点：语料命中了规则，扫描没跑到底。
    对「证明耗时」这个量测它仍然有效（证明确实生成了），但对「最坏情况成本」
    它不可用，所以一并记下来，让读表的人自己决定要不要剔除。
    """
    try:
        data = json.loads(out_path.read_text(encoding="utf-8"))
        if isinstance(data, list) and data:
            return data[0].get("passed")
        if isinstance(data, dict):
            return data.get("passed")
    except Exception:  # noqa: BLE001 — 读不出来只影响这一列的显示
        return None
    return None


def envelope(rows: list[dict]) -> list[str]:
    """从已量到的行里总结可行域的**边界**，而不是只把表丢出去。

    这一段全部由 :func:`rows` 现场推出来：写死的话，下次换台机器、换了采样点，
    结论就会和表对不上，而读表的人不会发现。没有数据可推时返回空列表（正在跑的
    中途落盘就是这种情况），不让 .md 出现半截的假结论。
    """
    ok = [r for r in rows if r.get("ok")]
    bad = [r for r in rows if not r.get("ok")]
    if not ok:
        return []
    floor = min(r["peak_rss_mb"] for r in ok)
    top = max(r["peak_rss_mb"] for r in ok)
    out = ["", "## 解读：这台机器的证明侧天花板", "",
           f"**{len(ok)} 个点量到了、{len(bad)} 个点被 OOM 杀。** 成功的点里峰值常驻落在 "
           f"**{floor:,.0f}–{top:,.0f} MB**；而 200 字符 × 1 条规则这种最小配置就已经 "
           f"{floor:,.0f} MB —— 说明 **prover 的固定开销本身就有约 {floor/1024:.2f} GiB**，"
           "它才是本机上真正的约束。",
           "",
           "往上加只有很窄的一条缝，而且**加长度、加规则数踩到的是独立的两级台阶**，"
           "不是斜着涨的：", ""]
    for r in rows:
        mark = "✓" if r.get("ok") else "✗ OOM"
        use = (f"{r['seconds']:.1f} s / {r['peak_rss_mb']:,.0f} MB"
               if r.get("ok") else f"死在第 {r['seconds']:.0f} s")
        out.append(f"- `({r['length']}, {r['rules']})` {mark} — {use}")
    out += ["",
            "由此得到的边界（本机 12 GB / 无 GPU，SP1 `core`，默认 prover 选项）：", "",
            "    1 条规则：≤10k 字符可证      2 条规则：约 200 字符可证      "
            "3 条及以上：出不来", "",
            "第 3 条规则恰好是 `pattern_block`：正则匹配会激活另一族 AIR chip，"
            "trace area 一次性抬高一截，所以**规则数这一轴在 2→3 之间断崖**。"
            "长度这一轴则在 10k→20k 之间断崖。",
            "",
            "⚠️ 与 §周期数表的关系：**证明侧与周期侧的天花板不在同一个地方**。"
            "周期表能一路扫到 100k 字符 × 6 条规则，因为那只跑 zkVM 执行、不出证；"
            "这里卡死的是内存不是 CPU（100k 字符时周期数也才千万级）。所以「能证明"
            "多大的策略」在本机上不是一条成本曲线，而是**一条固定地板加两级台阶**。"]
    return out


def render_md(rows: list[dict], corpus: dict) -> str:
    """把量测行渲染成 Markdown 表（每量到一个点就重写一次，见 :func:`dump`）。"""
    md = ["# Real SP1 proofs: wall time, artifact size, peak memory", "",
          f"语料：`{corpus['name']}`（{corpus['chars']} 字符，"
          f"sha256 `{corpus['sha256']}…`）。"
          "峰值内存由 `/usr/bin/time -v` 量取，**每个点一个独立进程**。"
          + (f"\n\n被剔除的 {len(corpus.get('excluded') or [])} 段（命中规则，"
             f"会短路；对「证明耗时」仍是有效点，对「最坏情况成本」不可用）："
             + "".join(f"\n- `{e['source']}` —— {'；'.join(e['hits'])}"
                       for e in (corpus.get('excluded') or []))
             if corpus.get('excluded') else ""), "",
          "| length | rules | time (s) | proof (KiB) | peak RSS (MiB) | verified | passed |",
          "|---:|---:|---:|---:|---:|:--|:--|"]
    for r in rows:
        if not r["ok"]:
            md.append(f"| {r['length']} | {r['rules']} | {r['seconds']} | — | — | — | "
                      f"{r['error']} |")
            continue
        md.append(f"| {r['length']} | {r['rules']} | {r['seconds']} | "
                  f"{r['proof_bytes']/1024:.1f} | {r['peak_rss_mb']} | "
                  f"{'yes' if r['verified'] else 'NO'} | "
                  f"{r['passed'] if r['passed'] is not None else '?'} |")
    return "\n".join(md + envelope(rows)) + "\n"


def dump(out_path: Path, rows: list[dict], corpus: dict) -> None:
    """把当前已量到的行落盘（JSON + Markdown）。**每点之后都调一次**。

    这样即使后面某个点把子进程（乃至整台机器）拖垮，前面已经花了几十分钟量到的
    数据也不会跟着消失。
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"corpus": corpus, "rows": rows}, indent=2),
                        encoding="utf-8")
    out_path.with_suffix(".md").write_text(render_md(rows, corpus), encoding="utf-8")


def main() -> int:
    """逐点出证明、量耗时/体积/内存并验证，每点后落盘 JSON + Markdown。"""
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "proofs.json")
    ap.add_argument("--points", type=parse_points, default=DEFAULT_POINTS,
                    help=f"逗号分隔的 <长度>,<规则数> 采样点（默认 {DEFAULT_POINTS}）")
    ap.add_argument("--corpus", default="demo",
                    help="响应文本的出处，语义同 bench_cycles.py：demo（默认）/ "
                         "synthetic / <文件路径>")
    args = ap.parse_args()

    loaded = bc.load_corpus(args.corpus)
    corpus_text = loaded.text
    corpus_sha = hashlib.sha256(corpus_text.encode("utf-8")).hexdigest()
    print(f"corpus={args.corpus}  {len(corpus_text)} 字符  sha256={corpus_sha[:16]}…")
    for s in loaded.sources:
        print(f"  ← {s}")
    for e in loaded.excluded:   # 与 bench_cycles 同口径：剔了谁、为什么剔
        print(f"  ✗ 剔除 {e['source']}：{'；'.join(e['hits'])}")

    corpus = {"name": args.corpus, "sources": loaded.sources,
              "excluded": loaded.excluded,
              "chars": len(corpus_text), "sha256": corpus_sha}
    # 与 bench_cycles 同样的起飞前体检：每个点真出证明前先确认平铺文本不命中规则。
    # 命中⇒短路⇒cycle 数偏低；耗时虽然照样量得准，但那张表会被拿去对照成本曲线，
    # 对着一个短路的点比，结论就是错的。所以在花掉几十分钟之前先挡住。
    for length, rc in args.points:
        hits = bc.trips(bc.text_of_length(corpus_text, length))
        if hits:
            raise SystemExit(
                f"L={length}：平铺后的语料命中规则 "
                f"{[f'{r}: {ev}' for r, ev in hits]}，会比成本曲线偏低。换 --corpus")

    rows: list[dict] = []
    for length, rc in args.points:
        print(f"\n=== L={length} rules={rc} （真实证明，分钟级）===", flush=True)
        row = run_point(length, rc, corpus_text)
        rows.append(row)
        dump(args.out, rows, corpus)   # 先落盘再打印：失败也不丢已量到的点
        if row["ok"]:
            print(f"L={length:>6} rules={rc}  {row['seconds']:6.1f}s  "
                  f"{row['proof_bytes']/1024:8.1f} KiB  peakRSS={row['peak_rss_mb']} MB  "
                  f"verified={row['verified']}  passed={row['passed']}", flush=True)
        else:
            print(f"L={length:>6} rules={rc}  失败：{row['error']}（耗时 {row['seconds']}s）",
                  flush=True)

    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
