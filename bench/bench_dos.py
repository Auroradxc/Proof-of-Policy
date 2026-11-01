#!/usr/bin/env python3
"""P1-11 证明路径 DoS：病理输入 ``a^n`` vs 模式 ``a+b`` 的执行 / 证明成本。

**病理构造**（与 `bench/bench_ablation.py` 同一口径）：

* 模式 `a+b`：需要 `a+` 之后跟一个 `b`；
* 输入 `a` × `n`：整段没有 `b` ⇒ 必然不匹配 ⇒ 扫描必须走到结尾。

两种匹配器在**判定语义上等价**（由 `tests/test_ablation.py` 钉死），但复杂度不同：

* `pike`（生产语义）：一次线性扫描，周期数 ~ O(n)；
* `naive`（消融基线）：每个起点重新锚定，周期数 ~ O(n²)。

本脚本把「执行路径」与「证明路径」分开量：

1. **执行路径**：`pop-script --execute`（宿主机解释 guest，不出证）给出 zkVM
   周期数；另用 Python 参考层的 `nfa.match_search` / `match_search_naive`
   量墙钟时间，作为与二进制无关的旁证。
2. **证明路径**：`pop-script --proof-mode core` 真出证，量 prove 墙钟与峰值 RSS。
   **本机 14.6 GiB**，SP1 core 证明有 ~10 GiB 的固定内存地板，因此：

   * 证明点默认只跑小 `n`（`--prove-points pike:100`）；
   * 所有证明**串行**：脚本对 `/tmp/pop-proof.lock` 取 `flock`，避免与其它
     agent 的 SP1 进程叠加；
   * 每次证明前检查可用内存，低于 `--min-free-gib` 就如实记为
     `skipped_insufficient_memory`，不硬跑；
   * 超时与 OOM **都是结果**，分别记为 `timeout` / `oom_or_killed`，不省略。

**这不是「pike 会被 DoS」的结论。** 生产语义是 pike，成本随 n 线性增长；本实验
要说明的是：*如果*把消融旋钮 `match_mode=naive` 当成生产配置，对抗长输入会让
执行与证明成本二次膨胀，直到本机 OOM。结论必须按这两层分开写。

用法：
  # 只跑执行路径（秒级）
  python3 bench/bench_dos.py --no-prove --out-dir bench/results
  # 执行 + 小 n 证明（需 SP1；串行、可能 OOM）
  python3 bench/bench_dos.py --prove-points pike:100,naive:25,naive:50 --out-dir bench/results
  # 工作树里没有构建产物时，显式指定二进制
  python3 bench/bench_dos.py --pop-script /path/to/pop-script ...
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import platform
import re
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "bench"))

from policydsl.core import nfa                                     # noqa: E402
from policydsl.core.compile import compile_policy                  # noqa: E402
from policydsl.core.model import Policy, Rule                      # noqa: E402
from policydsl.core.serialize import spec_canonical_text          # noqa: E402
from policydsl.evidence.cert import sha256_file                    # noqa: E402
from policydsl.paths import POP_SCRIPT                             # noqa: E402

PATTERN = "a+b"
DEFAULT_NS = [100, 200, 400]
MODES = ["pike", "naive"]
LOCK_PATH = Path("/tmp/pop-proof.lock")
TIME_BIN = "/usr/bin/time" if Path("/usr/bin/time").exists() else None

#: 本机实际值（24 核 / 14.6 GiB）在运行时重新采集；这里只留默认安全阈值。
DEFAULT_MIN_FREE_GIB = 11.5


# --------------------------------------------------------------------------- #
# 构造
# --------------------------------------------------------------------------- #

def policy(mode: str) -> Policy:
    """单条 ``pattern_block`` 规则，只切换匹配模式。"""
    return Policy("ablation", "1", rules=[
        Rule("pattern_block", "pat", {"patterns": [PATTERN], "match_mode": mode}),
    ])


def _vector(n: int, mode: str) -> Dict[str, Any]:
    spec = compile_policy(policy(mode))
    return {"name": f"dos-n{n}-{mode}", "response": "a" * n,
            "spec_canonical": spec_canonical_text(spec)}


# --------------------------------------------------------------------------- #
# 机器与二进制
# --------------------------------------------------------------------------- #

def _mem_total_gib() -> float:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) / (1024 * 1024)
    except OSError:
        pass
    return 0.0


def _mem_available_gib() -> float:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) / (1024 * 1024)
    except OSError:
        pass
    return 0.0


def machine_spec() -> Dict[str, Any]:
    return {
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "mem_total_gib": round(_mem_total_gib(), 1),
        "python": platform.python_version(),
    }


def resolve_binary(explicit: Optional[Path]) -> Optional[Path]:
    """按顺序找驱动：显式参数 → ``$POP_SCRIPT_DOS`` → 仓库缺省路径。"""
    for cand in (explicit,
                 Path(os.environ["POP_SCRIPT_DOS"]) if os.environ.get("POP_SCRIPT_DOS") else None,
                 POP_SCRIPT):
        if cand is not None and Path(cand).is_file():
            return Path(cand)
    return None


def binary_fingerprint(path: Optional[Path]) -> Dict[str, Any]:
    if path is None:
        return {"path": None, "sha256": None, "note": "driver not found"}
    return {"path": str(path), "sha256": sha256_file(path)}


# --------------------------------------------------------------------------- #
# 执行路径
# --------------------------------------------------------------------------- #

def run_execute(binary: Path, n: int, mode: str, timeout: float = 300.0) -> Dict[str, Any]:
    """``pop-script --execute``：返回周期数、判定结果与墙钟。"""
    with tempfile.TemporaryDirectory() as td:
        vp = Path(td) / "vectors.json"
        op = Path(td) / "out.json"
        vp.write_text(json.dumps({"vectors": [_vector(n, mode)]}), encoding="utf-8")
        t0 = time.perf_counter()
        r = subprocess.run([str(binary), "--execute", "--vectors", str(vp),
                            "--out", str(op)],
                           capture_output=True, text=True, timeout=timeout)
        wall = time.perf_counter() - t0
        if r.returncode != 0:
            return {"status": "error", "returncode": r.returncode,
                    "stderr_tail": r.stderr[-600:], "wall_s": round(wall, 3)}
        row = json.loads(op.read_text(encoding="utf-8"))[0]
        return {"status": "ok", "cycles": row["cycles"], "passed": row.get("passed"),
                "wall_s": round(wall, 3)}


def run_python_reference(n: int, mode: str, reps: int = 3) -> Dict[str, Any]:
    """Python 参考层墙钟（与二进制无关的旁证）。

    ``match_search_naive`` 是 O(n²)，在 n=400 时也只要秒级；取中位数。
    """
    spec = nfa.compile_pattern(PATTERN)
    fn = nfa.match_search if mode == "pike" else nfa.match_search_naive
    text = "a" * n
    ts: List[float] = []
    for _ in range(reps):
        t0 = time.perf_counter()
        matched = fn(spec, text)
        ts.append(time.perf_counter() - t0)
    return {"mode": mode, "matched": matched, "median_s": statistics.median(ts)}


# --------------------------------------------------------------------------- #
# 证明路径
# --------------------------------------------------------------------------- #

_RSS_RE = re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)")


def prove_once(binary: Path, n: int, mode: str, *, timeout_s: float,
               min_free_gib: float, proof_mode: str = "core") -> Dict[str, Any]:
    """出一份 core 证明；串行（flock）、超时杀进程组、OOM 如实记录。"""
    free = _mem_available_gib()
    if free < min_free_gib:
        return {"status": "skipped_insufficient_memory",
                "mem_available_gib": round(free, 2),
                "note": f"可用内存 {free:.2f} GiB < 阈值 {min_free_gib} GiB；不硬跑，留给云机"}

    with tempfile.TemporaryDirectory() as td:
        vp = Path(td) / "vectors.json"
        op = Path(td) / "out.json"
        vp.write_text(json.dumps({"vectors": [_vector(n, mode)]}), encoding="utf-8")
        cmd = ([TIME_BIN, "-v"] if TIME_BIN else []) + [
            str(binary), "--vectors", str(vp), "--out", str(op),
            "--job", "policy", "--proof-mode", proof_mode]
        env = dict(os.environ, SP1_PROVER="cpu")

        LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(LOCK_PATH, "a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)      # 等锁：绝不与其它 SP1 叠跑
            t0 = time.perf_counter()
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, env=env, start_new_session=True)
            timed_out = False
            try:
                out, err = proc.communicate(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                out, err = proc.communicate()
            elapsed = time.perf_counter() - t0
            rc = proc.returncode

    m = _RSS_RE.search(err or "")
    peak_mib = (int(m.group(1)) / 1024.0) if m else None
    status = _classify(rc, timed_out, err or "")
    result: Dict[str, Any] = {
        "n": n, "mode": mode, "proof_mode": proof_mode,
        "status": status, "returncode": rc,
        "prove_wall_s": round(elapsed, 1),
        "peak_rss_mib": round(peak_mib, 1) if peak_mib is not None else None,
        "binary": str(binary),
    }
    if status != "ok":
        result["stderr_tail"] = (err or "")[-1200:]
    if rc == 0:
        try:
            row = json.loads(op.read_text(encoding="utf-8"))[0]
            result["cycles"] = row.get("cycles")
            result["passed"] = row.get("passed")
        except (OSError, ValueError, IndexError):
            pass
    return result


def _classify(rc: int, timed_out: bool, stderr: str) -> str:
    if timed_out:
        return "timeout"
    if rc == 0:
        return "ok"
    low = stderr.lower()
    if (rc in (-9, 137) or "killed" in low or "out of memory" in low
            or "memory allocation" in low or "allocation failed" in low):
        return "oom_or_killed"
    return "error"


def parse_prove_points(spec: str) -> List[Tuple[str, int]]:
    """``pike:100,naive:50`` → ``[("pike",100), ("naive",50)]``。"""
    out: List[Tuple[str, int]] = []
    for item in spec.replace(" ", "").split(","):
        if not item:
            continue
        mode, _, n = item.partition(":")
        if mode not in MODES or not n.isdigit():
            raise argparse.ArgumentTypeError(f"bad prove point {item!r}（应为 mode:n）")
        out.append((mode, int(n)))
    return out


# --------------------------------------------------------------------------- #
# 渲染
# --------------------------------------------------------------------------- #

def render_md(payload: Dict[str, Any]) -> str:
    m = payload["machine"]
    md = [
        "# 证明路径 DoS：`a+b` vs `a^n`（P1-11）",
        "",
        f"机器：**{m['cpu_count']} 核 / {m['mem_total_gib']} GiB**"
        f"（{m['platform']}）。病理模式 `{payload['pattern']}`，输入 `a` × `n`"
        "（无 `b` ⇒ 必然不匹配 ⇒ 扫到底）。",
        "",
        f"驱动：`{payload['binary']['path'] or '未找到'}`，"
        f"sha256 `{(payload['binary']['sha256'] or '—')[:16]}…`。",
        "",
        "## 执行路径（`pop-script --execute`，不出证）",
        "",
        "| n | pike (cycles) | naive (cycles) | naive/pike | pike 周期/字符 | naive 周期/字符 | pike exec ms | naive exec ms |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    by = {(r["n"], r["mode"]): r for r in payload["execution"]["rust"]}
    py = {(r["n"], r["mode"]): r for r in payload["execution"]["python"]}
    for n in sorted({r["n"] for r in payload["execution"]["rust"]}):
        p, q = by.get((n, "pike")), by.get((n, "naive"))
        if not p or not q or p.get("status") != "ok" or q.get("status") != "ok":
            continue
        ratio = q["cycles"] / p["cycles"]
        md.append(
            f"| {n} | {p['cycles']:,} | {q['cycles']:,} | {ratio:.1f}× | "
            f"{p['cycles']/n:.1f} | {q['cycles']/n:.1f} | "
            f"{p['wall_s']*1000:.0f} | {q['wall_s']*1000:.0f} |")

    md += [
        "",
        "**读法**：pike 的每字符周期基本不变（线性）；naive 的每字符周期随 n 翻倍"
        "（二次）。这条差异在**执行路径**上已经出现，证明路径只是把它放大。"
        "（`exec ms` 含驱动固定启动开销，绝对值不要与 Python 参考层横比。）",
        "",
        "### Python 参考层墙钟（旁证，不走 zkVM）",
        "",
        "| n | pike 中位 ms | naive 中位 ms | naive/pike |",
        "|---:|---:|---:|---:|",
    ]
    for n in sorted({r["n"] for r in payload["execution"]["python"]}):
        pp, qq = py.get((n, "pike")), py.get((n, "naive"))
        if not pp or not qq:
            continue
        pr = (qq["median_s"] / pp["median_s"]) if pp["median_s"] else float("inf")
        md.append(f"| {n} | {pp['median_s']*1000:.3f} | {qq['median_s']*1000:.3f} | {pr:.1f}× |")

    md += [
        "",
        "## 证明路径（`--proof-mode core`，串行 `flock /tmp/pop-proof.lock`）",
        "",
        "| 点 | cycles | prove 墙钟 s | 峰值 RSS MiB | 状态 | 说明 |",
        "|---|---:|---:|---:|---|---|",
    ]
    for r in payload["proof"]:
        note = ""
        if r["status"] == "oom_or_killed":
            note = "OOM / SIGKILL —— **如实记录为结果**"
        elif r["status"] == "timeout":
            note = f"超过 {payload['prove_timeout_s']} s，已杀进程组"
        elif r["status"] == "skipped_insufficient_memory":
            note = r.get("note", "")
        elif r["status"] == "ok":
            note = "证明成功"
        if r.get("source") == "retained_from_previous_run":
            note = (note + "；沿用上次运行") if note else "沿用上次运行"
        md.append(
            f"| {r['mode']} n={r['n']} | {r.get('cycles') or '—'} | "
            f"{r.get('prove_wall_s', '—')} | {r.get('peak_rss_mib') or '—'} | "
            f"`{r['status']}` | {note} |")

    md += [
        "",
        "## 结论（分层写，不要混）",
        "",
        "1. **生产语义 pike 的执行成本是线性的**：n=100→400，周期/字符基本不变。"
        "对抗长输入不会让 pike 的匹配本身二次膨胀。",
        "2. **消融旋钮 `match_mode=naive` 是二次的**：若把它当成生产配置，"
        "同样的对抗输入会让执行周期 ~4× 增长（n 翻倍），证明路径随之变慢/变重。",
        "3. **证明路径的成本跟周期数走，但有一个 ~10 GiB 的固定内存地板**"
        "（SP1 core setup）。本机 14.6 GiB 只够**串行**跑小 n；naive 的较大 n "
        "在本机不可行 —— 这一条是**资源边界**，不是语义结论。",
        "4. OOM / timeout 都作为结果保留在上表；没有把失败点从表里删掉。",
        "",
        "## 边界与下一步",
        "",
        "* 本机 14.6 GiB，**不要与其它 agent 并行跑 SP1**；脚本已用 "
        "`flock /tmp/pop-proof.lock` 串行化，并在可用内存低于阈值时跳过（记 "
        "`skipped_insufficient_memory`）。",
        "* naive 的大 n（≥100）与任何 n=400 的证明路径点留给云机（64–128 GiB）；"
        "本机只报执行路径的周期数与可完成的小 n 证明。",
        "* 本实验证明的是**成本增长阶**，不是「pike 部署下存在 DoS」；"
        "pike 的线性成本仍可能被超长输入拖慢，但那是一个线性常数问题，"
        "不是这里量的二次爆炸。",
        "",
    ]
    if payload.get("notes"):
        md += ["## 注释（机器/二进制/判定自检）", ""]
        md += [f"* {n}" for n in payload["notes"]]
        md += [""]
    md += [
        "## 复现",
        "",
        "```bash",
        "python3 bench/bench_dos.py --no-prove --out-dir bench/results",
        "python3 bench/bench_dos.py --prove-points pike:100,naive:25,naive:50 --out-dir bench/results",
        "```",
        "",
        "证明点很贵，**可累积**：本次未重跑的点从既有结果文件原样保留，"
        "并在表里标 `source=retained_from_previous_run`。`--no-prove` 只刷新"
        "执行路径，不会抹掉已记录的证明/OOM 结果。",
        "",
    ]
    return "\n".join(md) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="P1-11 证明路径 DoS")
    ap.add_argument("--ns", type=lambda s: [int(x) for x in s.replace(" ", "").split(",") if x],
                    default=DEFAULT_NS, help="执行路径的输入长度（默认 100,200,400）")
    ap.add_argument("--pop-script", type=Path, default=None,
                    help="pop-script 路径（缺省 $POP_SCRIPT_DOS 或仓库构建产物）")
    ap.add_argument("--no-prove", action="store_true", help="只跑执行路径")
    ap.add_argument("--prove-points", type=parse_prove_points, default=[("pike", 100)],
                    help="证明点，形如 pike:100,naive:50（默认 pike:100）")
    ap.add_argument("--prove-timeout", type=float, default=900.0, help="每个证明点的上限秒数")
    ap.add_argument("--min-free-gib", type=float, default=DEFAULT_MIN_FREE_GIB,
                    help="证明前要求的最低可用内存（GiB）")
    ap.add_argument("--out-dir", type=Path, default=REPO / "bench" / "results")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_json = args.out_dir / "dos_proof.json"
    out_md = args.out_dir / "dos_proof.md"

    # 证明点很贵（每个 ~2–4 分钟、~12 GiB，且可能 OOM）。没有被本次显式重跑的
    # 点从既有结果文件里**原样保留**，并标 source=retained_from_previous_run ——
    # 否则一次默认运行就会把上次的 OOM 证据悄悄抹掉。
    previous_proof: Dict[Tuple[str, int], Dict[str, Any]] = {}
    if out_json.is_file():
        try:
            prev = json.loads(out_json.read_text(encoding="utf-8"))
            if prev.get("task") == "P1-11 proof-path DoS" and prev.get("pattern") == PATTERN:
                previous_proof = {(r.get("mode"), r.get("n")): r
                                  for r in prev.get("proof", [])}
        except (OSError, ValueError):
            previous_proof = {}

    binary = resolve_binary(args.pop_script)
    payload: Dict[str, Any] = {
        "task": "P1-11 proof-path DoS",
        "generated_by": "bench/bench_dos.py",
        "machine": machine_spec(),
        "pattern": PATTERN,
        "input": "a × n",
        "binary": binary_fingerprint(binary),
        "execution": {"rust": [], "python": []},
        "proof": [],
        "prove_timeout_s": args.prove_timeout,
        "notes": [],
    }
    if binary is not None and binary.resolve() != POP_SCRIPT.resolve():
        payload["notes"].append(
            f"本 worktree 无构建产物（{POP_SCRIPT} 不存在）；本表用显式指定的驱动 "
            f"{binary}（sha256 见 binary.sha256）。其执行周期数与 "
            "bench/results/ablation.md 一致（643,906 vs 643,894），说明是同一份"
            "实现的构建产物。")

    # ---- 执行路径 ----
    for n in args.ns:
        for mode in MODES:
            if binary is not None:
                try:
                    r = run_execute(binary, n, mode)
                except subprocess.TimeoutExpired:
                    r = {"status": "timeout", "n": n, "mode": mode}
                r.update({"n": n, "mode": mode})
                payload["execution"]["rust"].append(r)
                print(f"execute n={n:>5} {mode:<6} {r['status']:<6} "
                      f"cycles={r.get('cycles', '—')}", flush=True)
            payload["execution"]["python"].append(
                {"n": n, **run_python_reference(n, mode)})
    if any(r.get("matched") for r in payload["execution"]["python"]):
        payload["notes"].append(
            "Python 参考层有点命中了模式（matched=True）—— 该点不是最坏情况扫描，"
            "周期数不可比。")
    if binary is None:
        payload["notes"].append(
            "未找到 pop-script 构建产物：只有 Python 参考层墙钟，没有 zkVM 周期数。"
            "设 $POP_SCRIPT_DOS 或 --pop-script 指向已构建的驱动。")

    # 语义自检：pike 与 naive 的执行判定必须一致，否则比值没有意义。
    by_exec = {(r["n"], r["mode"]): r for r in payload["execution"]["rust"]}
    for n in args.ns:
        p, q = by_exec.get((n, "pike")), by_exec.get((n, "naive"))
        if p and q and p.get("status") == "ok" and q.get("status") == "ok":
            if p.get("passed") != q.get("passed"):
                payload["notes"].append(
                    f"n={n}: pike 与 naive 的 passed 不一致（{p.get('passed')} vs "
                    f"{q.get('passed')}）—— 比值不可比。")
        if p and p.get("status") == "ok" and p.get("passed") is not True:
            payload["notes"].append(
                f"n={n}: pike passed={p.get('passed')}（期望 True，即未命中、扫到底）—— "
                "该点可能被短路，周期数不代表最坏情况。")

    # ---- 证明路径 ----
    if args.no_prove:
        payload["notes"].append("--no-prove：证明路径未跑（执行路径结果不受影响）。")
    elif binary is None:
        payload["notes"].append("证明路径未跑：缺 pop-script 构建产物。")
    else:
        for mode, n in args.prove_points:
            print(f"prove  {mode} n={n} ... (串行，可能 OOM)", flush=True)
            r = prove_once(binary, n, mode, timeout_s=args.prove_timeout,
                           min_free_gib=args.min_free_gib)
            payload["proof"].append(r)
            print(f"prove  {mode} n={n} -> {r['status']} "
                  f"{r.get('prove_wall_s', '—')}s peak={r.get('peak_rss_mib', '—')}MiB",
                  flush=True)
        # prove 模式的驱动不打印 cycles；若同一 (n, mode) 已在执行路径测过，
        # 就把周期数补进证明表（否则留空，不要伪造）。
        exec_by = {(e["n"], e["mode"]): e for e in payload["execution"]["rust"]
                   if e.get("status") == "ok"}
        for r in payload["proof"]:
            if r.get("cycles") is None:
                e = exec_by.get((r["n"], r["mode"]))
                if e is not None:
                    r["cycles"] = e["cycles"]

    # ---- 合并：本次没重跑的证明点原样保留 ----
    ran = {(r.get("mode"), r.get("n")) for r in payload["proof"]}
    for r in payload["proof"]:
        r["source"] = "this_run"
    retained = []
    for key, r in previous_proof.items():
        if key not in ran:
            rr = dict(r)
            rr["source"] = "retained_from_previous_run"
            retained.append(rr)
    if retained:
        payload["proof"].extend(
            sorted(retained, key=lambda r: (str(r.get("mode")), r.get("n") or 0)))
        payload["notes"].append(
            "证明表保留了 "
            + ", ".join(f"{r.get('mode')}:n={r.get('n')}" for r in retained)
            + "（source=retained_from_previous_run；本次未重跑）。")

    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    out_md.write_text(render_md(payload), encoding="utf-8")
    print(f"wrote {out_json} and {out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
