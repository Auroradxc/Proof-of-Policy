#!/usr/bin/env python3
"""T3：真实 SP1 证明的**全量**回归 —— 出证 + 验证两条腿，按次留痕。

**它为什么存在**：`plan-p0p1p2.md` 的待办 T3 —— 「真实 SP1 证明的**全量**回归改为
『**出证 + 验证**两条腿都在 **CI 之外**定期跑」」，阻塞的是**论文 §7 的证明时间/
内存数字**。45 分钟一次进不了 CI，所以它是个**挂定时器**的东西，不是 CI 任务。

**它不重写出证/比对逻辑**。仓库里已经有三条腿，各归各的：

    出证腿 + golden 比对   scripts/prove/cross_validate.py     ← 向量表与判定比对的唯一出处
    耗时/体积/峰值 RSS     bench/bench_proofs.py         ← 量测口径的唯一出处
    验证已存盘的证明       bench/bench_verify.py         ← 同上

缺的从来不是某一条腿，而是**把两条腿串起来、按次留痕、能判成败**的那一层。
所以本文件只做**编排**：出证腿直接子进程调 `cross_validate.py`（它的向量表、
golden、分块逻辑一律不动，免得两处漂移），验证腿另起进程跑 `pop-script --verify`。

**为什么要留痕、且为什么必须只追加**：`cross_validate.py` 每次**覆盖**
`results_prove.json`，跑完就没了上一次 —— 那样「这次比上次慢了多少」无从谈起，
论文里的数字也指不回具体的某一次运行。所以本文件把每次运行**追加**进
``bench/results/regression-prove.jsonl``，一行一次，**永不覆盖、永不改写历史**。

**验证腿为什么是新进程**：出证进程此时**已经退出**，验证方手里只剩产物 + ELF。
这才是「第二条腿」的意思 —— 同进程里出证后顺手 `client.verify(...)` 是同一个
证明器在自证（`main.rs:417` 那处就有这么一次），不算独立验证。

**验证腿只覆盖 1 个向量**（记录里写在 ``verify_leg.note``，不装作全量）：它要证的
是「这份产物**换个人也能验**」这条**路径**没坏。19 份证明 ≈ 1 GiB 且要再跑 19 次
vkey setup，性价比不对。

**可测性**：``--pop-script`` 可注入**替身驱动**，因此本文件的全部逻辑（追加不覆盖 /
成败判定 / 留痕字段）在**没有 Rust 工具链**的机器上也能被单测覆盖，见
``tests/test_regression_prove.py``。

用法：
  SP1_PROVER=cpu python3 scripts/prove/regression_prove.py                 # 全量，≈45 min
  SP1_PROVER=cpu python3 scripts/prove/regression_prove.py --label nightly # 给这次运行起名
  python3 scripts/prove/regression_prove.py --print                        # 只看历史摘要
  python3 scripts/prove/regression_prove.py --history /tmp/r.jsonl --pop-script ./fake

**CI 之外定期跑**（这是 T3 的原话；45 min 不要塞进 CI）。每周一 04:17 跑一次：

    # crontab -e
    17 4 * * 1  cd /path/to/zk-policy && SP1_PROVER=cpu /usr/bin/python3 \\
                scripts/prove/regression_prove.py --label weekly \\
                >> bench/results/regression-prove.cron.log 2>&1

或 systemd（更推荐，能和别的重活排队、有日志、失败可查）：

    # ~/.config/systemd/user/pop-regression.service
    [Service]
    Type=oneshot
    WorkingDirectory=/path/to/zk-policy
    Environment=SP1_PROVER=cpu
    ExecStart=/usr/bin/python3 scripts/prove/regression_prove.py --label weekly
    # ~/.config/systemd/user/pop-regression.timer
    [Timer]
    OnCalendar=Mon 04:17
    Persistent=true            # 机器当时关着，开机后补跑

退出码：任一条腿 FAIL → 非 0（定时器据此判成败）。**OOM 被杀也算 FAIL** ——
本机 12 GB、SP1 core 证明的固定地板 ~10.15 GiB，被杀是**结论**（这台机器证不了
这么多），不是「没跑成」，不能被静默吞掉。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/（_bootstrap 所在）
from _bootstrap import REPO, bootstrap  # noqa: E402

bootstrap()

sys.path.insert(0, str(REPO / "bench"))  # bench_proofs 在 bench/ 下，不属于 scripts 的 5 组

import bench_proofs  # noqa: E402  —— 硬件记录（host_info）的唯一出处
import cross_validate as cv  # noqa: E402  —— 向量表与 golden 比对的唯一出处
from policydsl.evidence.cert import sha256_file, utc_now  # noqa: E402
from policydsl.paths import POP_SCRIPT as DEFAULT_POP  # noqa: E402  驱动路径的唯一出处
from policydsl.core.compile import compile_policy  # noqa: E402
from policydsl.core.serialize import spec_canonical_text  # noqa: E402

DEFAULT_HISTORY = REPO / "bench" / "results" / "regression-prove.jsonl"

#: ``/usr/bin/time -v`` 是拿峰值 RSS 的唯一可靠途径；没有它就不测内存，如实记 None。
TIME_BIN = "/usr/bin/time" if Path("/usr/bin/time").exists() else None

#: ``cross_validate`` 末行。这里解析它而不是复算结论 —— 复算就是第二处事实来源。
RESULT_RE = re.compile(r"^RESULT:\s+host\s+(\d+)/(\d+)\s+prove\s+(\S+)\s+(PASS|FAIL)\s*$", re.M)
MAX_RSS_RE = re.compile(r"Maximum resident set size \(kbytes\):\s*(\d+)")
#: ``time -v`` 那份报告的起始行。
TIME_BLOCK_RE = re.compile(r"^\tCommand being timed:.*$", re.M)
#: ``time`` 在子进程被信号杀死时打的那一行（在报告之前）。
SIGNAL_RE = re.compile(r"^Command terminated by signal (\d+)\s*$", re.M)

#: 记进历史的日志尾巴长度 —— 定时跑时终端早没了，证据得跟在记录里。
LOG_TAIL_LINES = 30
LOG_TAIL_CHARS = 6000


# --------------------------------------------------------------------------
# 留痕
# --------------------------------------------------------------------------

def strip_time_report(stderr: str) -> str:
    """去掉 ``time -v`` 那份 ~20 行的样板报告。

    **为什么非去不可**：``time`` 的报告打在**子进程输出之后**，而 ``tail()`` 取的是
    末尾 —— 不去掉的话，一次 OOM 的记录里留的是 20 行
    「Average resident set size / Page size / Exit status」，而**解释原因的那段
    Python traceback 被挤掉**。恰恰最需要证据的那种失败，证据最看不见。

    丢掉的是样板，不是信息：峰值 RSS 与信号都已单独解析成结构字段。
    """
    m = TIME_BLOCK_RE.search(stderr)
    return stderr[:m.start()] if m else stderr


def tail(text: str, lines: int = LOG_TAIL_LINES, chars: int = LOG_TAIL_CHARS) -> str:
    """取日志末尾若干行（再截总长）。历史记录里要能看出**为什么失败**。"""
    rows = [ln for ln in text.splitlines() if ln.strip()][-lines:]
    out = "\n".join(rows)
    return out[-chars:]


def append_history(path: Path, record: dict) -> None:
    """把一次运行**追加**成一行 JSON。只追加 —— 历史不可改写是本文件的核心承诺。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")


def read_history(path: Path) -> list[dict]:
    """读回历史；文件不存在或某行坏掉都不该让 `--print` 崩掉。"""
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for ln in p.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            out.append({"result": "UNREADABLE", "raw": ln[:200]})
    return out


# --------------------------------------------------------------------------
# 运行环境指纹
# --------------------------------------------------------------------------

def git_info() -> dict:
    """这次跑的是哪份源码。``dirty`` 一并记 —— 带未提交改动的数字不能当基线。"""
    def _g(*args: str) -> str:
        try:
            p = subprocess.run(["git", *args], cwd=str(REPO),
                               capture_output=True, text=True)
        except OSError:
            return ""
        return p.stdout.strip() if p.returncode == 0 else ""
    sha = _g("rev-parse", "HEAD")
    return {"sha": sha or None, "dirty": bool(_g("status", "--porcelain")),
            "branch": _g("rev-parse", "--abbrev-ref", "HEAD") or None}


def driver_fingerprint(pop_script: Path) -> dict:
    """证明器**二进制**的指纹。

    只记 git sha 是不够的：``circuits/target/release/pop-script`` 是构建产物，
    完全可能比源码旧（改完 Rust 没重编）。不记二进制摘要，「这批数字出自哪份驱动」
    就答不上来，而回归的全部价值就在于这个问题的答案。
    """
    p = Path(pop_script)
    if not p.exists():
        return {"path": str(p), "exists": False}
    try:
        digest = sha256_file(p)
        st = p.stat()
    except OSError as exc:
        return {"path": str(p), "exists": True, "error": str(exc)}
    return {"path": str(p), "exists": True, "sha256": digest,
            "bytes": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()}


# --------------------------------------------------------------------------
# 出证腿
# --------------------------------------------------------------------------

def run_prove_leg(pop_script: Path | None, chunk: int, work_dir: Path,
                  timeout: float | None = None) -> dict:
    """子进程调 ``cross_validate.py`` 跑全部向量，解析它末行的 ``RESULT:``。

    **不在这里复算判定** —— 向量表、golden、分块都在 ``cross_validate`` 里，
    再算一遍就是第二处事实来源，两处迟早不一致。这里只负责「跑、计时、判成败」。
    """
    cmd = [sys.executable, str(REPO / "scripts" / "prove" / "cross_validate.py"),
           "--chunk", str(chunk), "--work-dir", str(work_dir)]
    if TIME_BIN:
        cmd = [TIME_BIN, "-v"] + cmd
    env = dict(os.environ, SP1_PROVER="cpu")
    if pop_script is not None:
        env["POP_SCRIPT"] = str(pop_script)

    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=str(REPO), env=env, capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "seconds": round(time.time() - t0, 1),
                "reason": f"超时（>{timeout}s）",
                "log_tail": tail((exc.stderr or b"").decode("utf-8", "replace")
                                 if isinstance(exc.stderr, bytes) else (exc.stderr or ""))}
    secs = round(time.time() - t0, 1)

    # 峰值 RSS 与信号都从**完整** stderr 上解析（它们在 time 的样板里），
    # 留证据的 log_tail 则用去掉样板后的版本 —— 见 `strip_time_report`。
    leg: dict = {"seconds": secs, "returncode": p.returncode,
                 "log_tail": tail(strip_time_report(p.stderr))}
    rss = MAX_RSS_RE.search(p.stderr)
    if rss:
        leg["peak_rss_mb"] = round(int(rss.group(1)) / 1024)
    sig = SIGNAL_RE.search(p.stderr)
    if sig:
        leg["signal"] = int(sig.group(1))

    m = RESULT_RE.search(p.stdout)
    if not m:
        # 没有末行 = 没跑到底。**这正是要记下来的失败，不是「没跑」**：本机 12 GB
        # 上 SP1 core 证明的固定地板 ~10.15 GiB，证不完就是这台机器的**结论**。
        why = "进程被信号杀死" if "signal" in leg else "进程崩溃或被杀"
        leg.update(ok=False,
                   reason=f"末行没有 RESULT: —— {why}（OOM 是本机最常见的死法）")
        return leg
    host_ok, host_total, prove_txt, verdict = m.groups()
    leg.update(host_matched=int(host_ok), host_total=int(host_total),
               prove=prove_txt, ok=(p.returncode == 0 and verdict == "PASS"))
    if not leg["ok"]:
        leg["reason"] = f"cross_validate 判 {verdict}（退出码 {p.returncode}）"
    return leg


# --------------------------------------------------------------------------
# 验证腿
# --------------------------------------------------------------------------

def run_verify_leg(pop_script: Path, work_dir: Path,
                   timeout: float | None = None) -> dict:
    """对**一个**向量出证并落盘，再**另起进程**验证它。

    ``--proof-out`` 只支持单向量（``circuits/script/src/main.rs`` 会 panic），
    所以这里自己造一份单向量输入 —— 但**向量本身仍取自 ``cross_validate.vectors()``**，
    不另编一条。
    """
    name, policy, response, extras = cv.vectors()[0]
    spec = compile_policy(policy)
    entry = {"name": name, "response": response,
             "spec_canonical": spec_canonical_text(spec)}
    entry.update(extras or {})

    vpath = work_dir / "verify-vector.json"
    proof = work_dir / "verify-proof.bin"
    r_prove = work_dir / "verify-prove-result.json"
    r_verify = work_dir / "verify-result.json"
    vpath.write_text(json.dumps({"vectors": [entry]}, indent=2), encoding="utf-8")

    env = dict(os.environ, SP1_PROVER="cpu")
    note = (f"只覆盖 1 个向量（{name}）：验证腿要证的是「这份产物换个人也能验」"
            f"这条**路径**没坏，不是把 {len(cv.vectors())} 份再验一遍")
    t0 = time.time()
    try:
        p1 = subprocess.run([str(pop_script), "--vectors", str(vpath),
                             "--out", str(r_prove), "--proof-out", str(proof)],
                            cwd=str(REPO), env=env, capture_output=True,
                            text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "seconds": round(time.time() - t0, 1), "vector": name,
                "note": note, "reason": f"出证超时（>{timeout}s）"}
    if p1.returncode != 0 or not proof.exists():
        return {"ok": False, "seconds": round(time.time() - t0, 1), "vector": name,
                "note": note, "returncode": p1.returncode,
                "reason": "验证腿的单向量出证失败（没有产物可验）",
                "log_tail": tail(p1.stderr)}

    # ——— 到这里出证进程已经退出，下面是**独立**的一次验证 ———
    try:
        p2 = subprocess.run([str(pop_script), "--verify", "--proof", str(proof),
                             "--out", str(r_verify)],
                            cwd=str(REPO), env=env, capture_output=True,
                            text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "seconds": round(time.time() - t0, 1), "vector": name,
                "note": note, "reason": f"验证超时（>{timeout}s）"}
    secs = round(time.time() - t0, 1)
    leg: dict = {"seconds": secs, "vector": name, "note": note,
                 "proof_bytes": proof.stat().st_size,
                 "returncode": p2.returncode, "log_tail": tail(p2.stderr)}
    if p2.returncode != 0:
        leg.update(ok=False, reason="pop-script --verify 非零退出（验证失败或加载不了证明）")
        return leg
    try:
        v = json.loads(r_verify.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        leg.update(ok=False, reason=f"读不回验证结果：{exc}")
        return leg
    leg.update(ok=bool(v.get("verified")), vkey_hash=v.get("vkey_hash"),
               setup_seconds=v.get("setup_seconds"),
               verify_times_seconds=v.get("verify_times_seconds"))
    if not leg["ok"]:
        leg["reason"] = "验证结果是 verified=false"
    return leg


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def one_run(args: argparse.Namespace) -> dict:
    """跑一次完整回归并返回**留痕用的那条记录**（不负责写盘，便于单测直接看）。"""
    pop_script = Path(args.pop_script) if args.pop_script else DEFAULT_POP
    work_dir = Path(args.work_dir) if args.work_dir else Path(
        tempfile.mkdtemp(prefix="pop-regression-"))
    work_dir.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    prove = run_prove_leg(pop_script, args.chunk, work_dir, args.timeout)
    verify = None
    if not args.no_verify:
        verify = (run_verify_leg(pop_script, work_dir, args.timeout)
                  if prove.get("ok") else
                  {"ok": False, "skipped": True,
                   "reason": "出证腿未通过，跳过验证腿（没有可信的产物可验）"})

    record = {
        "ts": utc_now(),
        "label": args.label,
        "git": git_info(),
        "host": bench_proofs.host_info(),
        "driver": driver_fingerprint(pop_script),
        "chunk": args.chunk,
        "vectors": len(cv.vectors()),
        "prove_leg": prove,
        "verify_leg": verify,
        "seconds": round(time.time() - t0, 1),
        "result": "PASS" if (prove.get("ok") and (verify is None or verify.get("ok"))
                             ) else "FAIL",
    }
    if args.keep_work_dir:
        record["work_dir"] = str(work_dir)
    return record


def summarize(record: dict) -> str:
    """一条记录 → 一行给人看的话。"""
    pg, vg = record["prove_leg"], record.get("verify_leg") or {}
    bits = [f"出证 {'OK' if pg.get('ok') else 'FAIL'}"
            f"({pg.get('prove', '?')}) {pg.get('seconds', '?')}s"]
    if pg.get("peak_rss_mb"):
        bits.append(f"峰值 {pg['peak_rss_mb']:,} MB")
    if record.get("verify_leg") is None:
        bits.append("验证 未跑")
    else:
        bits.append(f"验证 {'OK' if vg.get('ok') else 'FAIL'}"
                    f"({vg.get('vector', '?')}) {vg.get('seconds', '?')}s")
    return f"[{record['result']}] {' · '.join(bits)}"


def print_history(path: Path) -> None:
    """打印历史摘要 —— 定期跑的东西必须能一眼看出「最近几次怎么样」。"""
    rows = read_history(path)
    if not rows:
        print(f"（{path} 还没有任何记录）")
        return
    print(f"{len(rows)} 次运行，来自 {path}\n")
    for r in rows:
        git = r.get("git") or {}
        sha = (git.get("sha") or "?")[:8]
        dirty = "+dirty" if git.get("dirty") else ""
        print(f"  {r.get('ts', '?'):<25} {summarize(r) if 'prove_leg' in r else '本次记录不可读'}"
              f"  [{sha}{dirty}] {r.get('label') or ''}")
    passes = sum(1 for r in rows if r.get("result") == "PASS")
    print(f"\n合计 {passes}/{len(rows)} PASS")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="T3：真实 SP1 证明的全量回归（出证 + 验证两条腿），按次留痕。")
    ap.add_argument("--pop-script", help=f"证明器驱动（缺省 {DEFAULT_POP}）；单测用它注入替身")
    ap.add_argument("--chunk", type=int, default=2,
                    help="出证腿每进程的向量数（缺省 2，即 T3 记的 45 min 口径）；"
                         "0 = 单进程，需 ≥16 GB")
    ap.add_argument("--history", type=Path, default=DEFAULT_HISTORY,
                    help=f"历史文件，只追加（缺省 {DEFAULT_HISTORY}）")
    ap.add_argument("--work-dir", help="中间产物目录（缺省：每次新建临时目录）")
    ap.add_argument("--keep-work-dir", action="store_true",
                    help="保留中间产物目录并把路径记进历史（排查用）")
    ap.add_argument("--label", help="给这次运行起个名（如 nightly / pre-paper-v2）")
    ap.add_argument("--no-verify", action="store_true", help="只跑出证腿，跳过验证腿")
    ap.add_argument("--timeout", type=float, default=None,
                    help="每条腿的超时秒数（缺省不限；定时任务建议给一个）")
    ap.add_argument("--print", dest="do_print", action="store_true",
                    help="只打印历史摘要，不跑回归")
    ap.add_argument("--dry-run", action="store_true",
                    help="不写历史文件，只把这次记录打到 stdout")
    args = ap.parse_args(argv)

    if args.do_print:
        print_history(args.history)
        return 0

    pop_script = Path(args.pop_script) if args.pop_script else DEFAULT_POP
    # 显式给了一个不存在的路径也算错，且要在**跑之前**报 —— 否则要等 45 分钟
    # 才在失败记录里发现路径打错了。
    if not pop_script.exists():
        print(f"error: 证明器驱动不存在：{pop_script}\n"
              f"  请先构建：cd circuits && cargo build --release -p pop-script\n"
              f"  （或用 --pop-script 指定驱动）", file=sys.stderr)
        return 2

    print(f"driver: {pop_script}")
    print(f"chunk={args.chunk}  vectors={len(cv.vectors())}  "
          f"history={args.history}")
    print(f"预计 {len(cv.vectors())} 个向量的真实证明，本机（12 GB）≈ 45 min\n"
          f"--- 出证腿：cross_validate.py（全量 + golden 比对）---", flush=True)

    record = one_run(args)
    print(f"\n--- 结果 ---\n{summarize(record)}")
    for leg_name in ("prove_leg", "verify_leg"):
        leg = record.get(leg_name)
        if leg and not leg.get("ok"):
            print(f"  {leg_name} 失败原因：{leg.get('reason')}")

    if args.dry_run:
        print("\n（--dry-run：未写历史文件）")
    else:
        append_history(args.history, record)
        print(f"\n已追加到 {args.history}（历史只追加，不覆盖）")
    return 0 if record["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
