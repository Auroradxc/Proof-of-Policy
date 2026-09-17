#!/usr/bin/env python3
"""阶段一至二交叉验证：Python golden（policydsl）vs SP1。

对每条测试向量我们：
  1. 构造一个 Policy，用 policydsl.core.evaluate 算出参考判定（即 golden；
     pattern_block 由编译后的 NFA == 契约来判定）；
  2. 把策略编译成 ConstraintSpec，并产出一个 Rust 侧 vectors.json
     （serde 外部标签枚举 Constraint：KeywordBlock / LengthBound / PatternBlock）
     供 SP1 驱动消费；
  3a. 宿主校验（快，全部向量）：pop-script --check  → pop-types::evaluate
  3b. 证明（真实证明，全部向量）：pop-script          → guest ProofOutput
  4. 断言两种模式下 passed + 违规规则集合都与 golden 一致。

**真实证明为什么要分块**（``--chunk``）：SP1 core 证明的峰值 RSS 本就 ~10.3 GB，
且**每证完一个还会缓慢累加**。在本机（11.9 GB RAM + 3 GB swap）上实测：把 14 个
向量交给**一个** ``pop-script`` 进程，会分别在第 6 / 第 7 个证明处被内核
OOM-kill（峰值 10.65 / 10.82 GB，``SIGKILL 9``）——而每次单独出证都是好的。
所以默认每 4 个向量起一个干净的进程（峰值回到 ~10.3 GB），再把结果按原序合并；
大内存机器可用 ``--chunk 0`` 恢复「一个进程跑完」。

从仓库根运行：
  SP1_PROVER=cpu python3 scripts/prove/cross_validate.py
  SP1_PROVER=cpu python3 scripts/prove/cross_validate.py --chunk 4   # 默认
  SP1_PROVER=cpu python3 scripts/prove/cross_validate.py --chunk 0   # 单进程（需 ≥16 GB）

两个**非破坏性**的口子，供 ``regression_prove.py`` 与单测使用（缺省行为不变）：

  ``POP_SCRIPT=<path>``   换掉证明器驱动。单测据此注入**替身驱动**，
                          从而不必有 Rust 工具链也能把整套流程跑完。
  ``--work-dir DIR``      换掉产物目录（``vectors.json`` / ``results_*.json``）。
                          定时回归用私有目录，免得与手工跑的那次互相覆盖
                          —— 那几个文件名是**固定**的，共用 ``scripts/`` 时
                          两次运行会踩同一批文件。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/（_bootstrap 所在）
from _bootstrap import REPO, bootstrap  # noqa: E402

bootstrap()

from policydsl.core.compile import compile_policy
from policydsl.core.evaluate import check
from policydsl.core.model import Policy, Rule, Transcript
from policydsl.core.serialize import spec_canonical_text
from policydsl.core import pii
from policydsl.evidence import trace

#: 证明器驱动。可用环境变量 ``POP_SCRIPT`` 覆盖 —— 定时回归（``regression_prove.py``）
#: 与单测都靠它**注入替身驱动**，从而不必有 Rust 工具链也能走完整流程。
POP_SCRIPT = Path(os.environ.get("POP_SCRIPT")
                  or (REPO / "circuits" / "target" / "release" / "pop-script"))

#: 产物目录（``vectors.json`` / ``results_*.json``）。可用 ``--work-dir`` 覆盖 ——
#: 定时回归就是靠覆盖用私有目录，免得和有人手工跑的 ``cross_validate`` 互相覆盖。
#:
#: 缺省从 ``scripts/`` 改到 ``scripts/.work/``：这四个文件是**草稿产物**，原先直接
#: 落在源码目录里，`ls scripts/` 分不清哪些是脚本、哪些是上次跑剩下的。`.work/`
#: 是专门的草稿区，由一条 gitignore 规则覆盖（替掉原先散在 4 条里的同名文件规则）。
DEFAULT_WORK_DIR = REPO / "scripts" / ".work"

# Python Violation.evidence_kind -> guest 规则类型字符串
KIND_MAP = {"keyword": "keyword_block", "length": "length_bound", "pattern": "pattern_block",
            "format": "format_check", "tool_arg": "tool_arg_guard", "budget": "budget_bound",
            "normalized_keyword": "normalized_keyword_block"}

#: 真实证明时每个 pop-script 进程处理的向量数（见模块 docstring 的 OOM 说明）。
DEFAULT_CHUNK = 4


def chunked(items: list, n: int) -> list[list]:
    """把 items 切成每组最多 n 个；``n <= 0`` 表示不切（一组装完）。"""
    if n <= 0:
        return [list(items)] if items else []
    return [list(items[i:i + n]) for i in range(0, len(items), n)]


def parse_chunk(argv: list[str]) -> int:
    """从命令行读 ``--chunk N`` / ``--chunk=N``（缺省 :data:`DEFAULT_CHUNK`）。"""
    for i, a in enumerate(argv):
        if a == "--chunk" and i + 1 < len(argv):
            return int(argv[i + 1])
        if a.startswith("--chunk="):
            return int(a.split("=", 1)[1])
    return DEFAULT_CHUNK


def parse_work_dir(argv: list[str]) -> Path:
    """从命令行读 ``--work-dir DIR`` / ``--work-dir=DIR``（缺省 ``scripts/``）。"""
    for i, a in enumerate(argv):
        if a == "--work-dir" and i + 1 < len(argv):
            return Path(argv[i + 1]).resolve()
        if a.startswith("--work-dir="):
            return Path(a.split("=", 1)[1]).resolve()
    return DEFAULT_WORK_DIR


#: 回执链的固定时间戳 —— 让 vectors.json 每次都逐字节相同（可复现）。
TRACE_TS = "2026-01-01T00:00:00+00:00"


def gateway() -> "trace.ToolGateway":
    """造一个**一次性**网关（进程内临时钥、固定时间戳），用于签发测试回执。"""
    return trace.ToolGateway(ts=TRACE_TS)


def vectors() -> list[tuple]:
    """返回 (name, policy, response, extras) 元组列表。输入均为纯 ASCII。

    ``extras`` 可携带 ``receipts``（P1-5 的网关回执链），用于轨迹类规则
    （tool_arg_guard / budget_bound）。回执由本模块的 :func:`gateway` 签出，
    与真实链路一致 —— 不是手搓的字典。
    """
    base = Policy(
        id="x", version="0.1.0", semantic="and",
        rules=[
            Rule("keyword_block", "no_bad", {"keywords": ["weaponize", "exploit", "doxxing"]}),
            Rule("length_bound", "len_ok", {"min": 1, "max": 2000}),
        ],
    )
    pii_email = Policy(
        id="p1", version="0.1.0", semantic="and",
        rules=[Rule("pattern_block", "no_email", {"patterns": [pii.PII_PATTERNS["email"]]})],
    )
    pii_secret = Policy(
        id="p2", version="0.1.0", semantic="and",
        rules=[Rule("pattern_block", "no_secret", {"patterns": [pii.PII_PATTERNS["secret_key"]]})],
    )
    fmt = Policy(
        id="f1", version="0.1.0", semantic="and",
        rules=[Rule("format_check", "must_be_json", {"format": "json"})],
    )
    toolpol = Policy(
        id="t1", version="0.1.0", semantic="and",
        rules=[Rule("tool_arg_guard", "no_secret_args",
                    {"forbidden_fields": ["password", "token", "api_key"]})],
    )
    budgetpol = Policy(
        id="b1", version="0.1.0", semantic="and",
        rules=[Rule("budget_bound", "call_budget", {"budget": 2, "unit": "calls"})],
    )
    tokenpol = Policy(
        id="b2", version="0.1.0", semantic="and",
        rules=[Rule("budget_bound", "token_budget", {"budget": 100, "unit": "tokens"})],
    )
    normpol = Policy(
        id="n1", version="0.1.0", semantic="and",
        rules=[Rule("normalized_keyword_block", "no_homoglyph",
                    {"keywords": ["weaponize", "dеlegate"], "fold": "v1"})],
    )
    def chain(*calls: tuple) -> list:
        """用一次性网关把 ``[(tool, args, result), ...]`` 签成回执链（JSON 形状）。"""
        return trace.receipts_to_json(trace.make_chain(list(calls),
                                                       gateway=gateway()))

    return [
        ("clean_pass", base,
         "The service processed your request and will reply shortly. Thank you.", {}),
        ("keyword_hit", base,
         "Here is a step-by-step guide on how to exploit the login endpoint.", {}),
        ("length_too_long", base, "x" * 2500, {}),
        ("email_hit", pii_email, "My details: reach dev@example.com anytime.", {}),
        ("email_clean", pii_email, "This guidance contains no addresses or mailboxes.", {}),
        ("secret_hit", pii_secret, "Rotate the key sk-abcdefghijklmnopqrstuvwxyz now.", {}),
        ("secret_clean", pii_secret, "All credentials have been rotated.", {}),
        ("format_ok", fmt, '{"ok": true, "n": 1}', {}),
        ("format_bad", fmt, "plain text, not json", {}),
        ("tool_arg_hit", toolpol, "",
         {"receipts": chain(("search_kb", {"query": "refund", "token": "secret"}, "hit"))}),
        ("tool_arg_clean", toolpol, "",
         {"receipts": chain(("search_kb", {"query": "refund"}, "clean"))}),
        ("budget_over", budgetpol, "",
         {"receipts": chain(("a", {}, "x"), ("b", {}, "y"), ("c", {}, "z"))}),
        ("budget_ok", budgetpol, "",
         {"receipts": chain(("a", {}, "x"), ("b", {}, "y"))}),
        # token 规则现在判**响应**的确定性 token 数（P1-5：电路内自算，
        # 不再读自填值）。150 个空白分隔的 run 超过预算 100。
        ("token_over", tokenpol, " ".join(["tok"] * 150), {}),
        # 规范化关键词（P2-9b）：三种绕过手段各一条，外加一条干净的对照。
        # 关键词表里的 "dеlegate" 本身就是用西里尔 е 写的 —— 编译期折成 ASCII，
        # 于是「作者笔误写成同形字」与「攻击者用同形字绕过」都会落在同一处。
        ("norm_homoglyph", normpol, "Here is how to wеaponize a device.", {}),
        ("norm_zero_width", normpol, "Here is how to wea​ponize a device.", {}),
        ("norm_fullwidth", normpol, "Here is how to ｗｅａｐｏｎｉｚｅ a device.", {}),
        ("norm_ascii", normpol, "Here is how to weaponize a device.", {}),
        ("norm_clean", normpol, "Here is a friendly summary of the results.", {}),
    ]


def golden(policy: Policy, response: str, extras: dict | None = None) -> dict:
    """用参考评估器（走结构化 Transcript）算出 golden 结果。"""
    extras = extras or {}
    tx = Transcript(
        response=response,
        receipts=trace.receipts_from_json(extras.get("receipts")),
    )
    res = check(policy, tx)
    rules = sorted({(v.rule.name, KIND_MAP.get(v.evidence_kind, v.evidence_kind))
                    for v in res.violations})
    return {"passed": res.passed, "violations": rules}


def run_pop(mode: str, vectors_path: Path, out_path: Path) -> None:
    """调用 pop-script；mode=="check" 时走宿主校验路径。"""
    args = [str(POP_SCRIPT)]
    if mode == "check":
        args.append("--check")
    args += ["--vectors", str(vectors_path), "--out", str(out_path)]
    env = dict(os.environ, SP1_PROVER="cpu")
    subprocess.run(args, env=env, check=True, cwd=str(REPO))


def run_pop_prove_chunked(vectors_payload: dict, out_path: Path, chunk: int,
                          work_dir: Path) -> None:
    """分块生成真实证明，把各块结果按原序合并写入 ``out_path``。

    分块只是**进程隔离**，不改变交给电路的输入：每块拿到的是原向量的连续子序列，
    合并后的顺序与单进程跑完全一致 —— 因此下游比对逻辑无需知道分块存在。
    """
    parts = chunked(vectors_payload["vectors"], chunk)
    merged: list = []
    for i, part in enumerate(parts, start=1):
        vp = work_dir / f"vectors_{i}.json"
        rp = work_dir / f"results_{i}.json"
        vp.write_text(json.dumps({"vectors": part}, indent=2))
        print(f"    chunk {i}/{len(parts)}: {len(part)} vector(s) -> {vp.name}", flush=True)
        run_pop("prove", vp, rp)
        merged.extend(json.loads(rp.read_text()))
    out_path.write_text(json.dumps(merged, indent=2))


def compare(results: list, expected: list) -> tuple[int, list[str]]:
    """逐向量比对 SP1 结果与 golden，返回 (匹配数, 明细)。"""
    ok_flags, detail = [], []
    for (name, exp), got in zip(expected, results, strict=True):
        got_rules = sorted({(v["rule"], v["kind"]) for v in got["violations"]})
        ok = got["passed"] == exp["passed"] and got_rules == exp["violations"]
        ok_flags.append(ok)
        detail.append((name, ok, exp, got))
    return sum(ok_flags), detail


def report(kind: str, ok_flags: list, detail: list) -> None:
    """打印逐向量的比对结果。"""
    for (name, ok, exp, got) in detail:
        print(f"[{'PASS' if ok else 'FAIL'}] {kind:5s} {name:20s} "
              f"golden.passed={exp['passed']} sp1.passed={got['passed']}  "
              f"rules={exp['violations']} vs {[(v['rule'], v['kind']) for v in got['violations']]}")
    print(f"{kind}: {sum(ok_flags)}/{len(ok_flags)} matched")


def main() -> int:
    vectors_in = vectors()
    payload = {"vectors": []}
    expected = []
    for name, policy, response, extras in vectors_in:
        spec = compile_policy(policy)
        entry = {"name": name, "response": response,
                 "spec_canonical": spec_canonical_text(spec)}
        entry.update(extras or {})
        payload["vectors"].append(entry)
        expected.append((name, golden(policy, response, extras)))

    if not POP_SCRIPT.exists():
        print(f"error: driver not built: {POP_SCRIPT}\n  cd circuits && cargo build --release -p pop-script")
        return 2

    work_dir = parse_work_dir(sys.argv)
    work_dir.mkdir(parents=True, exist_ok=True)
    if work_dir != DEFAULT_WORK_DIR:
        print(f"work dir: {work_dir}")
    vectors_path = work_dir / "vectors.json"
    vectors_path.write_text(json.dumps(payload, indent=2))
    print(f"{len(expected)} vectors, mode: host-check (all) + real proofs (all)")

    # 宿主校验（全部向量，不生成证明）
    results_check = work_dir / "results_check.json"
    print("--- host check (pop-types::evaluate, no proof) ---")
    run_pop("check", vectors_path, results_check)
    rc = json.loads(results_check.read_text())
    n1, d1 = compare(rc, expected)
    report("check", [ok for _, ok, _, _ in d1], d1)

    # 真实证明（全部向量）
    results_prove = work_dir / "results_prove.json"
    skipped_prove = "--no-prove" in sys.argv
    if skipped_prove:
        # 这里**不能**拿 host 的计数冒充 prove：`--no-prove` 下一条证明都没出，
        # 末行若照抄 host 数字，读的人（和文档）会把 host 结论当成出证结论。
        print("--- real proofs: skipped (--no-prove) ---")
        n2 = None
    else:
        chunk = parse_chunk(sys.argv)
        shape = ("single process" if chunk <= 0
                 else f"{len(chunked(payload['vectors'], chunk))} chunk(s) of {chunk}")
        print(f"--- real proofs (SP1 guest, {shape}) ---")
        # 先把上一轮的 results_prove.json 删掉：中途 OOM 被 kill 时不该留下一份
        # **上一次**的结果冒充本次结论（本文件只会跑完全部块才写）。
        results_prove.unlink(missing_ok=True)
        work_dir = Path(tempfile.mkdtemp(prefix="pop-crossvalidate-"))
        try:
            run_pop_prove_chunked(payload, results_prove, chunk, work_dir)
        finally:
            # 中间产物是**逐块**的 vectors/results：删掉，免得和最终的
            # results_prove.json 混在一起被误当成权威结果。
            shutil.rmtree(work_dir, ignore_errors=True)
        rp = json.loads(results_prove.read_text())
        n2, d2 = compare(rp, expected)
        report("prove", [ok for _, ok, _, _ in d2], d2)

    ok = n1 == len(expected) and (skipped_prove or n2 == len(expected))
    prove_txt = "SKIPPED (--no-prove)" if skipped_prove else f"{n2}/{len(expected)}"
    print("\n" + "=" * 60)
    print(f"RESULT: host {n1}/{len(expected)}  prove {prove_txt}  {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
