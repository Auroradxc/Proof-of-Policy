#!/usr/bin/env python3
"""阶段一至二交叉验证：Python golden（policydsl）vs SP1。

对每条测试向量我们：
  1. 构造一个 Policy，用 policydsl.evaluate 算出参考判定（即 golden；
     pattern_block 由编译后的 NFA == 契约来判定）；
  2. 把策略编译成 ConstraintSpec，并产出一个 Rust 侧 vectors.json
     （serde 外部标签枚举 Constraint：KeywordBlock / LengthBound / PatternBlock）
     供 SP1 驱动消费；
  3a. 宿主校验（快，全部向量）：pop-script --check  → pop-types::evaluate
  3b. 证明（真实证明，全部向量）：pop-script          → guest ProofOutput
  4. 断言两种模式下 passed + 违规规则集合都与 golden 一致。

从仓库根运行：
  SP1_PROVER=cpu python3 scripts/cross_validate.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl.compile import compile_policy
from policydsl.evaluate import check
from policydsl.model import Policy, Rule, ToolCall, Transcript
from policydsl.serialize import spec_canonical_text
from policydsl import pii

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"

# Python Violation.evidence_kind -> guest 规则类型字符串
KIND_MAP = {"keyword": "keyword_block", "length": "length_bound", "pattern": "pattern_block",
            "format": "format_check", "tool_arg": "tool_arg_guard", "budget": "budget_bound"}


def vectors() -> list[tuple]:
    """返回 (name, policy, response, extras) 元组列表。输入均为纯 ASCII。

    ``extras`` 可携带 ``tool_calls`` / ``token_count``，用于轨迹类规则
    （tool_arg_guard / budget_bound）。
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
    call = lambda n, a: {"name": n, "args": a}  # noqa: E731
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
         {"tool_calls": [call("search_kb", {"query": "refund", "token": "secret"})]}),
        ("tool_arg_clean", toolpol, "",
         {"tool_calls": [call("search_kb", {"query": "refund"})]}),
        ("budget_over", budgetpol, "",
         {"tool_calls": [call("a", {}), call("b", {}), call("c", {})]}),
        ("budget_ok", budgetpol, "", {"tool_calls": [call("a", {}), call("b", {})]}),
        ("token_over", tokenpol, "", {"token_count": 150}),
    ]


def golden(policy: Policy, response: str, extras: dict | None = None) -> dict:
    """用参考评估器（走结构化 Transcript）算出 golden 结果。"""
    extras = extras or {}
    tx = Transcript(
        response=response,
        tool_calls=[ToolCall(c["name"], c.get("args", {})) for c in extras.get("tool_calls", [])],
        token_count=extras.get("token_count"),
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

    scripts = REPO / "scripts"
    vectors_path = scripts / "vectors.json"
    vectors_path.write_text(json.dumps(payload, indent=2))
    print(f"{len(expected)} vectors, mode: host-check (all) + real proofs (all)")

    # 宿主校验（全部向量，不生成证明）
    results_check = scripts / "results_check.json"
    print("--- host check (pop-types::evaluate, no proof) ---")
    run_pop("check", vectors_path, results_check)
    rc = json.loads(results_check.read_text())
    n1, d1 = compare(rc, expected)
    report("check", [ok for _, ok, _, _ in d1], d1)

    # 真实证明（全部向量）
    results_prove = scripts / "results_prove.json"
    if "--no-prove" in sys.argv:
        print("--- real proofs: skipped (--no-prove) ---")
        n2 = n1
        d2 = d1
    else:
        print("--- real proofs (SP1 guest) ---")
        run_pop("prove", vectors_path, results_prove)
        rp = json.loads(results_prove.read_text())
        n2, d2 = compare(rp, expected)
        report("prove", [ok for _, ok, _, _ in d2], d2)

    ok = n1 == len(expected) and n2 == len(expected)
    print("\n" + "=" * 60)
    print(f"RESULT: host {n1}/{len(expected)}  prove {n2}/{len(expected)}  {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
