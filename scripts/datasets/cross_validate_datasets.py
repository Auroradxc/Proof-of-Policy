#!/usr/bin/env python3
"""数据集向量的跨语言对拍：Python golden vs SP1 电路判定（宿主校验，免出证）。

把 XSTest / Enron 生成的策略包 + 抽样向量交给 ``pop-script --check``，
它走 ``pop-types::evaluate`` —— 即 zkVM 内**同一套判定代码**的宿主实现。
断言 passed + 违规规则集合与 Python golden 逐向量一致。

用法（从仓库根）：
    SP1_PROVER=cpu python3 scripts/datasets/cross_validate_datasets.py

前置：``circuits/target/release/pop-script`` 已构建（cargo build --release -p pop-script）。
"""
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

from _bootstrap import bootstrap  # noqa: E402
bootstrap()

from policydsl.core.compile import compile_policy  # noqa: E402
from policydsl.core.evaluate import (  # noqa: E402
    EVIDENCE_KIND_TO_RULE_KIND, check)
from policydsl.core.model import Policy  # noqa: E402
from policydsl.core.serialize import spec_canonical_text  # noqa: E402
from policydsl.paths import POP_SCRIPT  # noqa: E402


def golden(policy: Policy, response: str) -> dict:
    res = check(policy, response)
    rules = sorted({(v.rule.name,
                     EVIDENCE_KIND_TO_RULE_KIND.get(v.evidence_kind, v.evidence_kind))
                    for v in res.violations})
    return {"passed": res.passed, "violations": rules}


def build_vectors() -> tuple[list, list]:
    """返回 (payload_entries, expected)。"""
    xstest = Policy.from_dict(
        json.loads((REPO / "policy_packs" / "safety_xstest_v1.json").read_text()))
    enron = Policy.from_dict(
        json.loads((REPO / "policy_packs" / "pii_enron_v1.json").read_text()))

    xv = json.loads((REPO / "scripts" / "examples" / "datasets"
                     / "xstest_vectors.json").read_text())
    ev = json.loads((REPO / "scripts" / "examples" / "datasets"
                     / "enron_vectors.json").read_text())

    entries, expected = [], []
    # XSTest：safe / unsafe 各取 20 条，覆盖「误报」与「漏报」两条边
    safe = [v for v in xv if v["label"] == "safe"][:20]
    unsafe = [v for v in xv if v["label"] == "unsafe"][:20]
    for v in safe + unsafe:
        name = f"xstest-{v['id']}-{v['label']}"
        entries.append({"name": name, "response": v["prompt"],
                        "spec_canonical": spec_canonical_text(compile_policy(xstest))})
        expected.append((name, golden(xstest, v["prompt"])))
    # Enron：取前 20 封含 PII 的邮件
    for v in ev[:20]:
        name = f"enron-{v['id']}"
        entries.append({"name": name, "response": v["snippet"],
                        "spec_canonical": spec_canonical_text(compile_policy(enron))})
        expected.append((name, golden(enron, v["snippet"])))
    return entries, expected


def main() -> int:
    if not POP_SCRIPT.exists():
        print(f"error: driver not built: {POP_SCRIPT}\n"
              f"  cd circuits && cargo build --release -p pop-script")
        return 2

    entries, expected = build_vectors()
    work = REPO / "scripts" / ".work" / "datasets"
    work.mkdir(parents=True, exist_ok=True)
    vectors_path = work / "vectors.json"
    vectors_path.write_text(json.dumps({"vectors": entries}, indent=2))

    print(f"{len(entries)} 个数据集向量（XSTest 40 + Enron 20），宿主校验中…")
    out_path = work / "results_check.json"
    subprocess.run([str(POP_SCRIPT), "--check", "--vectors", str(vectors_path),
                    "--out", str(out_path)],
                   env=dict(os.environ, SP1_PROVER="cpu"), check=True,
                   cwd=str(REPO))
    got = json.loads(out_path.read_text())

    n_ok = 0
    detail = []
    for (name, exp), g in zip(expected, got, strict=True):
        got_rules = sorted({(v["rule"], v["kind"]) for v in g["violations"]})
        ok = g["passed"] == exp["passed"] and got_rules == exp["violations"]
        n_ok += ok
        detail.append((name, ok, exp, g))

    for name, ok, exp, g in detail:
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {name:28s} golden.passed={exp['passed']} "
              f"sp1.passed={g['passed']}  rules={exp['violations']} vs "
              f"{[(v['rule'], v['kind']) for v in g['violations']]}")

    print(f"\n跨语言对拍：{n_ok}/{len(expected)} matched")
    return 0 if n_ok == len(expected) else 1


if __name__ == "__main__":
    raise SystemExit(main())
