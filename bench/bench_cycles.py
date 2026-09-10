#!/usr/bin/env python3
"""Proof-of-Policy 的 cycle 数矩阵（只跑 zkVM 执行、不生成证明）。

扫描「响应长度 × 规则条数 × 匹配模式」的组合，用 ``pop-script --execute``
记录 zkVM 的 cycle 数。因为省掉了证明生成所以很快，能铺很多采样点；真正（慢
几个数量级）的证明耗时/体积曲线在 ``bench_proofs.py`` 里。

结果写到 ``bench/results/cycles.json``，同时在同目录生成一份 .md 表格便于贴文档。

用法：
  python3 bench/bench_cycles.py [--out bench/results/cycles.json]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import pii  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.serialize import spec_to_rust_constraints  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
WORK = REPO / "bench" / "work"

EMAIL = pii.PII_PATTERNS["email"]


def make_policy(rule_count: int, mode: str = "pike") -> Policy:
    """构造 1 条 length_bound + (rule_count-1) 条额外约束（keyword/pattern）。

    固定第一条长度规则，是为了让不同规则数之间只差「扫描量」，便于横向比较；
    ``mode`` 只作用于 pattern_block，用来对比 pike(线性) 与 naive(O(n^2)) 两种匹配。
    """
    rules = [Rule("length_bound", "len", {"min": 1, "max": 10_000_000})]
    extras = [
        Rule("keyword_block", "kw", {"keywords": ["exploit", "weaponize", "doxxing"]}),
        Rule("pattern_block", "pat", {"patterns": [EMAIL], "match_mode": mode}),
        Rule("keyword_block", "kw2", {"keywords": ["terrorism", "child abuse"]}),
        Rule("pattern_block", "pat2", {"patterns": [pii.PII_PATTERNS["secret_key"]], "match_mode": mode}),
        Rule("keyword_block", "kw3", {"keywords": ["leverage"]}),
    ]
    rules.extend(extras[: max(0, rule_count - 1)])
    return Policy("bench", "1", rules=rules)


def response(prefix: str, length: int) -> str:
    """生成一个恰好 ``length`` 字符、且不含任何命中词的干净响应文本。

    纯干净（no hits）很重要：只有全部约束都被完整扫描到底，cycle 数才反映
    「最坏情况」的扫描成本，而不是命中即停的短路成本。
    """
    body = (prefix + " ") * ((length // (len(prefix) + 1)) + 1)
    return body[:length]


def run_execute(vector: dict) -> dict:
    """把单个向量喂给 ``pop-script --execute``，返回其 JSON 结果。

    走子进程而不是 import，是为了测真实的 CLI 路径（参数解析 + 序列化开销）。
    """
    WORK.mkdir(parents=True, exist_ok=True)
    vp = WORK / "v.json"
    op = WORK / "r.json"
    vp.write_text(json.dumps({"vectors": [vector]}))
    subprocess.run([str(POP_SCRIPT), "--execute", "--vectors", str(vp), "--out", str(op)],
                   cwd=str(REPO), check=True, capture_output=True, text=True)
    return json.loads(op.read_text())[0]


def main() -> int:
    """遍历所有采样点，落盘 JSON 结果与 Markdown 表格。"""
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=REPO / "bench" / "results" / "cycles.json")
    args = ap.parse_args()

    lengths = [200, 2_000, 20_000]
    rule_counts = [1, 3, 6]
    modes = ["pike", "naive"]
    rows = []
    for length in lengths:
        for rc in rule_counts:
            for mode in modes:
                # naive 匹配是 O(n^2)，长文本会把执行时间炸掉，只在短长度上跑
                if mode == "naive" and length > 2_000:
                    continue
                policy = make_policy(rc, mode)
                spec = compile_policy(policy)
                # 用不含命中词的长响应，强制每条约束都扫描到底（最坏情况）
                text = response("the quick brown fox jumps", length)
                out = run_execute({"name": f"L{length}-R{rc}-{mode}", "response": text,
                                   "constraints": spec_to_rust_constraints(spec)})
                rows.append({"length": length, "rules": rc, "mode": mode,
                             "cycles": out["cycles"], "passed": out["passed"]})
                print(f"L={length:>6} rules={rc} mode={mode:<5} cycles={out['cycles']:,}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rows, indent=2))

    # 同时输出 Markdown 表格，方便直接贴进 README/报告
    md = ["# Cycle-count matrix (zkVM execution, no proof)", "",
          "| length | rules | mode | cycles |", "|---:|---:|:--|---:|"]
    for r in rows:
        md.append(f"| {r['length']} | {r['rules']} | {r['mode']} | {r['cycles']:,} |")
    (args.out.with_suffix(".md")).write_text("\n".join(md) + "\n")
    print(f"\nwrote {args.out} and {args.out.with_suffix('.md')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
