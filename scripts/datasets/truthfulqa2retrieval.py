#!/usr/bin/env python3
"""TruthfulQA（真实问答数据）→ retrieval_guard 评测。

映射：一个检索式问答 agent 从知识库检索答案；检索到**正确答案**视为相关
（relevance=100）、检索到**错误答案**视为不相关/幻觉（relevance=0）。
策略 ``retrieval_guard(min_score=50)`` 应放行相关检索、拦下不相关检索。

TruthfulQA 是真实数据集（789 道题，每题含「正确回答」与「错误回答」），
本脚本把每题拆成「检索到正确」与「检索到错误」两次检索调用，各带一个
相关性得分（整数字符串），喂给确定性规则判定并算 F1。

用法：
    python3 scripts/datasets/truthfulqa2retrieval.py [TruthfulQA.csv]
"""
import csv
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from policydsl.core.model import Policy, Transcript  # noqa: E402
from policydsl.core.evaluate import check  # noqa: E402
from policydsl.evidence import trace  # noqa: E402

MIN_SCORE = 50
RELEVANT, IRRELEVANT = "100", "0"


def _first(text: str) -> str:
    """取分号分隔答案列表里的第一条（去空白）。"""
    parts = [p.strip() for p in (text or "").split(";") if p.strip()]
    return parts[0] if parts else ""


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/dong/.claude/jobs/a8adbc15/tmp/truthfulqa.csv"
    rows = list(csv.DictReader(open(path, encoding="utf-8")))

    pol = Policy.from_dict({
        "id": "retrieval-truthfulqa-v1", "version": "0.1.0", "semantic": "and",
        "rules": [{"kind": "retrieval_guard", "name": "min_relevance",
                   "params": {"min_score": MIN_SCORE, "score_field": "relevance"}}],
    })

    tp = fp = tn = fn = 0
    vectors = []
    for r in rows:
        q = r["Question"]
        good = _first(r.get("Correct Answers", ""))
        bad = _first(r.get("Incorrect Answers", ""))
        if not good or not bad:
            continue
        for doc, relevance, gt_violation in [
            (good, RELEVANT, False),   # 检索到正确 → 相关 → 应放行
            (bad, IRRELEVANT, True),   # 检索到错误 → 不相关 → 应拦下
        ]:
            args = {"query": q, "doc": doc, "relevance": relevance}
            receipts = trace.receipts_to_json(trace.make_chain(
                [("retrieve", args, "")]))
            res = check(pol, Transcript(
                response="", receipts=trace.receipts_from_json(receipts)))
            flagged = not res.passed
            if flagged and gt_violation:
                tp += 1
            elif flagged and not gt_violation:
                fp += 1
            elif not flagged and not gt_violation:
                tn += 1
            else:
                fn += 1
            vectors.append({"query": q, "retrieved": doc[:40], "relevance": relevance,
                            "gt": "violation" if gt_violation else "pass",
                            "predicted": "violation" if flagged else "pass"})

    p = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rec / (p + rec) if p + rec else 0.0

    out = REPO / "scripts" / "examples" / "datasets"
    out.mkdir(parents=True, exist_ok=True)
    (REPO / "policy_packs" / "retrieval_truthfulqa_v1.json").write_text(
        json.dumps({"id": "retrieval-truthfulqa-v1", "version": "0.1.0",
                    "semantic": "and",
                    "rules": [{"kind": "retrieval_guard", "name": "min_relevance",
                               "params": {"min_score": MIN_SCORE,
                                          "score_field": "relevance"}}]},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "retrieval_truthfulqa_vectors.json").write_text(
        json.dumps(vectors, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "retrieval_truthfulqa_results.json").write_text(json.dumps({
        "dataset": "truthfulqa", "rule": "retrieval_guard", "min_score": MIN_SCORE,
        "n_queries": len(rows), "n_calls": len(vectors),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(p, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "mapping": "检索到正确答案=相关(100)，检索到错误答案=不相关(0)",
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"retrieval_guard @ TruthfulQA（{len(rows)} 题 → {len(vectors)} 次检索调用，阈值 {MIN_SCORE}）")
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  精确率={p:.4f} 召回率={rec:.4f} F1={f1:.4f}")
    print(f"\n产出: policy_packs/retrieval_truthfulqa_v1.json")
    print(f"      scripts/examples/datasets/retrieval_truthfulqa_vectors.json / _results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
