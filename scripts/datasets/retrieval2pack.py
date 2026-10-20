#!/usr/bin/env python3
"""检索断言（retrieval_guard）评测：代表性 RAG 合规场景。

真实检索相关性数据集（BEIR / MS MARCO / Natural Questions）在 HuggingFace，
本机网络不可达，故此处用**代表性合成场景**：检索工具调用携带 (query, doc, relevance)
三个参数，relevance 是 0--100 的整数字符串，策略要求 relevance >= 70。

这是确定性阈值规则，与 tool_arg_guard / budget_bound 同类 —— 预期零误报。
评测的意义在于确认**跨语言判定一致 + 覆盖矩阵补上「检索」这一格**，而非
「拟合一个会漂移的分数」。

用法：
    python3 scripts/datasets/retrieval2pack.py
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from policydsl.core.model import Policy, Transcript  # noqa: E402
from policydsl.core.evaluate import check  # noqa: E402
from policydsl.evidence import trace  # noqa: E402

MIN_SCORE = 70
# (query, doc, relevance) —— 覆盖高分/低分/边界/非数字 四类
CASES = [
    ("account deletion policy", "doc-01", "95"),
    ("refund eligibility", "doc-02", "88"),
    ("GDPR data subject rights", "doc-03", "91"),
    ("password reset steps", "doc-04", "76"),
    ("annual report filing", "doc-05", "82"),
    ("unrelated marketing blurb", "doc-06", "33"),
    ("unrelated lunch menu", "doc-07", "12"),
    ("unrelated sports scores", "doc-08", "41"),
    ("boundary: exactly 70", "doc-09", "70"),
    ("boundary: 69 just below", "doc-10", "69"),
    ("non-numeric score", "doc-11", "high"),
    ("missing score field", "doc-12", None),
    ("data breach notification", "doc-13", "97"),
    ("unrelated weather", "doc-14", "5"),
    ("KYC verification", "doc-15", "84"),
    ("unrelated recipe", "doc-16", "18"),
    ("complaint escalation", "doc-17", "79"),
    ("unrelated celebrity gossip", "doc-18", "22"),
    ("terms of service", "doc-19", "86"),
    ("unrelated stock tips", "doc-20", "37"),
]


def main() -> int:
    pol = Policy.from_dict({
        "id": "retrieval-demo-v1", "version": "0.1.0", "semantic": "and",
        "rules": [{"kind": "retrieval_guard", "name": "min_relevance",
                   "params": {"min_score": MIN_SCORE, "score_field": "relevance"}}],
    })

    tp = fp = tn = fn = 0
    vectors = []
    for query, doc, score in CASES:
        args = {"query": query, "doc": doc}
        if score is not None:
            args["relevance"] = score
        receipts = trace.receipts_to_json(trace.make_chain(
            [("retrieve", args, "")]))
        res = check(pol, Transcript(response="",
                                    receipts=trace.receipts_from_json(receipts)))
        flagged = not res.passed
        # ground truth：得分缺失 → 跳过不判（与 tool_arg_guard「无禁字段不判」同构）；
        # 非数字 / 低于阈值 → 违规；>= 阈值 → 合规
        gt_violation = (score is not None
                        and (not score.isdigit() or int(score) < MIN_SCORE))
        if flagged and gt_violation:
            tp += 1
        elif flagged and not gt_violation:
            fp += 1
        elif not flagged and not gt_violation:
            tn += 1
        else:
            fn += 1
        vectors.append({"query": query, "doc": doc, "relevance": score,
                        "gt": "violation" if gt_violation else "pass",
                        "predicted": "violation" if flagged else "pass"})

    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0

    out = REPO / "scripts" / "examples" / "datasets"
    out.mkdir(parents=True, exist_ok=True)
    (REPO / "policy_packs" / "retrieval_demo_v1.json").write_text(
        json.dumps({"id": "retrieval-demo-v1", "version": "0.1.0", "semantic": "and",
                    "rules": [{"kind": "retrieval_guard", "name": "min_relevance",
                               "params": {"min_score": MIN_SCORE,
                                          "score_field": "relevance"}}]},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "retrieval_vectors.json").write_text(
        json.dumps(vectors, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "retrieval_results.json").write_text(json.dumps({
        "rule": "retrieval_guard", "min_score": MIN_SCORE,
        "n": len(CASES), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
        "note": "代表性合成 RAG 场景（真实检索数据集在不可达的 HuggingFace）",
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"retrieval_guard 评测（{len(CASES)} 次检索调用，阈值 {MIN_SCORE}）")
    print(f"  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  精确率={p:.4f} 召回率={r:.4f} F1={f1:.4f}")
    print(f"\n产出: policy_packs/retrieval_demo_v1.json")
    print(f"      scripts/examples/datasets/retrieval_vectors.json / retrieval_results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
