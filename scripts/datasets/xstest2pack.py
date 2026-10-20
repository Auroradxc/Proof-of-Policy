#!/usr/bin/env python3
"""XSTest → 策略包 + 测试向量 + 评测（精确率/召回率/F1）

XSTest（Röttger et al., 2023）的价值：safe 样本里也含「敏感词」（如
「kill a Python process」），朴素关键词黑名单会误伤。用它测 keyword_block
规则的**误报率**，正是「有效性」的度量——不是「跑没跑」，而是「拦得对不对」。

用法：
    python3 scripts/datasets/xstest2pack.py [xstest_prompts.csv]

产出：
    policy_packs/safety_xstest_v1.json          策略包（朴素关键词黑名单）
    scripts/examples/datasets/xstest_vectors.json  测试向量（含 ground truth 标签）
    scripts/examples/datasets/xstest_results.json  评测结果（TP/FP/TN/FN + P/R/F1）
"""
import csv
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]  # 向上两级到 zk-policy 根
sys.path.insert(0, str(REPO))

from policydsl.core.model import Policy
from policydsl.core.evaluate import check


def main() -> int:
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/xstest_prompts.csv"
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))

    # 1. 提取非空 focus 词作为「朴素黑名单」（正是 XSTest 要暴露其误报的对象）
    focus_words = sorted({r["focus"].strip() for r in rows if r["focus"].strip()})
    # 多词短语放到前面，避免「blow up」被「blow」这类单字提前命中的歧义（此处仅作说明，
    # keyword_block 用子串包含，顺序不影响判定）
    focus_words.sort(key=lambda w: (-len(w), w))

    # 2. 构建策略包（朴素关键词黑名单）
    pack = {
        "id": "safety-xstest-v1",
        "version": "0.1.0",
        "description": "Naive keyword blocklist over XSTest sensitive words; "
                       "exposes the false-positive rate of keyword-only policies.",
        "semantic": "and",
        "rules": [
            {"kind": "keyword_block",
             "name": "no_sensitive_topic",
             "params": {"keywords": focus_words}},
        ],
    }
    policy = Policy.from_dict(pack)

    # 3. 逐条判定 + 统计
    tp = fp = tn = fn = 0
    vectors = []
    for r in rows:
        prompt, label = r["prompt"], r["label"]
        result = check(policy, prompt)
        predicted_violation = not result.passed
        actual_violation = (label == "unsafe")
        hit_words = [v.evidence for v in result.violations]

        if predicted_violation and actual_violation:
            tp += 1
        elif predicted_violation and not actual_violation:
            fp += 1
        elif not predicted_violation and not actual_violation:
            tn += 1
        else:
            fn += 1

        vectors.append({
            "id": r["id"], "prompt": prompt, "label": label,
            "predicted": "violation" if predicted_violation else "pass",
            "hit_words": hit_words,
        })

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    # 4. 落盘
    out_dir = REPO / "scripts" / "examples" / "datasets"
    out_dir.mkdir(parents=True, exist_ok=True)
    (REPO / "policy_packs" / "safety_xstest_v1.json").write_text(
        json.dumps(pack, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "xstest_vectors.json").write_text(
        json.dumps(vectors, ensure_ascii=False, indent=2), encoding="utf-8")

    results = {
        "dataset": "xstest", "n": len(rows),
        "blacklist_words": len(focus_words),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_examples": [
            {"prompt": v["prompt"], "hit": v["hit_words"]}
            for v in vectors if v["label"] == "safe" and v["predicted"] == "violation"
        ][:5],
    }
    (out_dir / "xstest_results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    # 5. 打印
    print(f"XSTest 评测（朴素关键词黑名单，{len(focus_words)} 词）")
    print(f"  样本数={len(rows)}  TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"  精确率 Precision = {precision:.4f}")
    print(f"  召回率 Recall    = {recall:.4f}")
    print(f"  F1               = {f1:.4f}")
    print(f"  误报示例（safe 被误判）:")
    for e in results["false_positive_examples"][:3]:
        print(f"    「{e['prompt'][:45]}」→ 命中 {e['hit']}")
    print(f"\n产出: policy_packs/safety_xstest_v1.json")
    print(f"      scripts/examples/datasets/xstest_vectors.json / xstest_results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
