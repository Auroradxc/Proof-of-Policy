#!/usr/bin/env python3
"""τ-bench（真实多步 agent 轨迹）→ 两个策略包 + 测试向量 + 评测。

τ-bench（Sierra）是「agent-工具-用户」真实交互基准，每条任务带 ground-truth
工具调用序列（``info.task.actions``，含工具名 + kwargs）。用它补两类真实语料：

  - ``tool_arg_guard``：敏感参数字段（passengers / payment_methods / payment_id）
    的工具调用应被拦，纯查询字段（reservation_id / origin / date / user_id）应放行。
  - ``budget_bound``：累计调用次数超过预算（默认 3 次）的多步轨迹应被拦。

用法：
    python3 scripts/datasets/taubench2pack.py [taubench_airline.json]

产出：
    policy_packs/toolarg_taubench_v1.json / budget_taubench_v1.json
    scripts/examples/datasets/taubench_*_vectors.json / *_results.json
"""
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from policydsl.core.model import Policy, Transcript  # noqa: E402
from policydsl.core.evaluate import check  # noqa: E402
from policydsl.evidence import trace  # noqa: E402

SENSITIVE_FIELDS = ["passengers", "payment_methods", "payment_id"]


def receipts_chain(actions: list) -> list:
    """把 τ-bench 的 ground-truth actions 转成已签名回执链（JSON 形状）。"""
    entries = [(a["name"], a.get("kwargs", {}), "") for a in actions]
    return trace.receipts_to_json(trace.make_chain(entries))


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/dong/.claude/jobs/a8adbc15/tmp/taubench_airline.json"
    trajs = json.load(open(path, encoding="utf-8"))

    # 提取全部 ground-truth 动作
    all_actions = []
    for t in trajs:
        for a in t["info"]["task"]["actions"]:
            all_actions.append(a)

    # ---- ① tool_arg_guard ----
    from policydsl.core.model import Rule  # noqa: E402
    toolpol = Policy(
        id="toolarg-taubench-v1", version="0.1.0", semantic="and",
        rules=[Rule("tool_arg_guard", "no_sensitive_fields",
                    {"forbidden_fields": SENSITIVE_FIELDS})],
    )

    tp = fp = tn = fn = 0
    tool_vectors = []
    for a in all_actions:
        kwargs = a.get("kwargs", {})
        has_sensitive = any(k in kwargs for k in SENSITIVE_FIELDS)
        receipts = receipts_chain([a])
        res = check(toolpol, Transcript(response="",
                                        receipts=trace.receipts_from_json(receipts)))
        flagged = not res.passed
        if flagged and has_sensitive:
            tp += 1
        elif flagged and not has_sensitive:
            fp += 1
        elif not flagged and not has_sensitive:
            tn += 1
        else:
            fn += 1
        tool_vectors.append({"tool": a["name"], "kwargs": kwargs,
                             "has_sensitive": has_sensitive,
                             "predicted": "violation" if flagged else "pass"})

    # ---- ② budget_bound ----
    budgetpol = Policy(
        id="budget-taubench-v1", version="0.1.0", semantic="and",
        rules=[Rule("budget_bound", "call_budget", {"budget": 3, "unit": "calls"})],
    )
    bt = bf = btn = bfn = 0
    budget_vectors = []
    for t in trajs:
        actions = t["info"]["task"]["actions"]
        n_calls = len(actions)
        over_budget = n_calls > 3
        receipts = receipts_chain(actions)
        res = check(budgetpol, Transcript(response="",
                                          receipts=trace.receipts_from_json(receipts)))
        flagged = not res.passed
        if flagged and over_budget:
            bt += 1
        elif flagged and not over_budget:
            bf += 1
        elif not flagged and not over_budget:
            btn += 1
        else:
            bfn += 1
        budget_vectors.append({"task_id": t["task_id"], "n_calls": n_calls,
                               "over_budget": over_budget,
                               "predicted": "violation" if flagged else "pass"})

    def p_r_f1(tp, fp, tn, fn):
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        return round(p, 4), round(r, 4), round(f, 4)

    tp_p, tp_r, tp_f = p_r_f1(tp, fp, tn, fn)
    bp, br, bf1 = p_r_f1(bt, bf, btn, bfn)

    # 落盘
    out = REPO / "scripts" / "examples" / "datasets"
    out.mkdir(parents=True, exist_ok=True)
    (REPO / "policy_packs" / "toolarg_taubench_v1.json").write_text(
        json.dumps({"id": "toolarg-taubench-v1", "version": "0.1.0", "semantic": "and",
                    "rules": [{"kind": "tool_arg_guard", "name": "no_sensitive_fields",
                               "params": {"forbidden_fields": SENSITIVE_FIELDS}}]},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    (REPO / "policy_packs" / "budget_taubench_v1.json").write_text(
        json.dumps({"id": "budget-taubench-v1", "version": "0.1.0", "semantic": "and",
                    "rules": [{"kind": "budget_bound", "name": "call_budget",
                               "params": {"budget": 3, "unit": "calls"}}]},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "taubench_toolarg_vectors.json").write_text(
        json.dumps(tool_vectors, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "taubench_budget_vectors.json").write_text(
        json.dumps(budget_vectors, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "taubench_results.json").write_text(json.dumps({
        "tool_arg_guard": {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                           "precision": tp_p, "recall": tp_r, "f1": tp_f},
        "budget_bound": {"tp": bt, "fp": bf, "tn": btn, "fn": bfn,
                         "precision": bp, "recall": br, "f1": bf1},
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"τ-bench 评测（{len(all_actions)} 次工具调用，{len(trajs)} 条轨迹）")
    print(f"\n① tool_arg_guard（禁字段 {SENSITIVE_FIELDS}）")
    print(f"   TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"   精确率={tp_p} 召回率={tp_r} F1={tp_f}")
    print(f"\n② budget_bound（预算 3 次调用）")
    print(f"   TP={bt} FP={bf} TN={btn} FN={bfn}")
    print(f"   精确率={bp} 召回率={br} F1={bf1}")
    print(f"\n产出: policy_packs/toolarg_taubench_v1.json / budget_taubench_v1.json")
    print(f"      scripts/examples/datasets/taubench_*_vectors.json / taubench_results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
