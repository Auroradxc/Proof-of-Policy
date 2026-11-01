#!/usr/bin/env python3
"""策略推断攻击基准（BHV §7.4 E4b：披露层级 L0/L1/L2）。

**要回答什么。** 一张证书的公开值在三个披露级别下分别泄露多少策略信息？
本脚本以 ``policy_packs/agent_content_v1.json`` 为模板生成 20 个策略变体，
对每个变体生成一批证书公开值（L0 / L1 / L2 三组），训练一个**标准库实现的
多项式朴素贝叶斯**分类器，报告：

* top-1 / top-3 策略识别准确率；
* 真实变体与预测变体之间的经验互信息（bits）与归一化值；
* **审计效用代理**：只看披露出来的违规类别，能否映射到具体的修复动作。

**分类器**：优先不依赖 sklearn —— 本脚本用标准库实现多项式 NB（Laplace
平滑，``alpha=1``），因此任何 Python 3 环境都能复现，不需要 pip。若环境里
装了 sklearn，``sklearn_available`` 字段会记 ``true``，但结果仍然来自标准库
实现（保证跨机器口径一致）。**没有 pip 安装任何东西。**

**边界**：这里量的是**证书公开值通道**。电路公开值仍是 raw ``rule``/``kind``；
L1/L2 只是证书层投影（见 ``policydsl/evidence/disclosure.py`` 与
``docs/blockers/C1.md``）。证明工件（``core`` trace）与重执行通道不在本基准内。

用法::

    python3 bench/bench_policy_infer.py --out-dir bench/results
    python3 bench/bench_policy_infer.py --variants 20 --seed 20261101
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl.core.compile import compile_policy           # noqa: E402
from policydsl.core.model import Policy                     # noqa: E402
from policydsl.evidence import disclosure                   # noqa: E402
from policydsl.privacy.commit import canonical_violations    # noqa: E402

DEFAULT_PACK = REPO / "policy_packs" / "agent_content_v1.json"

#: 具体修复动作（按**规则类型**）。L0 能看到 kind，所以能选到具体动作。
ACTION_BY_KIND = {
    "keyword_block": "remove_keyword",
    "normalized_keyword_block": "remove_normalized_keyword",
    "pattern_block": "rewrite_pattern_hit",
    "length_bound": "adjust_length",
    "format_check": "fix_format",
    "tool_arg_guard": "remove_tool_arg",
    "budget_bound": "reduce_budget",
    "trace_unbound": "repair_trace",
    "semantic_bound": "review_semantic",
}
#: 只看**类别**时能给出的最具体动作。内容类只能给通用动作，因此无法与
#: 关键词/正则的具体修复动作逐项对应 —— 这就是审计效用损失。
ACTION_BY_CATEGORY = {
    "content": "rewrite_content",
    "length": "adjust_length",
    "format": "fix_format",
    "tool_arguments": "rewrite_tool_args",
    "budget": "reduce_budget",
    "trace_integrity": "repair_trace",
    "semantic": "review_semantic",
    "other": "manual_review",
}
#: L2 看不到类别，只能人工分诊。
ACTION_L2 = "manual_review"


# ---------------------------------------------------------------------------
# 策略变体与响应
# ---------------------------------------------------------------------------

def make_variant(i: int) -> Dict[str, Any]:
    """第 ``i`` 个策略变体：3–5 条规则，名称/参数都带变体编号。

    变体之间的差异刻意覆盖三个层次：

    * **规则名**（L0 直接泄露）—— 每个变体都不同；
    * **规则类别组合**（L1 泄露）—— 偶数变体多一条 normalized 规则，
      3 的倍数多一条 format 规则，5 的倍数多一条第二关键词规则；
    * **证据/承诺**（L2 只剩不透明哈希）—— 三者都无法从承诺恢复语义。
    """
    rules: List[Dict[str, Any]] = [
        {"kind": "keyword_block", "name": f"kw_{i:02d}",
         "params": {"keywords": [f"secret_{i:02d}", f"token{i:02d}"]}},
        {"kind": "length_bound", "name": f"len_{i:02d}",
         "params": {"min": 1, "max": 120 + i * 7}},
        {"kind": "pattern_block", "name": f"pat_{i:02d}",
         "params": {"patterns": [f"sk-{i:02d}-[A-Za-z0-9]{{16,}}"]}},
    ]
    if i % 2 == 0:
        rules.append({"kind": "normalized_keyword_block", "name": f"nkw_{i:02d}",
                      "params": {"keywords": [f"banned{i:02d}"]}})
    if i % 3 == 0:
        rules.append({"kind": "format_check", "name": f"fmt_{i:02d}",
                      "params": {"format": "json"}})
    if i % 5 == 0:
        rules.append({"kind": "keyword_block", "name": f"kwb_{i:02d}",
                      "params": {"keywords": [f"extra_{i:02d}"]}})
    return {"id": f"infer-{i:02d}", "version": "0.1.0",
            "description": f"policy inference variant {i}",
            "semantic": "and", "rules": rules}


def _responses(i: int, n: int) -> List[str]:
    """每个变体固定一组响应模板，循环生成 ``n`` 条。

    模板覆盖单个规则、两条规则的组合与合规响应。变体里没有的规则对应的
    模板仍然保留（攻击者事先并不知道候选策略里有哪些规则），因此会自然
    产生「这条响应什么都不触发」的样本。
    """
    max_len = 120 + i * 7
    kw = f"secret_{i:02d}"
    nkw = f"banned{i:02d}"
    kwb = f"extra_{i:02d}"
    pat = f"sk-{i:02d}-ABCDEFGHIJKLMNOP"
    templates = [
        f"please {kw} now",                     # keyword
        "x" * (max_len + 7),                    # length
        pat,                                    # pattern
        nkw,                                    # normalized keyword (若存在)
        kwb,                                    # second keyword (若存在)
        "this is not json",                     # format (若存在)
        f"{kw} and {pat}",                      # keyword + pattern
        f"{kw} " + "x" * (max_len + 3),         # keyword + length
        f"{nkw} {pat}",                         # normalized + pattern
        f"{kwb} {pat}",                         # second keyword + pattern
        "all clear, nothing sensitive here",    # compliant
    ]
    return [f"{templates[j % len(templates)]} #case{j}" for j in range(n)]


def _raw_outcome(pack: Dict[str, Any], response: str) -> Dict[str, Any]:
    """参考层判定 → 与电路公开值同形的 outcome（只需要 violations）。"""
    policy = Policy.from_dict(pack)
    policy.validate()
    spec = compile_policy(policy)
    violations = canonical_violations(spec, response)
    return {"passed": not violations, "violations": violations}


def public_view(raw_outcome: Dict[str, Any], level: str) -> Tuple[str, ...]:
    """把一条证书公开值变成分类器特征（只读**披露后**的可见字段）。

    * L0：规则名 + 类型（每个 token 一次）；
    * L1：类别 + 每类计数 + 总违规数；
    * L2：只有违规条数（承诺是哈希，跨样本不可泛化，因此不进特征）。
    """
    proj = disclosure.project_violations(raw_outcome.get("violations") or [], level)
    feats: List[str] = []
    if level == disclosure.LEVEL_L0:
        for v in proj:
            feats.append(f"rule={v.get('rule')}")
            feats.append(f"kind={v.get('kind')}")
    elif level == disclosure.LEVEL_L1:
        for v in proj:
            feats.append(f"category={v['category']}:count={v['count']}")
        feats.append(f"total={sum(v['count'] for v in proj)}")
    else:  # L2
        feats.append(f"existence={min(len(proj), 4)}")
    return tuple(feats)


# ---------------------------------------------------------------------------
# 标准库多项式朴素贝叶斯
# ---------------------------------------------------------------------------

class MultinomialNB:
    """极简多项式 NB（Laplace ``alpha`` 平滑）。

    类别先验按样本数；似然按 token 频次。特征按出现次数计（同一条违规的
    ``rule=`` / ``kind=`` 各算一次；同一类别出现两次就计两次），因此
    「违规条数」本身也是信号。
    """

    def __init__(self, alpha: float = 1.0):
        self.alpha = alpha
        self.classes: List[int] = []
        self.vocab: Dict[str, int] = {}
        self.log_prior: Dict[int, float] = {}
        self.log_likelihood: Dict[int, List[float]] = {}
        self._doc_count: Dict[int, int] = {}

    def fit(self, X: Sequence[Sequence[str]], y: Sequence[int]) -> "MultinomialNB":
        self.classes = sorted(set(y))
        vocab = sorted({tok for row in X for tok in row})
        self.vocab = {tok: i for i, tok in enumerate(vocab)}
        counts: Dict[int, List[int]] = defaultdict(lambda: [0] * len(vocab))
        doc_count: Dict[int, int] = defaultdict(int)
        for row, label in zip(X, y):
            doc_count[label] += 1
            for tok in row:
                counts[label][self.vocab[tok]] += 1
        n = len(y)
        for c in self.classes:
            self.log_prior[c] = math.log((doc_count[c] + self.alpha) /
                                         (n + self.alpha * len(self.classes)))
            total = sum(counts[c]) + self.alpha * len(vocab)
            self.log_likelihood[c] = [
                math.log((counts[c][j] + self.alpha) / total)
                for j in range(len(vocab))
            ]
        self._doc_count = dict(doc_count)
        return self

    def decision_function(self, row: Sequence[str]) -> Dict[int, float]:
        counts = Counter(row)
        out: Dict[int, float] = {}
        for c in self.classes:
            score = self.log_prior[c]
            ll = self.log_likelihood[c]
            for tok, k in counts.items():
                j = self.vocab.get(tok)
                if j is not None:
                    score += k * ll[j]
            out[c] = score
        return out

    def predict_proba(self, row: Sequence[str]) -> Dict[int, float]:
        scores = self.decision_function(row)
        m = max(scores.values())
        exp = {c: math.exp(s - m) for c, s in scores.items()}
        z = sum(exp.values())
        return {c: v / z for c, v in exp.items()}

    def ranking(self, row: Sequence[str]) -> List[int]:
        scores = self.decision_function(row)
        return sorted(scores, key=lambda c: scores[c], reverse=True)


# ---------------------------------------------------------------------------
# 指标
# ---------------------------------------------------------------------------

def top_k_accuracy(rankings: Sequence[List[int]], truth: Sequence[int], k: int) -> float:
    if not truth:
        return 0.0
    return sum(1 for rank, t in zip(rankings, truth) if t in rank[:k]) / len(truth)


def mutual_information_bits(a: Sequence[int], b: Sequence[int]) -> float:
    """经验互信息 ``I(A;B)``（bits），由联合分布直接算。"""
    n = len(a)
    if n == 0:
        return 0.0
    joint = Counter(zip(a, b))
    pa = Counter(a)
    pb = Counter(b)
    mi = 0.0
    for (x, y), c in joint.items():
        pxy = c / n
        mi += pxy * math.log2(pxy / ((pa[x] / n) * (pb[y] / n)))
    return max(mi, 0.0)


def entropy_bits(xs: Sequence[int]) -> float:
    n = len(xs)
    if n == 0:
        return 0.0
    p = Counter(xs)
    return -sum((c / n) * math.log2(c / n) for c in p.values())


def action_utility(raw_violations: List[Dict[str, Any]], level: str) -> Tuple[float, int]:
    """审计效用代理：披露信息能选出的具体修复动作，与真实动作的重合率。

    只看**违规样本**。真实动作按 ``rule.kind`` 取 :data:`ACTION_BY_KIND`；
    披露侧按级别取能选到的**最具体**动作：

    * L0 有 kind → 具体动作，理应 1.0；
    * L1 只有类别 → 内容类只能给 ``rewrite_content``，与
      ``remove_keyword`` / ``rewrite_pattern_hit`` 不重合；长度/格式仍能对上；
    * L2 只有承诺 → ``manual_review``，与任何具体动作都不重合。

    返回 ``(匹配率, 违规条数)``；没有违规时返回 ``(0.0, 0)``。
    """
    true_actions = [ACTION_BY_KIND.get(v.get("kind"), "manual_review")
                    for v in raw_violations]
    if level == disclosure.LEVEL_L0:
        disclosed = [ACTION_BY_KIND.get(v.get("kind"), "manual_review")
                     for v in disclosure.project_violations(raw_violations, level)]
    elif level == disclosure.LEVEL_L1:
        disclosed = [ACTION_BY_CATEGORY.get(v["category"], "manual_review")
                     for v in disclosure.project_violations(raw_violations, level)]
    else:
        disclosed = [ACTION_L2] * len(raw_violations)
    total = len(true_actions)
    if total == 0:
        return 0.0, 0
    matched = sum((Counter(true_actions) & Counter(disclosed)).values())
    return matched / total, total


# ---------------------------------------------------------------------------
# 主实验
# ---------------------------------------------------------------------------

def _sklearn_available() -> bool:
    try:
        import sklearn  # noqa: F401
        return True
    except Exception:
        return False


def run(out_dir: Path, n_variants: int, seed: int, base_path: Path,
        train_per: int, test_per: int) -> Dict[str, Any]:
    rng = random.Random(seed)
    # 模板固定，但随机化变体顺序，避免类别编号与规则组合产生偶然相关。
    order = list(range(n_variants))
    rng.shuffle(order)
    variants = {i: make_variant(i) for i in range(n_variants)}

    train_rows: Dict[str, List[Tuple[Tuple[str, ...], int]]] = {
        level: [] for level in disclosure.LEVELS
    }
    test_rows: Dict[str, List[Tuple[Tuple[str, ...], int]]] = {
        level: [] for level in disclosure.LEVELS
    }
    raw_for_utility: Dict[str, List[Tuple[List[Dict[str, Any]], int]]] = {
        level: [] for level in disclosure.LEVELS
    }
    for i in order:
        pack = variants[i]
        train_responses = _responses(i, train_per)
        test_responses = _responses(i, train_per + test_per)[train_per:]
        for response in train_responses:
            raw = _raw_outcome(pack, response)
            for level in disclosure.LEVELS:
                train_rows[level].append((public_view(raw, level), i))
        for response in test_responses:
            raw = _raw_outcome(pack, response)
            for level in disclosure.LEVELS:
                test_rows[level].append((public_view(raw, level), i))
                raw_for_utility[level].append((raw.get("violations") or [], i))

    levels: Dict[str, Any] = {}
    for level in disclosure.LEVELS:
        X_train = [r[0] for r in train_rows[level]]
        y_train = [r[1] for r in train_rows[level]]
        X_test = [r[0] for r in test_rows[level]]
        y_test = [r[1] for r in test_rows[level]]

        model = MultinomialNB().fit(X_train, y_train)
        rankings = [model.ranking(x) for x in X_test]
        preds = [r[0] for r in rankings]
        top1 = top_k_accuracy(rankings, y_test, 1)
        top3 = top_k_accuracy(rankings, y_test, 3)
        mi = mutual_information_bits(y_test, preds)
        h = entropy_bits(y_test)
        util_num = util_den = 0
        for raw_violations, _label in raw_for_utility[level]:
            u, n = action_utility(raw_violations, level)
            util_num += u * n
            util_den += n
        levels[level] = {
            "features": _feature_doc(level),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "classes": len(model.classes),
            "top1": round(top1, 4),
            "top3": round(top3, 4),
            "chance_top1": round(1.0 / max(len(model.classes), 1), 4),
            "mi_bits": round(mi, 4),
            "entropy_bits": round(h, 4),
            "normalized_mi": round(mi / h, 4) if h else 0.0,
            "action_utility": round(util_num / util_den, 4) if util_den else 0.0,
            "violating_cases": util_den,
        }

    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "base_pack": str(base_path.relative_to(REPO)),
        "seed": seed,
        "variants": n_variants,
        "train_per_variant": train_per,
        "test_per_variant": test_per,
        "classifier": "stdlib multinomial naive Bayes (alpha=1)",
        "sklearn_available": _sklearn_available(),
        "levels": levels,
        "notes": [
            "Classifier is implemented with the standard library; no pip install "
            "was performed. sklearn, if present, is not used.",
            "L0 exposes rule + kind; L1 exposes category + count; L2 exposes only "
            "opaque evidence commitments (the feature uses violation count only, "
            "because hashes do not generalize across samples).",
            "Action utility is a proxy: L0 maps kind -> specific repair action; "
            "L1 maps category -> generic action (content cannot distinguish "
            "keyword vs pattern); L2 -> manual review.",
            "This measures the certificate public-value channel only. Circuit "
            "public values still contain raw rule/kind (see docs/blockers/C1.md).",
        ],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "policy_infer.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out_dir / "policy_infer.md").write_text(render_md(result), encoding="utf-8")
    return result


def _feature_doc(level: str) -> str:
    return {
        disclosure.LEVEL_L0: "rule name + kind (per violation)",
        disclosure.LEVEL_L1: "category + per-category count + total",
        disclosure.LEVEL_L2: "violation count only (commitments are opaque hashes)",
    }[level]


def render_md(r: Dict[str, Any]) -> str:
    rows = []
    for level in disclosure.LEVELS:
        d = r["levels"][level]
        rows.append(
            f"| {level} | {d['features']} | {d['top1']:.3f} | {d['top3']:.3f} | "
            f"{d['mi_bits']:.3f} | {d['normalized_mi']:.3f} | "
            f"{d['action_utility']:.3f} |")
    table = "\n".join(rows)
    return f"""# 策略推断攻击基准（披露层级 L0/L1/L2，E4b）

**生成时间**：{r['generated_at']}
**模板**：`{r['base_pack']}` ｜ **种子**：{r['seed']} ｜ **变体数**：{r['variants']}
**训练/测试**：每变体 {r['train_per_variant']} / {r['test_per_variant']} 条
**分类器**：`{r['classifier']}`（sklearn 可用={r['sklearn_available']}，未使用、未安装）

## 结果

| 级别 | 公开值特征 | top-1 | top-3 | 互信息 (bits) | 归一化 MI | 修复动作匹配率 |
|---|---|---:|---:|---:|---:|---:|
{table}

随机猜的 top-1 是 `{r['levels']['L0']['chance_top1']:.3f}`（{r['levels']['L0']['classes']} 类）。

## 怎么读

- **L0 → L1 → L2 的准确率与互信息应当单调下降**：这是披露层级在起作用的直接
  证据。若某一级没有下降，说明该级的投影没有真正删掉可区分的字段。
- **L1 仍泄露规则类别**：它比 L0 弱，但不是零泄露。即使看不到规则名，
  「这条策略含内容类规则 + 长度规则」仍能缩小候选集。
- **L2 接近随机**：承诺是 256-bit 哈希，跨样本不可泛化；本基准对 L2 只用
  违规条数做特征。如果未来把证据明文或稳定类别漏进 L2，准确率会异常升高。
- **审计效用**：L0 能把 kind 映射到具体修复动作（如「删关键词」）；L1 的内容类
  只能给「重写内容」这种通用动作，与具体动作不重合；L2 只能人工分诊。这不是
  「准确率越低越好」的单目标 —— 披露层级是在推断风险与审计效用之间选点。

## 边界

- 只量**证书公开值通道**。电路公开值仍是 raw `rule`/`kind`；证明工件（`core`
  trace）与重执行通道不在本基准内。见 `docs/blockers/C1.md`。
- 分类器是标准库多项式 NB，不是攻击上限；更强的分类器只会让 L0/L1 的
  数字更高，不会让 L2 的承诺变得可解释。

## 复现

```bash
python3 bench/bench_policy_infer.py --out-dir bench/results
```
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", default=str(REPO / "bench" / "results"))
    ap.add_argument("--variants", type=int, default=20)
    ap.add_argument("--seed", type=int, default=20261101)
    ap.add_argument("--base-pack", default=str(DEFAULT_PACK))
    ap.add_argument("--train-per-variant", type=int, default=40)
    ap.add_argument("--test-per-variant", type=int, default=15)
    args = ap.parse_args()
    result = run(Path(args.out_dir), args.variants, args.seed, Path(args.base_pack),
                 args.train_per_variant, args.test_per_variant)
    for level in disclosure.LEVELS:
        d = result["levels"][level]
        print(f"{level}: top1={d['top1']:.3f} top3={d['top3']:.3f} "
              f"MI={d['mi_bits']:.3f} utility={d['action_utility']:.3f}")
    print(f"wrote {Path(args.out_dir) / 'policy_infer.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
