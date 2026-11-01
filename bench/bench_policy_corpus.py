#!/usr/bin/env python3
"""策略语料级推断攻击（E2：真实响应 × 更大候选策略集 × L0/L1/L2）。

**与 ``bench_policy_infer.py`` 的分工。** 那个脚本回答「披露层级本身是否
按设计逐级变弱」：20 个同模板变体、11 条模板生成的合成响应、每变体 55 条。
论文审计（``docs/paper-inputs/audit.md`` P0-7）指出它的语料是**合成**的，
不能支撑「真实 LLM 响应上的推断风险」这句话。本脚本补这一块：

* **候选策略**：以 ``policy_packs/*.json`` 的 13 个策略包为模板，生成
  ≥300 个候选（每包 3–8 条规则；关键词/正则/参数/顺序/命名变体；固定种子）。
  每个候选都真的走 ``Policy.from_dict → compile_policy``，记录 ``policy_hash``，
  并检查与 13 个随包策略的哈希、以及候选之间的哈希都不冲突。
* **真实响应**：消费 X2c chat 的样本文件
  ``bench/results/x2_chat/k_samples_chat.jsonl``（400 行，按响应正文去重后
  220 条；本脚本只读文件，**不走** X2c 的 chat-template 代码路径）。
* **构造性补充**：真实 chat 响应会触发大量**粗粒度**规则（自然语言不是 JSON、
  长回复越界、token 预算超限），但**内容**命中很少（300 候选 × 66 条 holdout
  里 keyword/pattern/normalized 只有 217 条），工具/检索规则在 chat 里根本没有
  回执。为了测量内容与工具规则的泄露，脚本从每个候选**自己的参数**派生出一组
  构造性刺激（关键词、同形字、正则样本、超长、非 JSON、工具回执、预算、检索
  分数）。构造性样本与真实样本**分开报告**，不混成一个「真实」数字。
* **攻击者**：标准库多项式朴素贝叶斯（复用 ``bench_policy_infer.MultinomialNB``，
  不装 sklearn），标签是候选策略，特征是**证书公开值**里披露出来的字段：

  - L0：``rule`` + ``kind``（每条违规）；
  - L1：``category:count`` + ``violation_count``；
  - L2：``evidence_commitment`` + 违规条数（**实际载荷形状**）；
  - L2-count-only：只用违规条数（A1 旧口径；用来显式对照「承诺不进特征」的假设）。

* **审计效用**：仍用 ``bench_policy_infer.action_utility`` 的代理 —— 披露出的
  类别能否选到与真实 ``kind`` 对应的具体修复动作。
* **对照**：语料规模 50 / 100 / 300 × 披露层级 L0/L1/L2。

**L2 承诺可链接性（本脚本相对 A1 的关键修正）。** ``disclosure.project_violations``
的 L2 承诺是 ``SHA256(evidence)``：同一条规则在**不同响应**上命中时，只要证据
相同（关键词值、正则字符串、``len=N``），承诺就逐字节相同。因此「哈希跨样本
不可泛化」这个假设不成立 —— 攻击者可以建一张 ``commitment → 策略`` 的字典。
本脚本把 L2 的承诺**放进特征**（那才是证书真实公开的内容），并额外跑一个显式
字典攻击；同时保留 count-only 行，让两条口径的差距可见。这是审计发现，不是
脚本为了抬高数字做的构造。

**边界（不 overclaim）。**

* 只量**证书载荷的 violations 通道**。证书里还有 ``policy.id`` 与
  ``policy_hash`` —— 候选语料已知时它们直接给出策略身份（top-1 = 1.0）。
  本脚本刻意**不把它们**放进特征，否则整个攻击没有信息量；报告里单独列一行
  平凡通道，并注明 ``policy_nonce`` 是关掉它的手段（BHV 定理 D）。
* 仍是**证书层**披露，不是电路级隐藏；证明公开值通道仍是 raw rule/kind
  （见 ``docs/blockers/C1.md``）。
* 不跑 SP1、不改 core/cert。构造性刺激只测「参考层判定 + 证书投影」的字段
  形状，证书载荷由 ``cert.build_payload`` 抽样自检，逐次攻击用等价的
  ``disclosure.project_outcome``（纯函数，字段形状相同）。

用法::

    python3 bench/bench_policy_corpus.py --out-dir bench/results
    python3 bench/bench_policy_corpus.py --candidates 300 --sizes 50 100 300
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

REPO = Path(__file__).resolve().parents[1]
BENCH = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(BENCH))

from policydsl.core.compile import compile_policy                 # noqa: E402
from policydsl.core.model import Policy                           # noqa: E402
from policydsl.evidence import cert, disclosure                   # noqa: E402
from policydsl.evidence.trace import (GENESIS, ToolReceipt,        # noqa: E402
                                      receipt_digest)
from policydsl.privacy.commit import canonical_violations          # noqa: E402

# 复用 A1 的分类器与指标，保证两套数字同口径。bench/ 不是包，按目录导。
from bench_policy_infer import (                                   # noqa: E402
    ACTION_BY_CATEGORY, ACTION_BY_KIND, ACTION_L2, MultinomialNB,
    action_utility, entropy_bits, mutual_information_bits, top_k_accuracy,
)

POLICY_DIR = REPO / "policy_packs"
DEFAULT_CHAT_SAMPLES = REPO / "bench" / "results" / "x2_chat" / "k_samples_chat.jsonl"
DEFAULT_SEED = 20261101

# ---------------------------------------------------------------------------
# 规则库：所有候选参数都从这里取，样本与正则成对出现，保证可构造命中。
# ---------------------------------------------------------------------------

#: ``(pattern, sample)``。sample 必须能被 pattern 搜到。
PATTERN_BANK: List[Tuple[str, str]] = [
    (r"[\w.+-]+@[\w-]+\.[\w.]+", "jane.doe@example.com"),
    (r"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}", "analyst@corp.example"),
    (r"\+?[0-9 ()-]{7,}", "+1 (415) 555-0100"),
    (r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", "(415) 555-0100"),
    (r"\d{3}-\d{2}-\d{4}", "123-45-6789"),
    (r"sk-[A-Za-z0-9]{16,}", "sk-" + "A" * 20),
    (r"sk-[A-Za-z0-9]{20,}", "sk-" + "B" * 24),
    (r"Bearer [A-Za-z0-9._~+/=-]{16,}", "Bearer " + "C" * 24),
    (r"Bearer [A-Za-z0-9._~+/=-]{20,}", "Bearer " + "D" * 28),
    (r"AKIA[0-9A-Z]{16}", "AKIAABCDEFGHIJKLMNOP"),
    (r"ghp_[A-Za-z0-9]{36}", "ghp_" + "a" * 36),
    (r"BEGIN (RSA |EC )?PRIVATE KEY", "BEGIN RSA PRIVATE KEY"),
    (r"\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}", "4111 1111 1111 1111"),
]

SHARED_KEYWORDS = [
    "exploit", "doxxing", "weaponize", "terrorism", "child abuse",
    "leverage", "margin call", "100x", "get rich", "guaranteed returns",
    "money laundering", "human trafficking", "identity theft",
    "internet browsing history", "social security number",
    "credit card details", "mental health history", "political affiliation",
]

TOOL_FIELDS = [
    "password", "token", "api_key", "payment_methods", "passengers",
    "card_number", "ssn", "secret",
]
TOOL_NAMES = ["search", "read_file", "send_email", "book_flight", "browser"]
RETRIEVAL_MIN = [25, 50, 70, 90]
LENGTH_MAXES = [64, 128, 256, 512, 1000, 1500, 2000, 4000]
FORMATS = ["json", "int", "float"]
FILL_KINDS = [
    "keyword_block", "normalized_keyword_block", "pattern_block",
    "length_bound", "format_check", "tool_arg_guard", "budget_bound",
    "retrieval_guard",
]

#: 同形字替换（只用于构造 ``normalized_keyword_block`` 的命中样本）。
_HOMOGLYPH = str.maketrans({"a": "а", "e": "е", "o": "о", "p": "р",
                            "c": "с", "x": "х", "y": "у", "i": "і"})


def _fold_evade(text: str) -> str:
    """把 ASCII 关键词换成同形字 —— 普通 ``keyword_block`` 不命中，
    ``normalized_keyword_block`` 折叠后命中。"""
    return text.translate(_HOMOGLYPH)


def _variant_pattern(i: int, base_pattern: str, unique: bool) -> Tuple[str, str]:
    """给 pattern 加一个候选专属前缀（可选），并返回能命中的样本。"""
    base_sample = _sample_for(base_pattern)
    if not unique:
        return base_pattern, base_sample
    prefix = f"case{i:03d}-"
    return prefix + base_pattern, prefix + base_sample


def _sample_for(pattern: str) -> str:
    for pat, sample in PATTERN_BANK:
        if pat == pattern:
            return sample
    raise KeyError(f"pattern bank has no sample for {pattern!r}")


# ---------------------------------------------------------------------------
# 候选策略生成
# ---------------------------------------------------------------------------

@dataclass
class Candidate:
    index: int
    pack: Dict[str, Any]
    spec: Dict[str, Any]
    policy_hash: str
    rule_count: int
    kinds: List[str]
    template: str
    naming: str
    signature: str          # "unique-evidence" / "shared-evidence"


def _rule_name(kind: str, template_name: str, i: int, j: int, unique: bool) -> str:
    if unique:
        return f"{template_name}__c{i:03d}_{j}"
    # 共享命名：按 kind 从一张固定的常见名字表里取，天然跨策略重合。
    base = {
        "keyword_block": "no_bad_topics",
        "normalized_keyword_block": "no_hidden_topics",
        "pattern_block": "no_secret",
        "length_bound": "bounded_reply",
        "format_check": "format_guard",
        "tool_arg_guard": "no_sensitive_fields",
        "budget_bound": "call_budget",
        "retrieval_guard": "min_relevance",
    }[kind]
    return base


def _mutate_params(kind: str, params: Dict[str, Any], i: int, j: int,
                   rng: random.Random, unique_evidence: bool) -> Dict[str, Any]:
    """按 kind 派生一组**合法且有区分度**的参数。"""
    p = copy.deepcopy(params)
    sig = f"sig{i:03d}" if unique_evidence else None
    if kind == "keyword_block":
        words = [str(w) for w in p.get("keywords", [])][:3]
        if not words:
            words = [rng.choice(SHARED_KEYWORDS)]
        if sig:
            words.append(sig)
        p = {"keywords": words}
    elif kind == "normalized_keyword_block":
        words = [str(w) for w in p.get("keywords", [])][:2]
        if not words:
            words = [rng.choice(SHARED_KEYWORDS)]
        if sig:
            words.append(f"hidden_{sig}")
        p = {"keywords": words}
    elif kind == "pattern_block":
        base_pat = (p.get("patterns") or [PATTERN_BANK[i % len(PATTERN_BANK)][0]])[0]
        pat, _sample = _variant_pattern(i, str(base_pat), unique=unique_evidence)
        p = {"patterns": [pat], "match_mode": rng.choice(["pike", "pike", "naive"])}
    elif kind == "length_bound":
        lo = rng.choice([0, 1])
        hi = rng.choice(LENGTH_MAXES)
        if hi < lo:
            hi = lo
        p = {"min": lo, "max": hi}
    elif kind == "format_check":
        p = {"format": rng.choice(FORMATS)}
    elif kind == "tool_arg_guard":
        fields = [str(f) for f in p.get("forbidden_fields", [])][:2]
        if not fields:
            fields = rng.sample(TOOL_FIELDS, k=2)
        p = {"forbidden_fields": sorted(set(fields))}
        if i % 3 == 0:
            p["tools"] = [rng.choice(TOOL_NAMES)]
    elif kind == "budget_bound":
        p = {"budget": rng.randrange(0, 9), "unit": rng.choice(["calls", "calls", "tokens"])}
    elif kind == "retrieval_guard":
        p = {"min_score": rng.choice(RETRIEVAL_MIN), "score_field": "relevance"}
        if i % 4 == 0:
            p["tools"] = [rng.choice(TOOL_NAMES)]
    return p


def _new_rule(kind: str, i: int, j: int, rng: random.Random,
              unique_evidence: bool, unique_naming: bool) -> Dict[str, Any]:
    name = _rule_name(kind, kind, i, j, unique_naming)
    params = _mutate_params(kind, {}, i, j, rng, unique_evidence)
    return {"kind": kind, "name": name, "params": params}


def make_candidate(i: int, template_pack: Dict[str, Any], rng: random.Random,
                   existing_hashes: Dict[str, str],
                   seen_hashes: Dict[str, int]) -> Candidate:
    """从模板派生第 ``i`` 个候选（3–8 条规则）。"""
    pack = copy.deepcopy(template_pack)
    pack["id"] = f"corpus-{i:04d}"
    pack["version"] = "0.1.0"
    pack["description"] = f"policy corpus candidate {i} (template {template_pack.get('id')})"
    # semantic_bound 的参考评估（canonical_violations）尚未实现，且它会把模型
    # 指纹固化进哈希；本实验不跑 SP1，故从候选中剔除，模板其余规则保留。
    base_rules = [r for r in pack.get("rules", []) if r.get("kind") != "semantic_bound"]
    pack["rules"] = base_rules

    unique_evidence = (i % 3 != 0)          # 2/3 候选带专属签名；1/3 共享参数
    unique_naming = (i % 2 == 0)            # 一半规则名唯一，一半沿用常见名
    target = 3 + (i * 7) % 6                # 3..8，覆盖全部规则数
    rules: List[Dict[str, Any]] = []
    for j, raw in enumerate(base_rules):
        kind = raw["kind"]
        name = raw.get("name", kind)
        if unique_naming:
            name = f"{name}__c{i:03d}_{j}"
        rules.append({
            "kind": kind,
            "name": name,
            "params": _mutate_params(kind, raw.get("params", {}), i, j, rng,
                                     unique_evidence),
        })
    while len(rules) < target:
        j = len(rules)
        kind = rng.choice(FILL_KINDS)
        rules.append(_new_rule(kind, i, j, rng, unique_evidence, unique_naming))
    if len(rules) > target:
        rules = rules[:target]
    # 规则顺序也变：L0 的 token 序列受顺序影响，L1 的类别桶顺序被投影排序掉。
    rng.shuffle(rules)
    # 同一策略内规则名必须唯一（共享命名表也可能撞名）。
    seen_names: set = set()
    for j, r in enumerate(rules):
        if r["name"] in seen_names:
            r["name"] = f"{r['name']}_{j}"
        seen_names.add(r["name"])

    pack["rules"] = rules
    policy = Policy.from_dict(pack)
    spec = compile_policy(policy)
    h = spec["sha256"]
    # 冲突不应发生；真发生了就换一个 id 再编译一次（id 进规范哈希），
    # 而不是静默接受一个撞哈希的候选。
    for attempt in range(5):
        if h not in existing_hashes and h not in seen_hashes:
            break
        pack["id"] = f"corpus-{i:04d}-dedupe{attempt}"
        spec = compile_policy(Policy.from_dict(pack))
        h = spec["sha256"]
    else:
        raise RuntimeError(f"candidate {i}: could not avoid a policy_hash collision")

    return Candidate(
        index=i, pack=pack, spec=spec, policy_hash=h,
        rule_count=len(pack["rules"]),
        kinds=[r["kind"] for r in pack["rules"]],
        template=str(template_pack.get("id")),
        naming="unique" if unique_naming else "shared",
        signature="unique-evidence" if unique_evidence else "shared-evidence",
    )


def build_corpus(n: int, seed: int) -> Tuple[List[Candidate], Dict[str, Any]]:
    packs = [json.loads(p.read_text(encoding="utf-8"))
             for p in sorted(POLICY_DIR.glob("*.json"))]
    if not packs:
        raise RuntimeError(f"no policy packs under {POLICY_DIR}")

    existing: Dict[str, str] = {}
    for path in sorted(POLICY_DIR.glob("*.json")):
        pack = json.loads(path.read_text(encoding="utf-8"))
        existing[compile_policy(Policy.from_dict(pack))["sha256"]] = pack.get("id", path.name)

    rng = random.Random(seed)
    candidates: List[Candidate] = []
    seen: Dict[str, int] = {}
    for i in range(n):
        template = packs[i % len(packs)]
        cand = make_candidate(i, template, rng, existing, seen)
        seen[cand.policy_hash] = i
        candidates.append(cand)

    stats = {
        "requested": n,
        "generated": len(candidates),
        "templates": sorted({c.template for c in candidates}),
        "template_count": len(packs),
        "existing_pack_hashes": existing,
        "existing_pack_count": len(existing),
        "unique_candidate_hashes": len({c.policy_hash for c in candidates}),
        "candidate_hashes": {str(c.index): c.policy_hash for c in candidates},
        "hash_collisions_with_existing": sorted(
            c.policy_hash for c in candidates if c.policy_hash in existing),
        "hash_collisions_within_corpus": len(candidates) - len({c.policy_hash for c in candidates}),
        "rule_count_distribution": dict(sorted(Counter(c.rule_count for c in candidates).items())),
        "kind_distribution": dict(sorted(Counter(k for c in candidates for k in c.kinds).items())),
        "naming_distribution": dict(Counter(c.naming for c in candidates)),
        "evidence_mode_distribution": dict(Counter(c.signature for c in candidates)),
    }
    return candidates, stats


# ---------------------------------------------------------------------------
# 刺激池：真实响应 + 构造性刺激
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Stimulus:
    text: str
    receipts: Tuple[ToolReceipt, ...] = ()
    kind: str = "text"


def _receipt_chain(specs: Sequence[Tuple[str, Dict[str, str]]]) -> Tuple[ToolReceipt, ...]:
    receipts: List[ToolReceipt] = []
    prev = GENESIS
    for seq, (tool, args) in enumerate(specs):
        r = ToolReceipt(seq=seq, tool=tool, args=dict(args), prev=prev)
        receipts.append(r)
        prev = receipt_digest(r)
    return tuple(receipts)


def load_real_responses(path: Path) -> List[Dict[str, Any]]:
    """读 X2c chat 样本文件，按 ``response`` 去重（只消费文件，不碰模板代码）。"""
    rows: List[Dict[str, Any]] = []
    seen: set = set()
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if row.get("error"):
                continue
            text = row.get("response")
            if not isinstance(text, str) or not text:
                continue
            if text in seen:
                continue
            seen.add(text)
            rows.append({
                "text": text,
                "prompt_id": row.get("prompt_id"),
                "prompt": row.get("prompt"),
                "label": row.get("label"),
                "type": row.get("type"),
                "temperature": row.get("temperature"),
                "sample_index": row.get("sample_index"),
            })
    # 稳定排序：同一份文件在任何机器上得到同一个 train/test 切分。
    rows.sort(key=lambda r: r["text"])
    return rows


def _pattern_sample_from_rule(rule: Dict[str, Any]) -> str:
    pattern = str(rule["params"]["patterns"][0])
    m = re.match(r"^(case\d{3}-)(.*)$", pattern)
    prefix, base = (m.group(1), m.group(2)) if m else ("", pattern)
    return prefix + _sample_for(base)


def _descriptors(cand: Candidate) -> List[Dict[str, Any]]:
    """为每个候选按**它自己的规则**生成一组刺激描述子。

    每组描述子至少覆盖每条规则一次；真实响应里几乎不出现的工具/检索/预算
    规则也会被构造性回执触发（否则这些规则在特征里永远缺席）。
    """
    ds: List[Dict[str, Any]] = []
    for j, rule in enumerate(cand.pack["rules"]):
        kind = rule["kind"]
        p = rule["params"]
        if kind == "keyword_block":
            for kw in p.get("keywords", [])[:2]:
                ds.append({"type": "keyword", "kw": kw, "rule": j})
        elif kind == "normalized_keyword_block":
            for kw in p.get("keywords", [])[:2]:
                ds.append({"type": "normalized", "kw": kw, "rule": j})
        elif kind == "pattern_block":
            ds.append({"type": "pattern", "sample": _pattern_sample_from_rule(rule),
                       "rule": j})
        elif kind == "length_bound":
            ds.append({"type": "length", "max": int(p["max"]), "rule": j})
        elif kind == "format_check":
            ds.append({"type": "format", "fmt": p["format"], "rule": j})
        elif kind == "tool_arg_guard":
            tools = p.get("tools") or TOOL_NAMES
            for field in p.get("forbidden_fields", [])[:2]:
                ds.append({"type": "tool_arg", "field": field,
                           "tool": tools[0], "rule": j})
        elif kind == "budget_bound":
            ds.append({"type": "budget", "budget": int(p["budget"]),
                       "unit": p.get("unit", "calls"), "rule": j})
        elif kind == "retrieval_guard":
            tools = p.get("tools") or TOOL_NAMES
            ds.append({"type": "retrieval", "min_score": int(p["min_score"]),
                       "field": p.get("score_field", "relevance"),
                       "tool": tools[0], "rule": j})
    ds.append({"type": "benign", "rule": -1})
    return ds


def render_stimulus(desc: Dict[str, Any], i: int, j: int) -> Stimulus:
    """把描述子渲染成 ``(text, receipts)``；``j`` 只做无害抖动。"""
    tag = f"case{i:03d}-{j:02d}"
    t = desc["type"]
    if t == "keyword":
        return Stimulus(f"please {desc['kw']} now {tag}", kind="keyword")
    if t == "normalized":
        return Stimulus(f"note {_fold_evade(str(desc['kw']))} here {tag}",
                        kind="normalized")
    if t == "pattern":
        return Stimulus(f"payload {desc['sample']} end {tag}", kind="pattern")
    if t == "length":
        target = int(desc["max"]) + 1 + (j % 4)
        suffix = f" {tag}"
        return Stimulus("x" * max(0, target - len(suffix)) + suffix, kind="length")
    if t == "format":
        body = "this is not json" if desc["fmt"] == "json" else "not-a-number"
        return Stimulus(f"{body} {tag}", kind="format")
    if t == "tool_arg":
        rec = _receipt_chain([(desc["tool"],
                               {"query": f"benign {tag}", desc["field"]: f"sensitive-{tag}"})])
        return Stimulus(f"tool call {tag}", receipts=rec, kind="tool_arg")
    if t == "budget":
        if desc["unit"] == "tokens":
            words = ["w"] * (int(desc["budget"]) + 2) + [tag]
            return Stimulus(" ".join(words), kind="budget_tokens")
        rec = _receipt_chain([(TOOL_NAMES[k % len(TOOL_NAMES)], {"query": f"q{k}-{tag}"})
                              for k in range(int(desc["budget"]) + 1)])
        return Stimulus(f"tool loop {tag}", receipts=rec, kind="budget_calls")
    if t == "retrieval":
        args = {desc["field"]: str(int(desc["min_score"]) - 1), "query": tag}
        rec = _receipt_chain([(desc["tool"], args)])
        return Stimulus(f"retrieval {tag}", receipts=rec, kind="retrieval")
    return Stimulus(f"all clear, nothing sensitive here {tag}", kind="benign")


def constructive_stimuli(cand: Candidate, n_train: int, n_test: int) -> Tuple[
        List[Stimulus], List[Stimulus]]:
    """每个候选按自己的规则生成 ``n_train + n_test`` 条刺激，前段训练后段测试。"""
    ds = _descriptors(cand)
    out: List[Stimulus] = []
    for j in range(n_train + n_test):
        desc = ds[j % len(ds)]
        out.append(render_stimulus(desc, cand.index, j))
    return out[:n_train], out[n_train:]


# ---------------------------------------------------------------------------
# 证书公开值 → 特征
# ---------------------------------------------------------------------------

def cert_outcome(spec: Dict[str, Any], violations: List[Dict[str, Any]],
                 level: str) -> Dict[str, Any]:
    """与 ``cert.build_payload(disclosure_level=...)`` 写进载荷的 outcome 同形。"""
    raw = {"passed": not violations, "violations": violations}
    return disclosure.project_outcome(raw, level)


def features_for(outcome: Dict[str, Any], level: str,
                 l2_mode: str = "full") -> Tuple[str, ...]:
    violations = outcome.get("violations") or []
    feats: List[str] = []
    if level == disclosure.LEVEL_L0:
        for v in violations:
            feats.append(f"rule={v.get('rule')}")
            feats.append(f"kind={v.get('kind')}")
    elif level == disclosure.LEVEL_L1:
        for v in violations:
            feats.append(f"category={v['category']}:count={v['count']}")
        feats.append(f"total={outcome.get('violation_count', 0)}")
    else:  # L2
        if l2_mode == "count_only":
            feats.append(f"n={len(violations)}")
        else:
            for v in violations:
                feats.append(f"commit={v['evidence_commitment']}")
            feats.append(f"n={len(violations)}")
    return tuple(feats)


# ---------------------------------------------------------------------------
# 数据集与指标
# ---------------------------------------------------------------------------

def evaluate_level(train_features: Sequence[Tuple[str, ...]],
                   train_labels: Sequence[int],
                   test_features: Sequence[Tuple[str, ...]],
                   test_labels: Sequence[int],
                   test_raw: Sequence[List[Dict[str, Any]]],
                   level: str) -> Dict[str, Any]:
    model = MultinomialNB().fit(train_features, train_labels)
    # 空特征行（无违规）的后验只由先验决定：缓存排序，300 类时能省一大截。
    empty_ranking = sorted(model.classes,
                           key=lambda c: model.log_prior[c], reverse=True)
    rankings: List[List[int]] = []
    for row in test_features:
        rankings.append(empty_ranking if not row else model.ranking(row))
    preds = [r[0] for r in rankings]
    top1 = top_k_accuracy(rankings, test_labels, 1)
    top3 = top_k_accuracy(rankings, test_labels, 3)
    mi = mutual_information_bits(test_labels, preds)
    h = entropy_bits(test_labels)
    # 「有证据」按**原始违规**判，而不是按特征 token：L2-count-only 的
    # 特征只有 ``n=``，拿特征判会把它误当成「没有证据」。
    covered = [k for k, violations in enumerate(test_raw) if violations]
    top1_cov = (sum(1 for k in covered if test_labels[k] == preds[k]) / len(covered)
                if covered else 0.0)
    top3_cov = (sum(1 for k in covered if test_labels[k] in rankings[k][:3]) /
                len(covered) if covered else 0.0)
    util_num = util_den = 0
    for violations in test_raw:
        u, n = action_utility(violations, level)
        util_num += u * n
        util_den += n
    return {
        "train_samples": len(train_features),
        "test_samples": len(test_features),
        "classes": len(model.classes),
        "vocab": len(model.vocab),
        "top1": round(top1, 4),
        "top3": round(top3, 4),
        "chance_top1": round(1.0 / max(len(model.classes), 1), 4),
        "mi_bits": round(mi, 4),
        "entropy_bits": round(h, 4),
        "normalized_mi": round(mi / h, 4) if h else 0.0,
        "action_utility": round(util_num / util_den, 4) if util_den else 0.0,
        "violating_cases": util_den,
        "evidence_coverage": round(len(covered) / max(len(test_features), 1), 4),
        "top1_on_covered": round(top1_cov, 4),
        "top3_on_covered": round(top3_cov, 4),
        "covered_samples": len(covered),
    }


def commitment_dictionary_attack(train_features: Sequence[Tuple[str, ...]],
                                 train_labels: Sequence[int],
                                 test_features: Sequence[Tuple[str, ...]],
                                 test_labels: Sequence[int]) -> Dict[str, Any]:
    """显式字典攻击：``commitment → 训练集里最常见的策略``。

    NB 已经能学到同一件事；这里单独量一次，是为了把「L2 承诺跨样本可链接」
    这个机制与分类器的其它效应分开。
    """
    table: Dict[str, Counter] = defaultdict(Counter)
    for row, label in zip(train_features, train_labels):
        for tok in row:
            if tok.startswith("commit="):
                table[tok][label] += 1
    covered = [(row, label) for row, label in zip(test_features, test_labels)
               if any(tok.startswith("commit=") for tok in row)]
    hits = 0
    for row, label in covered:
        votes: Counter = Counter()
        for tok in row:
            if tok.startswith("commit=") and tok in table:
                votes.update(table[tok])
        if votes and votes.most_common(1)[0][0] == label:
            hits += 1
    return {
        "dictionary_entries": len(table),
        "covered_test_samples": len(covered),
        "coverage": round(len(covered) / max(len(test_features), 1), 4),
        "top1_on_covered": round(hits / len(covered), 4) if covered else 0.0,
    }


# ---------------------------------------------------------------------------
# 主实验
# ---------------------------------------------------------------------------

def _feature_block(candidates: Sequence[Candidate],
                   stimuli: Sequence[Sequence[Stimulus]],
                   levels: Sequence[str]) -> Dict[str, List[List[Tuple[str, ...]]]]:
    """对每个候选 × 每组刺激算证书投影特征。

    返回 ``{level_key: [[policy0 的所有样本], [policy1 ...], ...]}``。
    """
    keys = list(levels) + ["L2_count_only"]
    out: Dict[str, List[List[Tuple[str, ...]]]] = {k: [] for k in keys}
    raws: List[List[List[Dict[str, Any]]]] = []
    for cand, group in zip(candidates, stimuli):
        feats = {k: [] for k in keys}
        raw_group: List[List[Dict[str, Any]]] = []
        for stim in group:
            violations = canonical_violations(cand.spec, stim.text,
                                              list(stim.receipts))
            raw_group.append(violations)
            for level in levels:
                proj = cert_outcome(cand.spec, violations, level)
                feats[level].append(features_for(proj, level))
            # L2 count-only 与 L2 full 共用同一投影，只是特征不同。
            proj_l2 = cert_outcome(cand.spec, violations, disclosure.LEVEL_L2)
            feats["L2_count_only"].append(features_for(proj_l2, disclosure.LEVEL_L2,
                                                       l2_mode="count_only"))
        for k in keys:
            out[k].append(feats[k])
        raws.append(raw_group)
    out["_raws"] = raws  # type: ignore[assignment]
    return out


def _collect(per_policy_feats: Dict[str, List[List[Tuple[str, ...]]]],
             per_policy_raws: List[List[List[Dict[str, Any]]]],
             train_idx: Sequence[int], test_idx: Sequence[int],
             n_classes: int, key: str) -> Tuple[List[Tuple[str, ...]], List[int],
                                                List[Tuple[str, ...]], List[int],
                                                List[List[Dict[str, Any]]]]:
    train_x: List[Tuple[str, ...]] = []
    train_y: List[int] = []
    test_x: List[Tuple[str, ...]] = []
    test_y: List[int] = []
    test_raw: List[List[Dict[str, Any]]] = []
    for label in range(n_classes):
        feats = per_policy_feats[key][label]
        raw = per_policy_raws[label]
        for j in train_idx:
            train_x.append(feats[j])
            train_y.append(label)
        for j in test_idx:
            test_x.append(feats[j])
            test_y.append(label)
            test_raw.append(raw[j])
    return train_x, train_y, test_x, test_y, test_raw


def run(out_dir: Path, n_candidates: int, seed: int, sizes: Sequence[int],
        chat_path: Path, train_real_frac: float = 0.7,
        constructive_train: int = 24, constructive_test: int = 12) -> Dict[str, Any]:
    t0 = time.time()
    candidates, corpus_stats = build_corpus(n_candidates, seed)
    real = load_real_responses(chat_path)
    if len(real) < 100:
        raise RuntimeError(f"only {len(real)} unique real responses; acceptance needs >=100")

    # 构造性刺激：每个候选自己的规则 → 固定 train/test 段。
    con_groups = [constructive_stimuli(c, constructive_train, constructive_test)
                  for c in candidates]
    con_train = [g[0] for g in con_groups]
    con_test = [g[1] for g in con_groups]

    real_texts = [r["text"] for r in real]
    n_real_train = max(1, int(len(real_texts) * train_real_frac))
    real_train_idx = list(range(n_real_train))
    real_test_idx = list(range(n_real_train, len(real_texts)))
    # 每个 per-policy 的 real_test 特征列表是**局部**下标（0..n_test-1），
    # 与真实文件里的全局下标不同 —— 别把全局下标喂给局部列表。
    real_train_local = list(range(len(real_train_idx)))
    real_test_local = list(range(len(real_test_idx)))
    real_train_stims = [[Stimulus(t, kind="real") for t in real_texts[:n_real_train]]
                        for _ in candidates]
    real_test_stims = [[Stimulus(t, kind="real") for t in real_texts[n_real_train:]]
                       for _ in candidates]

    # 特征只算一次；三种语料规模都是这份特征的前缀。
    feats = {
        "constructive_train": _feature_block(candidates, con_train, disclosure.LEVELS),
        "constructive_test": _feature_block(candidates, con_test, disclosure.LEVELS),
        "real_train": _feature_block(candidates, real_train_stims, disclosure.LEVELS),
        "real_test": _feature_block(candidates, real_test_stims, disclosure.LEVELS),
    }

    # cert.build_payload 抽样自检：证明我们算的 outcome 与真实载荷逐字节同形。
    sample_pack = candidates[0]
    sample_raw = {"passed": False, "violations": canonical_violations(
        sample_pack.spec, "please exploit now")}
    shape_samples = {}
    for level in disclosure.LEVELS:
        payload = cert.build_payload(
            sample_pack.pack["id"], sample_pack.pack["version"], sample_pack.spec,
            "reference", sample_raw, "0" * 64, disclosure_level=level)
        expected = disclosure.project_outcome(sample_raw, level)
        if payload["outcome"] != expected:
            raise RuntimeError(f"build_payload outcome mismatch at {level}")
        shape_samples[level] = payload["outcome"]

    # 真实 holdout 上到底触发了什么：这份分布决定「真实数字」怎么读。
    real_rows = 0
    real_with_violations = 0
    real_kinds: Counter = Counter()
    real_policies_with_any = 0
    for raw_group in feats["real_test"]["_raws"]:
        policy_hit = False
        for violations in raw_group:
            real_rows += 1
            if violations:
                real_with_violations += 1
                policy_hit = True
            for v in violations:
                real_kinds[v.get("kind", "?")] += 1
        real_policies_with_any += 1 if policy_hit else 0
    real_profile = {
        "test_policy_response_rows": real_rows,
        "rows_with_violations": real_with_violations,
        "row_evidence_coverage": round(real_with_violations / max(real_rows, 1), 4),
        "policies_with_any_violation": real_policies_with_any,
        "policies_with_any_violation_fraction": round(
            real_policies_with_any / max(len(candidates), 1), 4),
        "violation_kind_counts": dict(sorted(real_kinds.items())),
        "content_rule_hits": sum(real_kinds.get(k, 0) for k in (
            "keyword_block", "normalized_keyword_block", "pattern_block")),
        "note": (
            "Real chat responses are prose, so format_check / length_bound / "
            "token-budget rules fire often; semantic content hits (keyword / "
            "pattern / normalized) are rare. This is why L1 still has high audit "
            "utility on real responses: the dominant categories map losslessly to "
            "repair actions. Constructive stimuli cover the content/tool rules."),
    }

    levels = list(disclosure.LEVELS)
    datasets: Dict[str, Any] = {}
    for size in sizes:
        if size > len(candidates):
            continue
        k = size
        blocks: Dict[str, Any] = {}

        # ---- 构造性（平衡、违规充足）----
        con_levels = {}
        for key in levels:
            per = feats["constructive_train"][key]
            per_test = feats["constructive_test"][key]
            train_x, train_y, _, _, _ = _collect(
                feats["constructive_train"], feats["constructive_train"]["_raws"],
                list(range(constructive_train)), [], k, key)
            _, _, test_x, test_y, test_raw = _collect(
                feats["constructive_test"], feats["constructive_test"]["_raws"],
                [], list(range(constructive_test)), k, key)
            con_levels[key] = evaluate_level(train_x, train_y, test_x, test_y,
                                             test_raw, key)
        # L2 count-only 对照
        con_levels["L2_count_only"] = _eval_subset(
            feats["constructive_train"], feats["constructive_test"],
            k, list(range(constructive_train)), list(range(constructive_test)),
            "L2_count_only", disclosure.LEVEL_L2)
        blocks["constructive"] = {
            "description": "per-policy stimuli derived from each candidate's own rules",
            "levels": con_levels,
            "l2_commitment_dictionary": _dict_for(
                feats["constructive_train"], feats["constructive_test"],
                k, list(range(constructive_train)), list(range(constructive_test))),
        }

        # ---- 真实响应（X2c chat）----
        real_levels = {}
        for key in levels:
            train_x, train_y, _, _, _ = _collect(
                feats["real_train"], feats["real_train"]["_raws"],
                real_train_idx, [], k, key)
            _, _, test_x, test_y, test_raw = _collect(
                feats["real_test"], feats["real_test"]["_raws"],
                [], real_test_local, k, key)
            real_levels[key] = evaluate_level(train_x, train_y, test_x, test_y,
                                              test_raw, key)
        real_levels["L2_count_only"] = _eval_subset(
            feats["real_train"], feats["real_test"], k,
            real_train_local, real_test_local, "L2_count_only", disclosure.LEVEL_L2)
        blocks["real"] = {
            "description": "X2c chat responses (deduplicated by response text)",
            "train_responses": len(real_train_idx),
            "test_responses": len(real_test_idx),
            "levels": real_levels,
        }

        # ---- 混合训练 / 真实测试（迁移）----
        mixed_levels = {}
        for key in levels:
            con_x, con_y, _, _, _ = _collect(
                feats["constructive_train"], feats["constructive_train"]["_raws"],
                list(range(constructive_train)), [], k, key)
            real_x, real_y, _, _, _ = _collect(
                feats["real_train"], feats["real_train"]["_raws"],
                real_train_idx, [], k, key)
            _, _, test_x, test_y, test_raw = _collect(
                feats["real_test"], feats["real_test"]["_raws"],
                [], real_test_local, k, key)
            mixed_levels[key] = evaluate_level(con_x + real_x, con_y + real_y,
                                               test_x, test_y, test_raw, key)
        # 混合训练的两个来源样本数不同，必须各按自己的下标收集后拼接。
        mc_x, mc_y, _, _, _ = _collect(
            feats["constructive_train"], feats["constructive_train"]["_raws"],
            list(range(constructive_train)), [], k, "L2_count_only")
        mr_x, mr_y, _, _, _ = _collect(
            feats["real_train"], feats["real_train"]["_raws"],
            real_train_idx, [], k, "L2_count_only")
        _, _, mt_x, mt_y, mt_raw = _collect(
            feats["real_test"], feats["real_test"]["_raws"],
            [], real_test_local, k, "L2_count_only")
        mixed_levels["L2_count_only"] = evaluate_level(
            mc_x + mr_x, mc_y + mr_y, mt_x, mt_y, mt_raw, disclosure.LEVEL_L2)
        blocks["mixed_train_real_test"] = {
            "description": "train on constructive + real-train; test on held-out real",
            "levels": mixed_levels,
        }
        datasets[str(k)] = blocks

    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": seed,
        "script": "bench/bench_policy_corpus.py",
        "candidate_corpus": corpus_stats,
        "response_sources": {
            "real_file": str(chat_path.relative_to(REPO)) if chat_path.is_relative_to(REPO)
            else str(chat_path),
            "real_file_rows": sum(1 for _ in chat_path.open(encoding="utf-8")),
            "real_unique_responses": len(real),
            "real_label_distribution": dict(Counter(r["label"] for r in real)),
            "real_type_distribution": dict(Counter(r["type"] for r in real)),
            "real_length_min": min(len(r["text"]) for r in real),
            "real_length_max": max(len(r["text"]) for r in real),
            "real_over_1500_chars": sum(1 for r in real if len(r["text"]) > 1500),
            "real_train_responses": n_real_train,
            "real_test_responses": len(real_test_idx),
            "constructive_train_per_policy": constructive_train,
            "constructive_test_per_policy": constructive_test,
            "constructive_note": (
                "Constructive stimuli are derived from each candidate's own rule "
                "parameters (keywords, regex samples, length max+1, non-JSON, tool "
                "receipts, budget overflow, low retrieval score). They are reported "
                "separately from real responses and are not claimed to be LLM output."),
            "real_violation_profile": real_profile,
        },
        "settings": {
            "classifier": "stdlib multinomial naive Bayes (alpha=1); reused from "
                          "bench_policy_infer.py",
            "sklearn_available": _sklearn_available(),
            "levels": levels,
            "l2_primary": "actual L2 payload: evidence_commitment tokens + count",
            "l2_count_only": "A1 convention: count only, commitments ignored",
            "sizes": [s for s in sizes if s <= len(candidates)],
            "real_train_fraction": train_real_frac,
            "policy_hash_channel_note": (
                "policy.id / policy_hash in the certificate payload are excluded "
                "from features by design; a candidate-corpus hash lookup would give "
                "top-1 = 1.0 unless policy_nonce is used (BHV theorem D)."),
            "trivial_channels": {
                "policy_id_lookup_top1": 1.0,
                "policy_hash_lookup_top1": 1.0,
                "note": "not used as attack features; listed to keep the boundary visible",
            },
        },
        "shape_self_check": {
            "checked_with": "policydsl.evidence.cert.build_payload",
            "sample_policy": sample_pack.pack["id"],
            "sample_outcomes": shape_samples,
        },
        "datasets": datasets,
        "running_seconds": round(time.time() - t0, 2),
        "notes": [
            "Certificate-layer disclosure only; circuit public values still carry "
            "raw rule/kind (docs/blockers/C1.md).",
            "L2 evidence commitments are deterministic SHA-256 of evidence, so the "
            "same evidence value is linkable across responses; we therefore include "
            "commitments in the L2 feature set (actual payload shape) and also "
            "report a count-only A1-style comparison.",
            "No SP1 proof was produced or verified.",
        ],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "policy_corpus_infer.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out_dir / "policy_corpus_infer.md").write_text(render_md(result), encoding="utf-8")
    return result


def _eval_subset(train_block: Dict[str, Any], test_block: Dict[str, Any], k: int,
                 train_idx: Sequence[int], test_idx: Sequence[int], key: str,
                 level: str) -> Dict[str, Any]:
    """只对某个特征口径（如 L2_count_only）收集并评估。"""
    train_x, train_y, _, _, _ = _collect(train_block, train_block["_raws"],
                                         train_idx, [], k, key)
    _, _, test_x, test_y, test_raw = _collect(test_block, test_block["_raws"],
                                              [], test_idx, k, key)
    return evaluate_level(train_x, train_y, test_x, test_y, test_raw, level)


def _dict_for(train_block: Dict[str, Any], test_block: Dict[str, Any], k: int,
              train_idx: Sequence[int], test_idx: Sequence[int]) -> Dict[str, Any]:
    train_x, train_y, _, _, _ = _collect(
        train_block, train_block["_raws"], train_idx, [], k, "L2")
    _, _, test_x, test_y, _ = _collect(
        test_block, test_block["_raws"], [], test_idx, k, "L2")
    return commitment_dictionary_attack(train_x, train_y, test_x, test_y)


def _sklearn_available() -> bool:
    try:
        import sklearn  # noqa: F401
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _row(name: str, d: Dict[str, Any]) -> str:
    return (f"| {name} | {d['top1']:.3f} | {d['top3']:.3f} | {d['mi_bits']:.3f} | "
            f"{d['normalized_mi']:.3f} | {d['action_utility']:.3f} | "
            f"{d['evidence_coverage']:.3f} | {d['top1_on_covered']:.3f} | "
            f"{d['violating_cases']} |")


def render_md(r: Dict[str, Any]) -> str:
    c = r["candidate_corpus"]
    sizes = r["settings"]["sizes"]
    main_size = max(sizes)
    blocks = r["datasets"][str(main_size)]

    def table(levels: Dict[str, Any]) -> str:
        rows = []
        for key in ["L0", "L1", "L2", "L2_count_only"]:
            d = levels[key]
            label = {"L0": "L0（rule+kind）", "L1": "L1（类别桶）",
                     "L2": "L2（承诺，实际载荷）",
                     "L2_count_only": "L2-count-only（A1 旧口径）"}[key]
            rows.append(_row(label, d))
        return "\n".join(rows)

    scaling_rows = []
    for key in ["L0", "L1", "L2"]:
        for size in sizes:
            d = r["datasets"][str(size)]["constructive"]["levels"][key]
            scaling_rows.append(
                f"| {key} | {size} | {d['top1']:.3f} | {d['top3']:.3f} | "
                f"{d['mi_bits']:.3f} | {d['normalized_mi']:.3f} | "
                f"{d['action_utility']:.3f} |")
    con = blocks["constructive"]
    real = blocks["real"]
    mixed = blocks["mixed_train_real_test"]
    rp = r["response_sources"]["real_violation_profile"]
    rk = rp["violation_kind_counts"]
    return f"""# 策略语料级推断攻击（E2：真实响应 × 300 候选 × L0/L1/L2）

**生成时间**：{r['generated_at']} ｜ **脚本**：[`bench/bench_policy_corpus.py`](../../bench/bench_policy_corpus.py) ｜ **种子**：{r['seed']}
**真实响应**：[`{r['response_sources']['real_file']}`](../../{r['response_sources']['real_file']})（{r['response_sources']['real_file_rows']} 行，按正文去重后 {r['response_sources']['real_unique_responses']} 条）
**结果数据**：[`bench/results/policy_corpus_infer.json`](../../bench/results/policy_corpus_infer.json)

## 1. 候选语料

| 项 | 值 |
|---|---|
| 模板策略包 | {c['template_count']} 个（`policy_packs/*.json`） |
| 生成候选 | {c['generated']} 个（请求 {c['requested']}） |
| 唯一 `policy_hash` | {c['unique_candidate_hashes']} 个 |
| 与现有包的哈希冲突 | {len(c['hash_collisions_with_existing'])} |
| 候选之间哈希冲突 | {c['hash_collisions_within_corpus']} |
| 规则数分布 | {c['rule_count_distribution']} |
| kind 分布 | {c['kind_distribution']} |
| 命名口径 | {c['naming_distribution']}（unique = 规则名带候选 id；shared = 沿用常见名） |
| 证据口径 | {c['evidence_mode_distribution']}（unique = 关键词/正则带候选签名） |

> `semantic_bound` 从候选中剔除：参考评估器 `canonical_violations` 对它是
> `NotImplementedError`，而且本实验不跑 SP1/ezkl。模板里的其余规则全部保留。

## 2. 响应

| 项 | 值 |
|---|---|
| 真实文件 | `{r['response_sources']['real_file']}` |
| 真实唯一响应 | {r['response_sources']['real_unique_responses']} 条（train {r['response_sources']['real_train_responses']} / test {r['response_sources']['real_test_responses']}） |
| 真实标签分布 | safe={r['response_sources']['real_label_distribution'].get('safe', 0)}，unsafe={r['response_sources']['real_label_distribution'].get('unsafe', 0)} |
| 真实长度范围 | {r['response_sources']['real_length_min']}–{r['response_sources']['real_length_max']} 字符（>1500：{r['response_sources']['real_over_1500_chars']} 条） |
| 构造性刺激 | 每候选 {r['response_sources']['constructive_train_per_policy']} train / {r['response_sources']['constructive_test_per_policy']} test，由该候选自己的规则参数派生 |

**真实响应触发了什么。** 220 条真实 chat 响应全是自然语言，没有一条超过
1478 字符。作用在 {r['candidate_corpus']['generated']} 个候选上、只看 holdout 时，
{rp['test_policy_response_rows']} 个 (policy, response) 里有 {rp['rows_with_violations']} 个带违规
（行覆盖率 {rp['row_evidence_coverage']:.3f}），{rp['policies_with_any_violation']} 个策略至少被一条真实
响应触发。但违规几乎全部来自粗粒度规则：format_check {rk.get('format_check', 0)} 条、
length_bound {rk.get('length_bound', 0)} 条、budget_bound {rk.get('budget_bound', 0)} 条 —— 自然语言不是
JSON、长回复越界、token 预算超限。**内容**命中（keyword/pattern/normalized）
只有 {rp['content_rule_hits']} 条。所以真实数字能测「粗粒度规则参数」的泄露，测不到
内容规则的泄露；构造性样本专门补后者（工具回执、检索分数、预算溢出也在其中）。
两类数字分开报告，不混成一个「真实」数字。

## 3. 主结果（{main_size} 个候选，构造性 holdout）

| 披露级别 | top-1 | top-3 | MI (bits) | 归一化 MI | 修复动作匹配率 | 证据覆盖率 | 有证据样本 top-1 | 违规条数 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
{table(con['levels'])}

* 随机猜 top-1 = {con['levels']['L0']['chance_top1']:.4f}（{con['levels']['L0']['classes']} 类）。
* **L2 不再是随机**：证书里的 `evidence_commitment = SHA256(evidence)` 是确定性的，
  同一条规则/同一个证据值在不同响应上给出同一串哈希，攻击者可以把它当稳定指纹
  建字典。`L2-count-only` 行保留 A1 的旧口径（把承诺丢掉、只数条数），两者差距
  就是「承诺可链接」这一发现的大小。
* `evidence_coverage` = 测试样本里至少披露出一条违规的比例；`top1_on_covered`
  只在这部分样本上算准确率，排除「空证书 → 只能猜先验」的稀释。
* L2 的修复动作匹配率不是严格 0（{con['levels']['L2']['action_utility']:.3f}）：`retrieval_guard`
  的真实动作本来就记为 `manual_review`，L2 的 `manual_review` 恰好与之重合；
  其余 kind 的 L2 效用仍是 0。

## 4. 真实响应（X2c chat，{real['levels']['L0']['classes']} 类）

| 披露级别 | top-1 | top-3 | MI (bits) | 归一化 MI | 修复动作匹配率 | 证据覆盖率 | 有证据样本 top-1 | 违规条数 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
{table(real['levels'])}

真实证据覆盖率是 {rp['row_evidence_coverage']:.3f}，但种类高度偏向 format/length/budget
（§2）。所以这组数字说明的是「**粗粒度规则的参数**（长度上界、token 预算、
是否做格式校验）很容易从真实证书反推」；内容规则上的收益要看构造性表。L1 的
审计效用在这组里偏高（{real['levels']['L1']['action_utility']:.3f}），正是因为真实违规多落在
「类别 → 动作」无损的长度/格式/预算类；L0 的 {real['levels']['L0']['action_utility']:.3f} 则是
定义上的上界。`top1_on_covered` 列只保留真正带违规的样本，是攻击者在真实
证书「有东西可看」时的收益。

## 5. 混合训练 → 真实测试（迁移）

训练集 = 构造性 train + 真实 train，测试集 = 留出的真实响应：

| 披露级别 | top-1 | top-3 | MI (bits) | 归一化 MI | 修复动作匹配率 | 证据覆盖率 | 有证据样本 top-1 | 违规条数 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
{table(mixed['levels'])}

## 6. 语料规模 × 披露级别（构造性 holdout）

| 级别 | 候选数 | top-1 | top-3 | MI (bits) | 归一化 MI | 修复动作匹配率 |
|---|---:|---:|---:|---:|---:|---:|
{chr(10).join(scaling_rows)}

规模从 50 增到 300 时，随机基线从 {1/50:.3f} 降到 {1/main_size:.3f}；看 top-1
的**绝对提升**要同时对照这条基线，不能只看数字本身。

## 7. L2 承诺字典攻击（机制对照）

| 数据集 | 字典条目 | 覆盖测试样本 | 覆盖率 | 覆盖样本 top-1 |
|---|---|---:|---:|---:|
| 构造性 | {con['l2_commitment_dictionary']['dictionary_entries']} | {con['l2_commitment_dictionary']['covered_test_samples']} | {con['l2_commitment_dictionary']['coverage']:.3f} | {con['l2_commitment_dictionary']['top1_on_covered']:.3f} |

这行的意义：即使分类器换掉、只做「哈希 → 策略」查表，L2 仍会泄露规则/证据的
身份。要关掉它，承诺必须**按证书加盐**（例如把 `policy_hash`、response nonce 或
签名者域一起哈希），或者只公开**桶级**承诺；当前 `disclosure.py` 的
`evidence_commitment` 是裸 `SHA256(evidence)`。

## 8. 与 A1（20 变体）的差异

| 维度 | A1 `bench_policy_infer.py` | E2 本脚本 |
|---|---|---|
| 候选策略 | 20 个同模板变体 | {c['generated']} 个、13 模板、3–8 规则、命名/证据两种口径 |
| 响应 | 11 条模板循环生成（**合成**） | 220 条真实 X2c chat 响应 + 构造性补充（分开报告） |
| L2 特征 | 只用违规条数（假设哈希不可泛化） | 实际载荷的承诺；另列 count-only 对照 |
| 规模曲线 | 无 | 50 / 100 / 300 |
| 结果 | L0 .810/.840；L1 .113/.313；L2 .073/.220（top-1/top-3） | 见上表 |

**一句话**：A1 的数字回答「层级设计是否单调」；E2 的数字回答「在更大、命名
更真实、响应更真实的语料上，各层到底泄露多少」，并暴露了 A1 假设掉的一个
渠道 —— **确定性的 L2 证据承诺可跨样本链接**。

## 9. 边界与 blocker

1. **证书层，不是电路层。** 证明公开值仍是 raw `rule`/`kind`；直接读证明或
   `core` 工件的人不经过本实验的投影。见 [`docs/blockers/C1.md`](../../docs/blockers/C1.md)。
2. **`policy.id` / `policy_hash` 被刻意排除。** 候选语料已知时，证书里的哈希
   本身就是策略身份（top-1 = 1.0）；本实验量的是 violations 通道。生产里要靠
   `policy_nonce`（BHV 定理 D）把字典攻击挡掉。
3. **真实 chat 响应只触发粗粒度规则。** {rp['content_rule_hits']} 条内容命中 vs
   format/length/budget 的几万条：这是 chat 场景的真实分布，不是脚本缺陷。要把
   内容/工具规则的推断风险测满，需要真实 agent/工具轨迹（带工具回执与违规
   输出），本 worktree 没有这类数据；构造性表补的正是这块。
4. **构造性样本不是 LLM 输出。** 它们由规则参数派生，只用于保证每条规则至少
   命中一次；不与真实响应合并成一个数字。
5. **未跑 SP1。** 字段形状用 `cert.build_payload` 抽样自检；没有证明工件、
   没有 vkey。

## 10. 复现

```bash
python3 bench/bench_policy_corpus.py --out-dir bench/results
python3 -m unittest tests.test_doc_links -v
```
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", default=str(REPO / "bench" / "results"))
    ap.add_argument("--candidates", type=int, default=300)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--sizes", type=int, nargs="+", default=[50, 100, 300])
    ap.add_argument("--chat-samples", default=str(DEFAULT_CHAT_SAMPLES))
    ap.add_argument("--constructive-train", type=int, default=24)
    ap.add_argument("--constructive-test", type=int, default=12)
    args = ap.parse_args()
    result = run(Path(args.out_dir), args.candidates, args.seed, args.sizes,
                 Path(args.chat_samples), constructive_train=args.constructive_train,
                 constructive_test=args.constructive_test)
    print(f"candidates={result['candidate_corpus']['generated']} "
          f"hashes={result['candidate_corpus']['unique_candidate_hashes']} "
          f"collisions={result['candidate_corpus']['hash_collisions_within_corpus']}")
    for size, blocks in result["datasets"].items():
        print(f"[{size} candidates]")
        for ds in ("constructive", "real", "mixed_train_real_test"):
            lv = blocks[ds]["levels"]
            print(f"  {ds}: " + " ".join(
                f"{k} top1={lv[k]['top1']:.3f}/top3={lv[k]['top3']:.3f}/"
                f"MI={lv[k]['mi_bits']:.3f}/util={lv[k]['action_utility']:.3f}"
                for k in ("L0", "L1", "L2")))
    print(f"wrote {Path(args.out_dir) / 'policy_corpus_infer.md'} "
          f"({result['running_seconds']}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
