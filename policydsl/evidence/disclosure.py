"""证书层披露层级（L0 / L1 / L2）与违规投影。

**边界（先读这一句）**：这不是电路级隐藏。SP1 guest 仍然把每条违规的
``rule`` 与 ``kind`` 写进证明公开值；本模块只在**证书层**决定载荷公开多少，
并让验证方按证书声明的级别把证明公开值重投影后比对。第三方若直接读取
证明公开值（或 ``core`` 档的证明工件），仍然能看到 raw ``rule`` / ``kind``。
电路级 coarsening（让公开值本身就只含类别）需要单独改电路并重建 vkey，
不在本模块的范围内 —— 见 ``docs/blockers/C1.md``。

三级披露
========

====================  ==================================================
级别                  证书载荷里的违规长什么样
====================  ==================================================
``L0``（旧行为）       ``{"rule", "kind", "evidence_commitment"}`` —— 规则
                       名 + 规则类型；明文 ``evidence`` 被换成承诺
``L1``                 ``[{"category", "count"}, ...]`` —— 只留**规则类别**
                       与每类违规数，外加顶层 ``violation_count``
``L2``                 ``[{"evidence_commitment"}, ...]`` —— 只有不透明承诺，
                       连类别与计数都不单独给出（列表长度即存在性）
====================  ==================================================

类别是**策略作者事先定义**的粗粒度桶（内容 / 长度 / 格式 / 工具参数 /
预算 / 轨迹 / 语义），不是规则名的截断，也不是规则类型的原样回显。
因此 L1 的推断面比 L0 小，但仍会泄露「策略里有哪些**种类**的规则」——
这正是 ``docs/security-model.md`` §4.6.4 ③ 要度量的泄露口，P1-06 的
``bench/bench_policy_infer.py`` 量化它。

为什么验证方要「重投影」而不是直接比对
======================================

电路公开值仍是 raw 形状。验证方读到 ``disclosure_level`` 后，自己对
``proof_outcome`` 调 :func:`project_outcome`，再与证书载荷比对。这样：

* 旧证书（没有 ``disclosure_level``）走原路径，逐字节行为不变；
* 新证书若声称 L1/L2，载荷里就不允许出现 ``rule`` / ``kind``；
* 声称的级别与载荷形状不一致，或者级别未知，一律 fail closed。

**不主张**：L1/L2 不会让验证方学到泄漏之外的东西；证明工件通道与重执行
通道仍由 ``docs/certificate-binding-framework.md`` §7.3 的另外两条债处理。
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

#: 三级披露的字符串常量。大小写不敏感，但输出统一成大写。
LEVEL_L0 = "L0"
LEVEL_L1 = "L1"
LEVEL_L2 = "L2"
LEVELS: Tuple[str, ...] = (LEVEL_L0, LEVEL_L1, LEVEL_L2)

#: 缺省级别 —— 与字段出现之前的行为一致（rule + kind）。
DEFAULT_LEVEL = LEVEL_L0

#: 规则类型 → 粗粒度类别。**不是** kind 的原样回显：多个 kind 会折叠成同一类。
#: 新增 kind 时若不在这里登记，会落到 ``"other"``（仍然不泄露具体 kind 名）。
RULE_CATEGORY: Dict[str, str] = {
    "keyword_block": "content",
    "normalized_keyword_block": "content",
    "pattern_block": "content",
    "length_bound": "length",
    "format_check": "format",
    "tool_arg_guard": "tool_arguments",
    "budget_bound": "budget",
    "trace_unbound": "trace_integrity",
    "semantic_bound": "semantic",
}

#: L0 允许出现的违规字段（白名单）。明文 ``evidence`` / ``evidence_kind`` 不在内。
L0_FIELDS = frozenset({"rule", "kind", "evidence_commitment"})
L1_FIELDS = frozenset({"category", "count"})
L2_FIELDS = frozenset({"evidence_commitment"})


class DisclosureError(ValueError):
    """披露级别非法，或载荷/公开值无法按声明级别投影。"""


def normalize_level(level: Any, *, default: Optional[str] = None) -> str:
    """把级别规范化成 ``L0`` / ``L1`` / ``L2``；未知级别抛 :class:`DisclosureError`。

    ``default`` 只在 ``level is None`` 时使用；传了非空但非法的值**不会**
    退回默认 —— 那会把「标错」静默变成「按 L0 处理」，正是 fail open。
    """
    if level is None:
        if default is None:
            raise DisclosureError("disclosure level is required")
        return normalize_level(default)
    if not isinstance(level, str):
        raise DisclosureError(f"disclosure_level must be a string, got {type(level).__name__}")
    # **不剪空白**：``"l0 "`` 这种写法多半是配置拼接事故，静默接受会让
    # 「级别写错」看起来像「级别写对」。大小写不敏感是唯一放宽。
    got = level.upper()
    if got not in LEVELS:
        raise DisclosureError(
            f"unknown disclosure_level {level!r} (expected one of {', '.join(LEVELS)})")
    return got


def declared_level(payload: Dict[str, Any]) -> Optional[str]:
    """证书载荷声明的级别；字段缺失返回 ``None``（旧证书 → 按 L0 行为处理）。

    字段存在但非法时抛 :class:`DisclosureError`（fail closed）。
    """
    if not isinstance(payload, dict):
        raise DisclosureError("certificate payload must be an object")
    if "disclosure_level" not in payload:
        return None
    return normalize_level(payload.get("disclosure_level"))


def level_from_policy(policy: Any, *, default: str = DEFAULT_LEVEL) -> str:
    """从策略包取披露级别；没有声明时返回 ``default``（缺省 L0）。

    ``policy`` 可以是：

    * 策略包字典（``policy_packs/*.json`` 的形状）—— 读顶层的
      ``disclosure_level``。注意 :meth:`policydsl.core.model.Policy.from_dict`
      不携带未知字段，所以**出证前**要从原始字典读；
    * :class:`policydsl.core.model.Policy` 实例 —— 读同名属性。核心模型没有
      这个字段，调用方可以在实例上动态挂一个（dataclass 未用 ``slots``），
      或直接用 ``default``。

    **这个级别不进** ``policy_hash``：它是签发时的披露选择，不改变策略语义，
    也不改变既有策略包的哈希（否则旧证书全部失效）。
    """
    raw: Any
    if isinstance(policy, dict):
        raw = policy.get("disclosure_level")
    else:
        raw = getattr(policy, "disclosure_level", None)
    return normalize_level(raw, default=default)


def category_for_kind(kind: Any) -> str:
    """规则类型 → 粗粒度类别；未知/畸形 kind 收敛为 ``"other"``。"""
    if isinstance(kind, str):
        return RULE_CATEGORY.get(kind, "other")
    return "other"


def _evidence_bytes(value: Any) -> bytes:
    """证据值的稳定字节串（字符串按 UTF-8；其它按规范 JSON）。"""
    if isinstance(value, str):
        return value.encode("utf-8")
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def evidence_commitment(value: Any) -> str:
    """对证据值求 SHA-256（与 ``policydsl.privacy.commit.evidence_commitment``
    对字符串的约定一致；非字符串先做规范 JSON）。"""
    return hashlib.sha256(_evidence_bytes(value)).hexdigest()


def _violation_commitment(v: Dict[str, Any]) -> Optional[str]:
    """取/算一条违规的证据承诺；没有证据也没有承诺时返回 ``None``。"""
    ec = v.get("evidence_commitment")
    if isinstance(ec, str) and ec:
        return ec.lower()
    if "evidence" in v:
        return evidence_commitment(v["evidence"])
    return None


def _require_violation(v: Any, level: str) -> Dict[str, Any]:
    if not isinstance(v, dict):
        raise DisclosureError(
            f"{level}: each violation must be an object, got {type(v).__name__}")
    return v


def project_violations(violations: Iterable[Dict[str, Any]], level: str) -> List[Dict[str, Any]]:
    """把 raw 违规列表投影到指定级别。

    * ``L0``：保留 ``rule`` / ``kind``，并把明文 ``evidence`` 换成
      ``evidence_commitment``（不泄露明文证据）；
    * ``L1``：按 :data:`RULE_CATEGORY` 聚合成 ``{"category", "count"}``，
      按类别名排序（顺序稳定、不泄露原规则顺序）；
    * ``L2``：只留 ``{"evidence_commitment": ...}``，按承诺排序。

    未知级别抛 :class:`DisclosureError`。投影是**纯函数**：同一输入同一输出，
    因此验证方可以对证明公开值重放同一步骤。
    """
    level = normalize_level(level)
    if violations is None:
        violations = []
    if not isinstance(violations, (list, tuple)):
        raise DisclosureError(f"violations must be a list, got {type(violations).__name__}")

    if level == LEVEL_L0:
        out: List[Dict[str, Any]] = []
        for raw in violations:
            v = _require_violation(raw, level)
            item: Dict[str, Any] = {}
            if "rule" in v:
                item["rule"] = v["rule"]
            if "kind" in v:
                item["kind"] = v["kind"]
            c = _violation_commitment(v)
            if c:
                item["evidence_commitment"] = c
            out.append(item)
        return out

    if level == LEVEL_L1:
        counts: Dict[str, int] = {}
        for raw in violations:
            v = _require_violation(raw, level)
            cat = category_for_kind(v.get("kind"))
            counts[cat] = counts.get(cat, 0) + 1
        return [{"category": c, "count": n} for c, n in sorted(counts.items())]

    # L2：只有不透明承诺。缺承诺的条目用「整条违规的承诺」兜底，保证
    # 列表长度仍能表达存在性，而不会把 rule/kind 写回去。
    commits: List[str] = []
    for raw in violations:
        v = _require_violation(raw, level)
        c = _violation_commitment(v)
        if c is None:
            c = evidence_commitment(v)
        commits.append(c)
    return [{"evidence_commitment": c} for c in sorted(commits)]


def project_outcome(outcome: Dict[str, Any], level: str) -> Dict[str, Any]:
    """投影整个 ``outcome``（深拷贝，不改入参）。

    只改 ``violations`` 与（L1 的）``violation_count``。``passed`` /
    ``policy_hash`` / ``response_binding`` / ``trace_root`` 等字段原样保留 ——
    它们不是规则级披露。

    **``delegated`` 非空且 level != L0 时 fail closed**：委托约束的 ``name``
    本身就是规则名，L1/L2 没有定义把它映射成类别的协议。与其静默泄露，不如
    拒绝出证/验证。空 ``delegated`` 列表不泄露任何东西，原样保留。
    """
    level = normalize_level(level)
    if not isinstance(outcome, dict):
        raise DisclosureError(f"outcome must be an object, got {type(outcome).__name__}")
    delegated = outcome.get("delegated") or []
    if level != LEVEL_L0 and delegated:
        raise DisclosureError(
            f"{level}: delegated constraints are non-empty; their rule names leak "
            "policy structure. Only L0 is supported for delegated rules until a "
            "category-level delegated schema exists (fail closed).")

    out = copy.deepcopy(outcome)
    violations = project_violations(out.get("violations") or [], level)
    out["violations"] = violations
    if level == LEVEL_L1:
        out["violation_count"] = sum(int(v["count"]) for v in violations)
    else:
        out.pop("violation_count", None)
    return out


def _keys(v: Dict[str, Any]) -> set:
    return set(v.keys())


def validate_projected_outcome(outcome: Any, level: str) -> Tuple[bool, str]:
    """检查 ``outcome`` 是否**看起来像**该级别的投影（形状 + 无 raw 字段）。

    这是**不带证明**时的检查；带证明时 :func:`check_outcome_disclosure` 会
    进一步重投影 proof outcome 做逐字段比对。返回 ``(ok, detail)``。
    """
    try:
        level = normalize_level(level)
    except DisclosureError as exc:
        return False, f"unknown disclosure_level: {exc}"
    if not isinstance(outcome, dict):
        return False, "outcome is not an object"
    violations = outcome.get("violations", [])
    if not isinstance(violations, list):
        return False, "outcome.violations is not a list"
    delegated = outcome.get("delegated") or []
    if level != LEVEL_L0 and delegated:
        return False, f"{level}: outcome.delegated is non-empty (rule names leak)"

    if level == LEVEL_L0:
        allowed = L0_FIELDS
        for i, v in enumerate(violations):
            if not isinstance(v, dict):
                return False, f"L0: violations[{i}] is not an object"
            extra = _keys(v) - allowed
            if extra:
                return False, (f"L0: violations[{i}] exposes {sorted(extra)}; "
                               "only rule/kind/evidence_commitment are allowed")
            if not isinstance(v.get("rule"), str) or not v.get("rule"):
                return False, f"L0: violations[{i}] lacks a rule name"
            if not isinstance(v.get("kind"), str) or not v.get("kind"):
                return False, f"L0: violations[{i}] lacks a kind"
        return True, f"L0: {len(violations)} raw violation(s) (rule + kind)"

    if level == LEVEL_L1:
        total = 0
        for i, v in enumerate(violations):
            if not isinstance(v, dict):
                return False, f"L1: violations[{i}] is not an object"
            if _keys(v) != L1_FIELDS:
                return False, (f"L1: violations[{i}] has keys {sorted(_keys(v))}; "
                               "expected exactly category + count")
            if not isinstance(v.get("category"), str) or not v["category"]:
                return False, f"L1: violations[{i}].category is invalid"
            if not isinstance(v.get("count"), int) or isinstance(v.get("count"), bool) \
                    or v["count"] < 1:
                return False, f"L1: violations[{i}].count is invalid"
            total += v["count"]
        if "violation_count" in outcome and outcome["violation_count"] != total:
            return False, ("L1: outcome.violation_count does not equal the sum of "
                           "per-category counts")
        return True, f"L1: {len(violations)} category bucket(s), {total} violation(s)"

    # L2
    for i, v in enumerate(violations):
        if not isinstance(v, dict):
            return False, f"L2: violations[{i}] is not an object"
        if _keys(v) != L2_FIELDS:
            return False, (f"L2: violations[{i}] has keys {sorted(_keys(v))}; "
                           "expected exactly evidence_commitment")
        c = v.get("evidence_commitment")
        if not isinstance(c, str) or len(c) != 64 or not _is_hex(c):
            return False, f"L2: violations[{i}].evidence_commitment is not sha256 hex"
    return True, f"L2: {len(violations)} opaque evidence commitment(s)"


def _is_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


def check_outcome_disclosure(payload: Dict[str, Any],
                             proof_outcome: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
    """验证方的一站式检查：级别是否合法、载荷形状是否匹配、投影是否等于证明。

    返回 ``(ok, detail)``。字段缺失时返回 ``True``（旧证书，L0 行为，逐字节
    兼容）；级别未知返回 ``False``；给了 ``proof_outcome`` 时，要求
    ``project_outcome(proof_outcome, level) == payload["outcome"]``。
    """
    try:
        level = declared_level(payload)
    except DisclosureError as exc:
        return False, f"fail closed: {exc}"
    if level is None:
        return True, "certificate predates the field — L0 behavior"
    outcome = payload.get("outcome")
    ok, why = validate_projected_outcome(outcome, level)
    if not ok:
        return False, why
    if proof_outcome is not None:
        try:
            expected = project_outcome(proof_outcome, level)
        except DisclosureError as exc:
            return False, f"{level}: proof public values cannot be projected: {exc}"
        if expected != outcome:
            return False, (f"{level}: certificate outcome is not the projection of the "
                           "proof public values (raw rule/kind mismatch or tampering)")
    return True, why
