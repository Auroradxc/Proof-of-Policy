"""披露层级（L0 / L1 / L2）与公开值 v2 的形状检查。

**C2 之后的边界（先读这一句）**：披露 coarsening 发生在**电路内**。声明为
``Lx`` 的证明，其公开值本身只含该级别允许的字段；``pop-pv-v2`` 与
``disclosure_level`` 由 guest 写进公开值。本模块因此不再充当「验证方重投影
器」—— v2 路径只做**形状校验 + 承诺助手**，验证方要求证书载荷与解码后的
公开值**逐字段相等**。旧的 ``project_outcome`` 只保留给 v1 legacy 路径
（``--legacy-v1``）与历史调用方，不得用于 v2 正常路径。

========================  ==================================================
级别                       公开值里的违规长什么样（``pop-pv-v2``）
========================  ==================================================
``L0``                    ``{"shape":"raw","rule","kind",
                          "evidence_commitment"}`` —— 规则名 + 类型 + 逐条
                          承诺；明文 ``evidence`` **不进公开值**
``L1``                    ``{"shape":"category","category","count",
                          "evidence_commitment"}`` + 顶层 ``violation_count``
``L2``                    ``{"shape":"opaque","evidence_commitment"}`` ——
                          只有逐条承诺（列表长度仍泄露条数）
========================  ==================================================

承诺的精确字节见 :func:`item_commitment_v2` / :func:`bucket_commitment_v2`；
它们与 Rust ``pop-types`` 的同名函数逐字节一致，由
``tests/vectors/disclosure_v2.json`` 两侧对拍。

**仍然没有隐藏的东西**（必须与论文一起写）：``core`` / ``compressed`` 证明
工件仍泄露见证；重执行通道不变；L2 的列表长度等于违规条数；``delegated``
的类别桶 schema 在本次 MVP 中**未实现**，非空 delegated 在 L1/L2 下 fail
closed。见 ``docs/blockers/C2.md``。
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
from typing import Any, Dict, Iterable, List, Optional, Tuple

#: 三级披露的字符串常量。大小写不敏感，但输出统一成大写。
LEVEL_L0 = "L0"
LEVEL_L1 = "L1"
LEVEL_L2 = "L2"
LEVELS: Tuple[str, ...] = (LEVEL_L0, LEVEL_L1, LEVEL_L2)

#: 缺省级别 —— 与字段出现之前的行为一致（rule + kind）。
DEFAULT_LEVEL = LEVEL_L0

#: 公开值契约版本。v1 = 没有 schema 字段的旧证明（默认拒绝）。
PUBLIC_VALUE_SCHEMA_V1 = "v1"
PUBLIC_VALUE_SCHEMA_V2 = "pop-pv-v2"

#: 与 Rust ``DISCLOSURE_DOMAIN`` / ``TAG_*`` 逐字节一致。
DISCLOSURE_DOMAIN = b"pop-disclose-v1"
TAG_ITEM = 0x01
TAG_BUCKET = 0x02
TAG_NAMES = 0x03
TAG_RULE_NAME = 0x04

#: 类别 → 稳定 id（L1 桶顺序）。必须与 Rust ``RuleCategory::id`` 一致。
CATEGORY_IDS: Dict[str, int] = {
    "content": 0,
    "length": 1,
    "format": 2,
    "tool_arguments": 3,
    "budget": 4,
    "trace_integrity": 5,
    "semantic": 6,
    "other": 7,
}

#: 规则类型 → 粗粒度类别。**不是** kind 的原样回显：多个 kind 会折叠成同一类。
#: 新增 kind 时若不在这里登记，会落到 ``"other"``（仍然不泄露具体 kind 名）。
#: ``retrieval_guard`` 是 A9 设计指出此前漏登记的一条，归 tool_arguments。
RULE_CATEGORY: Dict[str, str] = {
    "keyword_block": "content",
    "normalized_keyword_block": "content",
    "pattern_block": "content",
    "length_bound": "length",
    "format_check": "format",
    "tool_arg_guard": "tool_arguments",
    "retrieval_guard": "tool_arguments",
    "budget_bound": "budget",
    "trace_unbound": "trace_integrity",
    "semantic_bound": "semantic",
}

#: v2 公开值里各级别允许的违规字段（白名单）。明文 ``evidence`` 一律不在内。
L0_FIELDS = frozenset({"shape", "rule", "kind", "evidence_commitment"})
L1_FIELDS = frozenset({"shape", "category", "count", "evidence_commitment"})
L2_FIELDS = frozenset({"shape", "evidence_commitment"})

#: v1 legacy 形状（没有 ``shape`` 标签；L0 还可能带明文 evidence）。
LEGACY_L0_FIELDS = frozenset({"rule", "kind", "evidence", "evidence_commitment"})
LEGACY_L1_FIELDS = frozenset({"category", "count"})
LEGACY_L2_FIELDS = frozenset({"evidence_commitment"})


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
    对字符串的约定一致；非字符串先做规范 JSON）。

    **v1 / legacy 专用**：v2 公开值用 :func:`item_commitment_v2`（带域分隔、
    类型标签与 response_binding 盐）。两套不得混用。
    """
    return hashlib.sha256(_evidence_bytes(value)).hexdigest()


# --------------------------------------------------------------------------
# v2 承诺（与 Rust pop-types 逐字节一致）
# --------------------------------------------------------------------------

def _require_rb(response_binding: Any) -> bytes:
    """``response_binding`` 必须是 64 个小写十六进制字符（32 字节）。"""
    if not isinstance(response_binding, str) or len(response_binding) != 64:
        raise DisclosureError("response_binding must be 64 hex characters")
    try:
        return bytes.fromhex(response_binding)
    except ValueError as exc:
        raise DisclosureError(f"response_binding is not hex: {exc}") from exc


def _evidence_utf8(evidence: Any) -> bytes:
    """证据串按 UTF-8 编码（与 Rust ``&str`` 的字节一致）。"""
    if not isinstance(evidence, str):
        raise DisclosureError(f"evidence must be a string, got {type(evidence).__name__}")
    return evidence.encode("utf-8")


def item_commitment_v2(evidence: Any, response_binding: str) -> str:
    """逐条证据承诺：``H(domain ‖ 0x01 ‖ RB ‖ u32be(len(E)) ‖ E)``。"""
    rb = _require_rb(response_binding)
    e = _evidence_utf8(evidence)
    h = hashlib.sha256()
    h.update(DISCLOSURE_DOMAIN)
    h.update(bytes([TAG_ITEM]))
    h.update(response_binding.encode("ascii"))
    h.update(struct.pack(">I", len(e)))
    h.update(e)
    return h.hexdigest()


def bucket_commitment_v2(category: str, item_commitments: Iterable[str],
                         response_binding: str) -> str:
    """L1 类别桶承诺：``H(domain ‖ 0x02 ‖ RB ‖ u8(cat_id) ‖ u32be(n) ‖
    concat(sorted_raw32(items)))``。"""
    _require_rb(response_binding)
    cat_id = _category_id(category)
    items = list(item_commitments)
    digests = []
    for c in items:
        if not isinstance(c, str) or len(c) != 64 or not _is_hex(c):
            raise DisclosureError(f"item commitment is not sha256 hex: {c!r}")
        digests.append(bytes.fromhex(c))
    digests.sort()
    h = hashlib.sha256()
    h.update(DISCLOSURE_DOMAIN)
    h.update(bytes([TAG_BUCKET]))
    h.update(response_binding.encode("ascii"))
    h.update(bytes([cat_id]))
    h.update(struct.pack(">I", len(items)))
    for d in digests:
        h.update(d)
    return h.hexdigest()


def rule_name_commitment_v2(rule: str, response_binding: str) -> str:
    """delegated 规则名承诺（MVP 未在电路内启用；供未来桶 schema 对齐）。"""
    _require_rb(response_binding)
    r = _evidence_utf8(rule)
    h = hashlib.sha256()
    h.update(DISCLOSURE_DOMAIN)
    h.update(bytes([TAG_RULE_NAME]))
    h.update(response_binding.encode("ascii"))
    h.update(struct.pack(">I", len(r)))
    h.update(r)
    return h.hexdigest()


def names_commitment_v2(rules: Iterable[str], response_binding: str) -> str:
    """delegated 名字集合承诺（MVP 未在电路内启用）。"""
    _require_rb(response_binding)
    rules = list(rules)
    digests = sorted(bytes.fromhex(rule_name_commitment_v2(r, response_binding))
                     for r in rules)
    h = hashlib.sha256()
    h.update(DISCLOSURE_DOMAIN)
    h.update(bytes([TAG_NAMES]))
    h.update(response_binding.encode("ascii"))
    h.update(struct.pack(">I", len(rules)))
    for d in digests:
        h.update(d)
    return h.hexdigest()


def _category_id(category: Any) -> int:
    if not isinstance(category, str) or category not in CATEGORY_IDS:
        raise DisclosureError(f"unknown violation category: {category!r}")
    return CATEGORY_IDS[category]


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
        return [{"category": c, "count": n}
                for c, n in sorted(counts.items(), key=lambda kv: CATEGORY_IDS[kv[0]])]

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
    """**仅 v1 legacy**：把 raw outcome 投影到指定级别（深拷贝，不改入参）。

    C2 之后正常验证路径**不再调用本函数**：v2 公开值由 guest 在 commit 前
    coarsen，验证方只做形状检查与逐字段相等。这里保留它只为旧证书/旧工具链的
    legacy 路径（``--legacy-v1``）与历史调用方；新代码不得用它「补做隐藏」。

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
        allowed = LEGACY_L0_FIELDS
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
            if _keys(v) != LEGACY_L1_FIELDS:
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
        if _keys(v) != LEGACY_L2_FIELDS:
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


# --------------------------------------------------------------------------
# v2 公开值形状校验（验证方用；**不重投影**）
# --------------------------------------------------------------------------

_V2_ALLOWED_KEYS = frozenset({
    "mode", "policy_hash", "response_binding", "trace_root", "passed",
    "response_commitment", "redaction",
    "public_value_schema", "disclosure_level", "violation_count",
    "violations", "delegated", "delegated_buckets",
})
#: L1/L2 公开值里任何层级都不允许出现的键（delegated 桶也不能带 name）。
_BANNED_KEYS = frozenset({"rule", "kind", "name", "evidence"})


def is_v2_outcome(outcome: Any) -> bool:
    """这个 outcome 是否自称 ``pop-pv-v2``。"""
    return (isinstance(outcome, dict)
            and outcome.get("public_value_schema") == PUBLIC_VALUE_SCHEMA_V2)


def _scan_banned(obj: Any, path: str) -> Optional[str]:
    """递归找禁用键；找到返回路径，否则 None。"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _BANNED_KEYS:
                return f"{path}.{k}"
            hit = _scan_banned(v, f"{path}.{k}")
            if hit:
                return hit
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hit = _scan_banned(v, f"{path}[{i}]")
            if hit:
                return hit
    return None


def validate_outcome_v2(outcome: Any, level: Any) -> Tuple[bool, str]:
    """严格校验一个 ``pop-pv-v2`` 公开值是否符合声明级别。

    这是**形状**检查，不做投影：调用方随后必须要求证书载荷与解码后的公开值
    逐字段相等（见 :func:`check_outcome_disclosure`）。返回 ``(ok, detail)``。
    """
    try:
        level = normalize_level(level)
    except DisclosureError as exc:
        return False, f"unknown disclosure_level: {exc}"
    if not isinstance(outcome, dict):
        return False, "outcome is not an object"

    schema = outcome.get("public_value_schema")
    if schema != PUBLIC_VALUE_SCHEMA_V2:
        return False, (f"unknown/absent public_value_schema: {schema!r} "
                       f"(expected {PUBLIC_VALUE_SCHEMA_V2!r})")
    extra = _keys(outcome) - _V2_ALLOWED_KEYS
    if extra:
        return False, f"outcome exposes unknown keys: {sorted(extra)}"
    try:
        declared = normalize_level(outcome.get("disclosure_level"))
    except DisclosureError as exc:
        return False, f"outcome disclosure_level invalid: {exc}"
    if declared != level:
        return False, (f"declared level {level} != public-value level {declared} "
                       "(the level must be committed by the circuit)")

    violations = outcome.get("violations")
    if not isinstance(violations, list):
        return False, "outcome.violations is not a list"
    delegated = outcome.get("delegated")
    buckets = outcome.get("delegated_buckets")
    if not isinstance(delegated, list):
        return False, "outcome.delegated is not a list"
    if not isinstance(buckets, list):
        return False, "outcome.delegated_buckets is not a list"

    # MVP：delegated 的类别桶 schema 未实现。L1/L2 遇到非空 delegated 必须
    # fail closed；任何级别出现非空 delegated_buckets 都是「未实现却被使用」。
    if level != LEVEL_L0 and delegated:
        return False, (f"{level}: outcome.delegated is non-empty; category-level "
                       "delegated buckets are not implemented (fail closed)")
    if buckets:
        return False, ("outcome.delegated_buckets is non-empty; the delegated bucket "
                       "schema is not implemented in this MVP (fail closed)")
    if outcome.get("mode") == "private" and delegated:
        return False, "private outcome carries non-empty delegated (circuit boundary violated)"

    if level == LEVEL_L0:
        if "violation_count" in outcome:
            return False, "L0 must not carry violation_count"
        for i, v in enumerate(violations):
            if not isinstance(v, dict):
                return False, f"L0: violations[{i}] is not an object"
            if _keys(v) != L0_FIELDS:
                return False, (f"L0: violations[{i}] has keys {sorted(_keys(v))}; "
                               "expected exactly shape + rule + kind + evidence_commitment")
            if v.get("shape") != "raw":
                return False, f"L0: violations[{i}].shape != 'raw'"
            if not isinstance(v.get("rule"), str) or not v["rule"]:
                return False, f"L0: violations[{i}] lacks a rule name"
            if not isinstance(v.get("kind"), str) or not v["kind"]:
                return False, f"L0: violations[{i}] lacks a kind"
            c = v.get("evidence_commitment")
            if not isinstance(c, str) or len(c) != 64 or not _is_hex(c):
                return False, f"L0: violations[{i}].evidence_commitment is not sha256 hex"
        # L0 允许 delegated（名字可见），但任何层级都不该有明文证据/rule/kind。
        for i, d in enumerate(delegated):
            if not isinstance(d, dict):
                return False, f"L0: delegated[{i}] is not an object"
            leaked = _keys(d) & {"rule", "kind", "evidence"}
            if leaked:
                return False, f"L0: delegated[{i}] leaks banned keys {sorted(leaked)}"
        return True, f"L0: {len(violations)} raw violation(s), names visible"

    # L1/L2：任何层级都不允许 rule / kind / name / evidence。
    hit = _scan_banned({"violations": violations, "delegated": delegated,
                        "delegated_buckets": buckets}, "outcome")
    if hit:
        return False, f"{level}: banned key leaked at {hit}"

    if level == LEVEL_L1:
        total = 0
        last_id = -1
        for i, v in enumerate(violations):
            if not isinstance(v, dict):
                return False, f"L1: violations[{i}] is not an object"
            if _keys(v) != L1_FIELDS:
                return False, (f"L1: violations[{i}] has keys {sorted(_keys(v))}; "
                               "expected exactly shape + category + count + "
                               "evidence_commitment")
            if v.get("shape") != "category":
                return False, f"L1: violations[{i}].shape != 'category'"
            try:
                cid = _category_id(v.get("category"))
            except DisclosureError:
                return False, f"L1: violations[{i}].category is unknown"
            if cid <= last_id:
                return False, "L1: category buckets must be strictly increasing by id"
            last_id = cid
            count = v.get("count")
            if not isinstance(count, int) or isinstance(count, bool) or count < 1:
                return False, f"L1: violations[{i}].count is invalid"
            c = v.get("evidence_commitment")
            if not isinstance(c, str) or len(c) != 64 or not _is_hex(c):
                return False, f"L1: violations[{i}].evidence_commitment is not sha256 hex"
            total += count
        vc = outcome.get("violation_count")
        if not isinstance(vc, int) or isinstance(vc, bool):
            return False, "L1: violation_count is missing/invalid"
        if vc != total:
            return False, "L1: violation_count does not equal the sum of bucket counts"
        return True, f"L1: {len(violations)} category bucket(s), {total} violation(s)"

    # L2
    if "violation_count" in outcome:
        return False, "L2 must not carry violation_count"
    prev: Optional[str] = None
    for i, v in enumerate(violations):
        if not isinstance(v, dict):
            return False, f"L2: violations[{i}] is not an object"
        if _keys(v) != L2_FIELDS:
            return False, (f"L2: violations[{i}] has keys {sorted(_keys(v))}; "
                           "expected exactly shape + evidence_commitment")
        if v.get("shape") != "opaque":
            return False, f"L2: violations[{i}].shape != 'opaque'"
        c = v.get("evidence_commitment")
        if not isinstance(c, str) or len(c) != 64 or not _is_hex(c):
            return False, f"L2: violations[{i}].evidence_commitment is not sha256 hex"
        if prev is not None and c < prev:
            return False, "L2: evidence commitments must be non-decreasing"
        prev = c
    return True, f"L2: {len(violations)} opaque evidence commitment(s)"


def _strip_mode(outcome: Any) -> Any:
    if isinstance(outcome, dict):
        return {k: v for k, v in outcome.items() if k != "mode"}
    return outcome


def check_outcome_disclosure(payload: Dict[str, Any],
                             proof_outcome: Optional[Dict[str, Any]] = None,
                             *, allow_legacy_v1: bool = False) -> Tuple[bool, str]:
    """验证方的一站式披露检查（v2 不再重投影）。

    判定顺序（A9 §7.1 的 MVP 子集）：

    1. ``binding.public_value_schema`` / 公开值里的 ``public_value_schema`` 必须
       一致且为 ``pop-pv-v2``；证书顶层 ``disclosure_level`` 必须存在、合法，
       并与公开值里的级别相等；
    2. 公开值形状必须严格匹配该级别（:func:`validate_outcome_v2`）；
    3. 有证明时，解码后的公开值必须与证书载荷 **逐字段相等**（恒等，不投影）；
    4. 旧 v1（无 schema）默认拒绝；只有 ``allow_legacy_v1=True`` 且级别为
       （缺省或）L0 时放行，并在 detail 里标注 ``legacy-v1``。没有证明工件的
       v1 证书（``proof_mode=unproven``）仍按旧路径接受，但在 detail 里如实
       标注，不声称电路级隐藏。
    """
    if not isinstance(payload, dict):
        return False, "certificate payload must be an object"
    binding = payload.get("binding") or {}
    payload_schema = binding.get("public_value_schema") if isinstance(binding, dict) else None
    outcome = payload.get("outcome")
    outcome_schema = outcome.get("public_value_schema") if isinstance(outcome, dict) else None
    has_level = "disclosure_level" in payload

    is_v2 = (payload_schema == PUBLIC_VALUE_SCHEMA_V2
             or outcome_schema == PUBLIC_VALUE_SCHEMA_V2
             or has_level)

    if not is_v2:
        # ---- v1 legacy ---------------------------------------------------
        if proof_outcome is not None:
            if isinstance(proof_outcome, dict) and is_v2_outcome(proof_outcome):
                return False, ("certificate is v1 but the proof commits pop-pv-v2 "
                               "public values — schema mismatch")
            if not allow_legacy_v1:
                return False, ("v1 proof public values are rejected by default; "
                               "pass --legacy-v1 to accept L0-only legacy proofs")
            level = declared_level(payload)
            if level is not None and level != LEVEL_L0:
                return False, f"legacy-v1 only supports L0 (certificate declares {level})"
            ok, why = validate_projected_outcome(outcome, LEVEL_L0)
            if not ok:
                return False, f"legacy-v1: {why}"
            if _strip_mode(outcome) != _strip_mode(proof_outcome):
                return False, ("legacy-v1: certificate outcome does not equal the "
                               "decoded v1 public values")
            return True, f"legacy-v1 (L0): {why}"
        # 没有证明工件的旧证书：保留 P1-05 之前的路径，但明确标注不是电路级。
        ok, why = validate_projected_outcome(outcome, LEVEL_L0)
        if not ok:
            return False, f"legacy v1 (unproven): {why}"
        return True, f"legacy v1 (unproven, not circuit-level): {why}"

    # ---- v2 --------------------------------------------------------------
    if payload_schema != PUBLIC_VALUE_SCHEMA_V2:
        return False, (f"binding.public_value_schema is {payload_schema!r}; "
                       f"expected {PUBLIC_VALUE_SCHEMA_V2!r}")
    if outcome_schema != payload_schema:
        return False, ("binding.public_value_schema != outcome.public_value_schema "
                       "(certificate does not mirror the committed public values)")
    if not has_level:
        return False, "v2 outcome requires a top-level certificate disclosure_level"
    try:
        level = declared_level(payload)
    except DisclosureError as exc:
        return False, f"fail closed: {exc}"
    if level is None:
        return False, "v2 outcome requires a certificate disclosure_level"
    ok, why = validate_outcome_v2(outcome, level)
    if not ok:
        return False, why
    if proof_outcome is not None:
        if not is_v2_outcome(proof_outcome):
            return False, ("certificate claims pop-pv-v2 but the proof public values "
                           "have no v2 schema (v1 proof cannot masquerade as v2)")
        ok_p, why_p = validate_outcome_v2(proof_outcome, level)
        if not ok_p:
            return False, f"{level}: proof public values are malformed: {why_p}"
        if _strip_mode(outcome) != _strip_mode(proof_outcome):
            return False, (f"{level}: certificate outcome is not a field-by-field "
                           "mirror of the decoded public values")
    return True, f"{level}: {why}"
