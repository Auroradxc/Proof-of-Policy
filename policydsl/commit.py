"""私有模式原语：响应承诺、选择性披露、以及「带证明的脱敏」
（VDR 风格，即「仅在掩码位置不同」）。

这是 SP1 私有模式程序（``pop-types::evaluate_private``）的参考层实现。
语义与 Rust 侧逐字节兼容：

- ``commitment`` / ``evidence_commitment``：对 UTF-8 字节求 SHA-256，小写十六进制。
- 关键词匹配采用 ASCII 小写化（与电路内匹配器一致）。
- 违规采用每种类型各自的「规范证据字符串」：
    keyword_block -> （第一个、按 spec 顺序）命中的关键词
    length_bound  -> "len=<N>"
    pattern_block -> 命中的模式串
- 脱敏（redaction）：码点长度相同；掩码位置填掩码字符（``*``），
  其余位置与原文本完全一致。
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Tuple

from . import nfa

MASK_CHAR = "*"


def _ascii_lower(s: str) -> str:
    """仅对 ASCII 大写字母做小写化（与电路内匹配器保持字节级一致）。

    注意：这里不用 Python 的 str.lower()，因为它会把非 ASCII 字母也小写，
    可能导致链下/链上对同一输入得出不同结果。
    """
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def commitment(text: str) -> str:
    """对 ``text`` 的 UTF-8 字节求 SHA-256，返回小写十六进制。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def evidence_commitment(evidence: str) -> str:
    """对违规证据片段的承诺（与 ``commitment`` 用同一个哈希）。"""
    return commitment(evidence)


def canonical_violations(spec: Dict, response: str,
                         tool_calls: Optional[List[Dict]] = None,
                         token_count: Optional[int] = None) -> List[Dict]:
    """精确镜像 ``pop-types::evaluate``，返回 (rule, kind, evidence) 列表。

    ``tool_calls`` 是 ``{"name": str, "args": {str: str}}`` 列表；证据字符串
    与 Rust 侧逐字节一致（私有模式证据承诺需要这种一致）。
    """
    from .evaluate import _parse_format  # 复用规范子集解析器

    lower = _ascii_lower(response)
    calls = tool_calls or []
    out: List[Dict] = []
    for c in spec["constraints"]:
        kind, name = c["kind"], c["name"]
        if kind == "keyword_block":
            # 关键词：取第一个（spec 顺序）命中的关键词作为证据
            hit = next((kw for kw in c["keywords"] if kw in lower), None)
            if hit is not None:
                out.append({"rule": name, "kind": "keyword_block", "evidence": hit})
        elif kind == "length_bound":
            n = len(response)
            if not (c["min"] <= n <= c["max"]):
                out.append({"rule": name, "kind": "length_bound", "evidence": f"len={n}"})
        elif kind == "pattern_block":
            # 正则：按编译顺序逐条匹配，命中即记证据并跳出
            for i, s in enumerate(c["nfa"]["compiled"]):
                if nfa.match_search(s, response):
                    out.append({"rule": name, "kind": "pattern_block",
                                "evidence": c["patterns"][i]})
                    break
        elif kind == "format_check":
            if not _parse_format(c["format"], response):
                out.append({"rule": name, "kind": "format_check", "evidence": c["format"]})
        elif kind == "tool_arg_guard":
            # 工具参数：兼容 dict 与对象两种调用表示，取「工具:字段」为证据
            allowed = c.get("tools") or []
            for call in calls:
                cname = call["name"] if isinstance(call, dict) else call.name
                args = (call.get("args", {}) if isinstance(call, dict) else call.args)
                if allowed and cname not in allowed:
                    continue
                hit = next((f for f in c["forbidden_fields"] if f in args), None)
                if hit is not None:
                    out.append({"rule": name, "kind": "tool_arg_guard",
                                "evidence": f"{cname}:{hit}"})
                    break  # 每个工具调用至多记一条违规
        elif kind == "budget_bound":
            unit = c.get("unit", "calls")
            total = len(calls) if unit == "calls" else int(token_count or 0)
            if total > c["budget"]:
                out.append({"rule": name, "kind": "budget_bound",
                            "evidence": f"{unit}={total}/{c['budget']}"})
        else:
            raise NotImplementedError(f"kind '{kind}' not provable in-circuit yet")
    return out


# --------------------------------------------------------------------------- #
# 脱敏（选择性披露 / redaction）
# --------------------------------------------------------------------------- #

def mask_from_patterns(patterns: List[str], text: str) -> List[int]:
    """返回被任意给定正则匹配覆盖的字符下标（排序）。"""
    specs = [nfa.compile_pattern(p) for p in patterns]
    return nfa.mask_indices(specs, text)


def spec_spans(spec: Dict, text: str) -> List[Tuple[int, int]]:
    """合并 spec 中所有 pattern_block 约束的匹配区间。"""
    spans: List[Tuple[int, int]] = []
    for c in spec["constraints"]:
        if c["kind"] == "pattern_block":
            for s in c["nfa"]["compiled"]:
                spans.extend(nfa.find_spans(s, text))
    return nfa.merge_spans(spans)


def spans_valid(spec: Dict, text: str, spans: List[Tuple[int, int]]) -> bool:
    """每个区间都必须是某条 pattern_block 模式的「真实完整匹配」。"""
    comps = [s for c in spec["constraints"] if c["kind"] == "pattern_block"
             for s in c["nfa"]["compiled"]]
    for (lo, hi) in spans:
        if not any(nfa.anchored_full_match(s, text, lo, hi) for s in comps):
            return False
    return True


def mask_covered(mask: List[int], spans: List[Tuple[int, int]]) -> bool:
    """每个被掩码的下标都必须落在某个区间内（mask ⊆ spans）。"""
    return all(any(lo <= m < hi for lo, hi in spans) for m in mask)


def redact(text: str, mask: List[int], char: str = MASK_CHAR) -> str:
    """把 ``text`` 中指定下标处的字符替换为 ``char``。"""
    ms = set(mask)
    return "".join(char if i in ms else ch for i, ch in enumerate(text))


def redaction_ok(response: str, redacted: str, mask: List[int],
                 char: str = MASK_CHAR) -> bool:
    """VDR 风格检查：等长、掩码位置为 ``char``、其余位置不变。

    掩码下标越界返回 False。
    """
    if len(response) != len(redacted):
        return False
    n = len(response)
    ms = set(mask)
    if any(i < 0 or i >= n for i in mask):
        return False
    for i, (a, b) in enumerate(zip(response, redacted)):
        if i in ms:
            if b != char:
                return False
        elif a != b:
            return False
    return True


def private_output(spec: Dict, response: str,
                   mask: Optional[List[int]] = None,
                   redacted: Optional[str] = None,
                   spans: Optional[List[Tuple[int, int]]] = None,
                   tool_calls: Optional[List[Dict]] = None,
                   token_count: Optional[int] = None) -> Dict:
    """构建与 ``pop-types::PrivateOutput`` 一致的字典（golden）。

    ``spans`` 是「见证匹配区间」，用于证明被掩码位置确实落在真实模式匹配内：
    仅当每个区间都是真实匹配、且每个掩码下标都落在区间内时，``mask_covered``
    才为 True。
    """
    vs = canonical_violations(spec, response, tool_calls, token_count)
    # 违规只暴露证据承诺（不泄露明文证据），实现选择性披露
    violations = [{"rule": v["rule"], "kind": v["kind"],
                   "evidence_commitment": evidence_commitment(v["evidence"])} for v in vs]
    redaction = None
    if redacted is not None:
        m = sorted(mask or [])
        sp = [tuple(s) for s in (spans or [])]
        covered = spans_valid(spec, response, sp) and mask_covered(m, sp)
        redaction = {
            "redacted_commitment": commitment(redacted),
            "mask_count": len(m),
            "redaction_ok": redaction_ok(response, redacted, m),
            "mask_covered": covered,
        }
    return {
        "response_commitment": commitment(response),
        "passed": len(vs) == 0,
        "violations": violations,
        "redaction": redaction,
    }


# --------------------------------------------------------------------------- #
# 证据开示（对审计者选择性披露 / evidence opening）
# --------------------------------------------------------------------------- #

def open_evidence(commitment_hex: str, fragment: str) -> bool:
    """验证 ``fragment`` 能否「打开」``commitment_hex``（即 sha256 匹配）。"""
    return evidence_commitment(fragment) == commitment_hex


def evidence_bundle(spec: Dict, response: str) -> List[Dict]:
    """授权后的完整披露：每条违规附明文证据与对应承诺，
    使审计者能对照证明核验。"""
    out = []
    for v in canonical_violations(spec, response):
        out.append({
            "rule": v["rule"], "kind": v["kind"],
            "evidence": v["evidence"],
            "evidence_commitment": evidence_commitment(v["evidence"]),
        })
    return out


def verify_bundle(bundle: List[Dict]) -> bool:
    """每条记录的承诺都必须等于 sha256(evidence)。"""
    return all(open_evidence(e["evidence_commitment"], e["evidence"]) for e in bundle)
