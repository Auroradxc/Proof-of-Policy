"""私有模式原语：响应承诺、选择性披露、「带证明的脱敏」（VDR 风格，即「仅在
掩码位置不同」），以及 P0-2 的**挑战-响应绑定**。

这是 SP1 私有模式程序（``pop-types::evaluate_private``）的参考层实现。
语义与 Rust 侧逐字节兼容：

- ``commitment`` / ``evidence_commitment``：对 UTF-8 字节求 SHA-256，小写十六进制。
- ``response_binding``：对 ``BIND_DOMAIN ‖ len(nonce) ‖ nonce ‖ T`` 求 SHA-256
  （P0-2；与 ``pop_types::response_binding`` 逐字节一致）。
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
import hmac
from typing import Dict, List, Optional, Tuple

from . import nfa

MASK_CHAR = "*"

#: 挑战-响应绑定的域分隔前缀（对应 ``pop_types::BIND_DOMAIN``）。
BIND_DOMAIN = b"pop-bind-v1"
#: 证书 ``challenge`` 块里声明的绑定方案名（便于将来换代）。
BIND_SCHEME = "pop-bind-v1"


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


# --------------------------------------------------------------------------- #
# 挑战-响应绑定（P0-2）
# --------------------------------------------------------------------------- #

def response_binding(nonce: bytes, response: str) -> str:
    """把一条响应 ``T`` 绑定到一个一次性挑战 ``nonce`` 上。

    计算 ``SHA256(BIND_DOMAIN ‖ len(nonce) ‖ nonce ‖ T_utf8)``，小写十六进制。

    **为什么需要它**：证明只说明「某条 T 满足 π」，从不说 T 是哪一条 ——
    公开模式下 T 是证明的私有输入、证书里不出现，私有模式下更是只剩一个
    ``commitment(T)``（「存在某个通过判定的 T」，但说不出是哪个）。于是
    「被证明的 T」与「客户端收到的 T′」之间没有任何联系，中间人可以用一条
    合规的 T 换一条不合规的 T′ 送达。绑定让**验证者出题**：电路把
    ``(nonce, T)`` 一起承诺进公开值，持 ``T′`` 与 ``nonce`` 的一方离线重算
    即可确认 ``T′ == T``。

    ``len(nonce)`` 这个 4 字节大端长度前缀不是装饰：没有它，
    ``nonce=b"ab", T="cd"`` 与 ``nonce=b"abcd", T=""`` 会哈希出同一个值。
    挑战值通常定长，但把无歧义性寄托在调用方自觉上不是好买卖 —— 加了长度
    前缀，(nonce, T) → 字节串就是单射。

    ``nonce`` 为空是合法的（= 未走挑战流程）：绑定退化为「对空挑战的承诺」，
    **不提供重放防护**，但格式统一，验证方无需分支处理。
    """
    return hashlib.sha256(BIND_DOMAIN + len(nonce).to_bytes(4, "big") + nonce
                          + response.encode("utf-8")).hexdigest()


def verify_binding(nonce: bytes, response: str, binding: str) -> bool:
    """``response`` 配上 ``nonce`` 能否「打开」``binding``（常量时间比较）。"""
    return hmac.compare_digest(response_binding(nonce, response), binding)


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
                   token_count: Optional[int] = None,
                   nonce: bytes = b"") -> Dict:
    """构建与 ``pop-types::PrivateOutput`` 一致的字典（golden）。

    ``spans`` 是「见证匹配区间」，用于证明被掩码位置确实落在真实模式匹配内：
    仅当每个区间都是真实匹配、且每个掩码下标都落在区间内时，``mask_covered``
    才为 True。

    ``nonce`` 是本次会话的一次性挑战（P0-2）；缺省 ``b""`` 表示未走挑战流程。
    ``response_commitment`` 仍然只是 ``commitment(T)`` —— 它说明「存在某个
    通过判定的 T」；把 T 拴到这次会话上的是 ``response_binding``。
    二者是不同的问题，所以都保留。

    ⚠️ **隐藏性的上界（P0-4 查证后收紧，见 ``docs/sp1-zk-audit.md``）**：
    这里的「承诺」只保证**公开值不出现明文**，**不保证 T 不可恢复**。
    ``response_binding`` 与 ``response_commitment`` 都是**公开且可离线重算**的 T 的函数，
    而自然语言响应的熵远低于 SHA-256 的 256 bit —— 任何持 ``(nonce, T')`` 的一方
    都能对候选 ``T'`` 算一遍哈希比对（这正是绑定可被独立核对的原因）。
    更一般地：在「验证者独立重算绑定」这一前提下，
    **响应绑定与响应内容隐藏对低熵 T 互斥**。
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
        "response_binding": response_binding(nonce, response),
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
