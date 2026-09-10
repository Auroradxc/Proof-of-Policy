"""PII（个人隐私信息）模式与校验位验证器（参考层）。

模式采用 Proof-of-Policy 的 NFA 子集表达（ASCII 语义，见 ``policydsl.nfa``）。
这里的值是「规范来源」（canonical source）；可以从它们生成策略包
（见 ``scripts/`` 或 ``pii_redaction_v1`` 包），保证字符串永不漂移。

校验位验证器（IBAN MOD-97）是纯算法辅助函数：正则只能刻画「外形」，校验和
需要单独一个参考函数。把校验和验证接入专用约束类型是未来工作（不在阶段一至三
的 MVP 约束集合内）。
"""

from __future__ import annotations

from . import nfa

# 规范 PII 模式（全部落在受支持的 NFA 子集内）。
PII_PATTERNS = {
    "email": r"[\w.+-]+@[\w-]+\.[\w.]+",
    "phone": r"\+?[0-9 ()-]{7,}",
    "secret_key": r"sk-[A-Za-z0-9]{16,}",
    "bearer_token": r"Bearer [A-Za-z0-9._~+/=-]{16,}",
}

# 提前编译检查：导入时即编译，若有模式不受支持则在 import 阶段就报错，
# 避免运行到一半才暴露不兼容的正则。
_NFA_CACHE = {name: nfa.compile_pattern(pat) for name, pat in PII_PATTERNS.items()}


def compiled_pattern(name: str) -> dict:
    """返回指定名字 PII 模式对应的缓存 NFA 规格。"""
    if name not in _NFA_CACHE:
        raise KeyError(f"unknown PII pattern '{name}' (have {sorted(_NFA_CACHE)})")
    return _NFA_CACHE[name]


def contains(name: str, text: str) -> bool:
    """若 ``text`` 中含有指定名字 PII 模式的匹配则返回 True。"""
    return nfa.match_search(compiled_pattern(name), text)


def pattern_names() -> list[str]:
    """返回全部 PII 模式名（排序）。"""
    return sorted(PII_PATTERNS)


# --------------------------------------------------------------------------- #
# 校验位验证器（check-digit validators）
# --------------------------------------------------------------------------- #

def iban_mod97(iban: str) -> int:
    """计算 IBAN 的 ISO 7064 MOD-97-10 校验，返回余数（0..96）。

    算法：去掉空格并大写 → 把前 4 个字符（国家码+校验位）移到末尾 →
    字母按 A=10..Z=35 转成数字串 → 整个数字串对 97 取模。
    """
    s = iban.replace(" ", "").upper()
    if len(s) < 5:
        raise ValueError("IBAN too short")
    rearranged = s[4:] + s[:4]
    digits = "".join(str(ord(ch) - 55) if "A" <= ch <= "Z" else ch for ch in rearranged)
    if not digits.isdigit():
        raise ValueError("IBAN contains invalid characters")
    return int(digits) % 97


def is_valid_iban(iban: str) -> bool:
    """有效的 IBAN 其 MOD-97 余数应为 1。"""
    try:
        return iban_mod97(iban) == 1
    except ValueError:
        return False
