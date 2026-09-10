"""极简正则 → NFA 引擎（policydsl.nfa）的测试。

策略：对受支持的 ASCII 子集，用一份固定的模式 × 文本语料，把模拟器的判定
结果与 Python ``re`` 做属性比对——两侧语义必须逐例一致，否则 Python 参考
评估器与 SP1 电路会给出不同结论。此外单独覆盖：不受支持语法的快速失败，
以及 spec 的序列化确定性（电路侧反序列化的是同一份 spec）。
"""

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import nfa  # noqa: E402


# 模式与文本的笛卡尔积构成属性测试的输入空间：既覆盖真实 PII 形状，也覆盖
# 各类语法构造（量词、分支、字符类、取反、转义、锚点式边界）。
PATTERNS = [
    r"[\w.+-]+@[\w-]+\.[\w.]+",      # 邮箱
    r"sk-[A-Za-z0-9]{10,}",          # 密钥
    r"\+\d[\d\s-]{6,}",              # 类电话
    r"a+", r"colou?r", r"(cat|dog)s?", r"b{2,4}",
    r"[^0-9]+", r"\d{2,4}-\d{2,4}", r"a.*b", r"[a-c]+x?",
    r"\$[0-9]+(\.[0-9]{2})?",
]

TEXTS = [
    "contact a@b.com now", "no email here", "sk-abcdefGHIJ0123456789 x",
    "key=sk-xyz small", "+1 234 5678901", "call me", "aaaa", "ab",
    "colour color", "a cat and 3 dogs", "bbb bbbbb", "x at start",
    "123-45 xy", "aXb", "ccc", "the quick", "abcx", "", "price $1.25 or $10",
    "costs 5 dollars", "..a@@b..c", "-x-", "with sk-AAAAbbbbCCCCdddd key",
]


class TestMatchesPythonRe(unittest.TestCase):
    """属性测试：NFA 模拟器必须与 Python ``re.search`` 逐例一致。"""

    def test_corpus_agrees_with_re_search(self):
        # 遍历全部「模式 × 文本」组合逐一比对；用 subTest 让失败能定位到具体组合。
        for pat in PATTERNS:
            with self.subTest(pattern=pat):
                spec = nfa.compile_pattern(pat)
                for text in TEXTS:
                    self.assertEqual(
                        nfa.match_search(spec, text),
                        re.search(pat, text) is not None,
                        msg=f"pattern={pat!r} text={text!r}",
                    )

    def test_email_and_secret_typical(self):
        # 真实场景的正/负例：防止属性语料被退化输入掩盖而失去判别力。
        spec = nfa.compile_pattern(r"[\w.+-]+@[\w-]+\.[\w.]+")
        self.assertTrue(nfa.match_search(spec, "ping admin@example.com"))
        self.assertFalse(nfa.match_search(spec, "ping the admin"))
        sk = nfa.compile_pattern(r"sk-[A-Za-z0-9]{16,}")
        self.assertTrue(nfa.match_search(sk, "key=sk-abcdefghijklmnop123"))
        self.assertFalse(nfa.match_search(sk, "sk-short"))


class TestFailFast(unittest.TestCase):
    """超出子集的语法必须显式抛错，而不是静默产生错误的匹配语义。"""

    def test_unsupported_anchors(self):
        # 锚点 ^ $ 不在子集内：判定语义本就等价于 re.search，无需锚定。
        for pat in [r"^x", r"x$"]:
            with self.assertRaises(nfa.RegexSyntaxError):
                nfa.compile_pattern(pat)

    def test_lookaround_rejected(self):
        # 环视需要记忆上下文，无法用有限状态机表达。
        with self.assertRaises(nfa.RegexSyntaxError):
            nfa.compile_pattern(r"(?=abc)def")

    def test_backreference_rejected(self):
        # 反向引用需要计数/记忆能力，同样超出 NFA 表达范围。
        with self.assertRaises(nfa.RegexSyntaxError):
            nfa.compile_pattern(r"(a)\1")

    def test_unbalanced_group(self):
        # 括号不闭合属于语法错误。
        with self.assertRaises(nfa.RegexSyntaxError):
            nfa.compile_pattern(r"(ab")


class TestSpec(unittest.TestCase):
    """spec 是跨语言契约：需编译确定、JSON 往返不变，且往返后仍可正确匹配。"""

    def test_deterministic_and_json_roundtrip(self):
        s1 = nfa.compile_pattern(r"(a|b)+c?")
        s2 = json.loads(json.dumps(s1))  # 经 JSON 往返后结构不变（Rust 侧按同一格式反序列化）
        self.assertEqual(s1, s2)
        # 同一模式重复编译结果相同；且用往返后的 spec 去匹配仍得到正确结论。
        self.assertEqual(nfa.compile_pattern(r"(a|b)+c?"), s1)
        self.assertTrue(nfa.match_search(s2, "abbbc"))
        self.assertFalse(nfa.match_search(s2, "q"))


if __name__ == "__main__":
    unittest.main()
