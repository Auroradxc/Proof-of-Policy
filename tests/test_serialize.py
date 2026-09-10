"""跨层契约（规范 JSON 字节）的测试。

Python 编译层与电路层之间**只有一份契约**：``canonical_spec_bytes(spec)``
产出的规范 JSON 字节。电路侧把这段字节整段读入，同时用它派生 ``policy_hash``
与解析要判定的约束 —— 二者不可分离（这正是 P0-1 修复的健全性问题）。

因此本文件锁定的是**那份字节的性质**，而不是任何「变体名映射」：
确定性、纯 ASCII、键排序、以及 ``sha256(bytes) == spec["sha256"]`` 这个
让电路与链下能算出同一个哈希的恒等式。
"""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl.compile import canonical_spec_bytes, compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.serialize import build_vectors, spec_canonical_text, vector_entry  # noqa: E402


def _all_six() -> Policy:
    """覆盖全部六类规则的策略。"""
    return Policy("t", "1", rules=[
        Rule("keyword_block", "kb", {"keywords": ["bad"]}),
        Rule("length_bound", "lb", {"min": 1, "max": 100}),
        Rule("pattern_block", "pb", {"patterns": [r"a+@b\.c"]}),
        Rule("format_check", "fc", {"format": "json"}),
        Rule("tool_arg_guard", "tg", {"forbidden_fields": ["token"]}),
        Rule("budget_bound", "bb", {"budget": 3, "unit": "calls"}),
    ])


class TestCanonicalContract(unittest.TestCase):
    """规范字节的确定性、ASCII 性与哈希恒等式。"""

    def test_hash_equals_sha256_of_canonical_bytes(self):
        # 恒等式：spec["sha256"] 必须等于对规范字节求的 sha256。
        # 电路侧算的就是同一个值 —— 这是「策略绑定」能成立的全部依据。
        for p in (_all_six(), Policy("t2", "0.2.0", rules=[
                Rule("length_bound", "lb", {"min": 0, "max": 10})])):
            spec = compile_policy(p)
            self.assertEqual(spec["sha256"],
                             hashlib.sha256(canonical_spec_bytes(spec)).hexdigest())

    def test_canonical_is_pure_ascii(self):
        # 纯 ASCII 是 design 的前提：电路侧把字节当作 Rust `String`（UTF-8）
        # 读取后对 `as_bytes()` 求哈希，必须与 Python 的字节逐位相同。
        # 一旦有位（非 ASCII 字符被原样写出），两侧哈希就会漂移。
        spec = compile_policy(Policy("策略-α", "1", rules=[
            Rule("keyword_block", "kb", {"keywords": ["敏感词"]})]))
        raw = canonical_spec_bytes(spec)
        raw.decode("ascii")  # 非 ASCII 会在此抛 UnicodeDecodeError
        self.assertTrue(all(b < 128 for b in raw))
        # ASCII 文本 ⇒ 解码再编码是恒等变换（电路侧正是这么做的）
        self.assertEqual(raw, spec_canonical_text(spec).encode("utf-8"))

    def test_canonical_is_deterministic_and_compact(self):
        spec = compile_policy(_all_six())
        text = spec_canonical_text(spec)
        # 确定性：同一 spec 反复序列化结果一致
        self.assertEqual(text, spec_canonical_text(spec))
        # 键排序 + 紧凑分隔符（无空格）
        self.assertNotIn(", ", text)
        self.assertNotIn(": ", text)
        # 顶层键按字典序排列
        keys = list(json.loads(text).keys())
        self.assertEqual(keys, sorted(keys))

    def test_metadata_excluded_from_contract(self):
        # sha256 自身不参与哈希（否则是自指）；契约只含 5 个稳定字段。
        obj = json.loads(spec_canonical_text(compile_policy(_all_six())))
        self.assertEqual(set(obj), {"spec_version", "policy_id", "policy_version",
                                    "semantic", "constraints"})
        self.assertNotIn("sha256", obj)


class TestContractCarriesConstraints(unittest.TestCase):
    """六类约束都如实出现在电路将要解析的那段字节里。"""

    def test_all_six_kinds_in_order(self):
        obj = json.loads(spec_canonical_text(compile_policy(_all_six())))
        kinds = [c["kind"] for c in obj["constraints"]]
        self.assertEqual(kinds, ["keyword_block", "length_bound", "pattern_block",
                                 "format_check", "tool_arg_guard", "budget_bound"])

    def test_pattern_block_carries_compiled_nfa(self):
        # pattern_block 的关键跨层字段：编译后的 NFA（电路不再自行编译正则）。
        obj = json.loads(spec_canonical_text(compile_policy(_all_six())))
        pat = next(c for c in obj["constraints"] if c["kind"] == "pattern_block")
        self.assertIn("nfa", pat)
        self.assertIn("compiled", pat["nfa"])
        self.assertTrue(pat["nfa"]["compiled"])
        self.assertGreaterEqual(len(pat["nfa"]["compiled"][0]["states"]), 2)

    def test_unknown_kind_carried_verbatim(self):
        # 未支持的 kind 必须**原样带进契约**，而不是在 Python 侧被丢弃或改写成
        # 别的东西：电路侧解析失败会 fail-closed（产不出证明），比静默跳过安全。
        spec = {"spec_version": "v1", "policy_id": "x", "policy_version": "1",
                "semantic": "and",
                "constraints": [{"kind": "made_up", "name": "x"}]}
        obj = json.loads(spec_canonical_text(spec))
        self.assertEqual(obj["constraints"], [{"kind": "made_up", "name": "x"}])


class TestVectorEntryHelpers(unittest.TestCase):
    """vectors 条目构造helper —— 收敛字段名，避免调用点写错。"""

    def test_vector_entry_shape(self):
        spec = compile_policy(_all_six())
        e = vector_entry(spec, "hello", private=True, mask=[1])
        self.assertEqual(set(e), {"spec_canonical", "response", "private", "mask"})
        self.assertEqual(e["spec_canonical"], spec_canonical_text(spec))
        self.assertEqual(e["response"], "hello")

    def test_build_vectors_wraps(self):
        spec = compile_policy(_all_six())
        out = build_vectors([vector_entry(spec, "a"), vector_entry(spec, "b")])
        self.assertEqual(len(out["vectors"]), 2)


if __name__ == "__main__":
    unittest.main()
