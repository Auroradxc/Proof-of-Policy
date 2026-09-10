"""ConstraintSpec → ProofRequest（Rust serde 枚举）映射的测试。

这是 Python 编译层与电路层之间的边界契约：变体名或字段结构一旦对不上，
SP1 侧反序列化就会失败。因此逐类型、逐顺序地锁定映射结果。
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.serialize import spec_to_rust_constraints  # noqa: E402


class TestSerialize(unittest.TestCase):
    """六个约束类型到 Rust 枚举变体的映射，以及未知类型的处理。"""

    def test_three_in_circuit_kinds(self):
        # 三种「在电路内可判定」的基础约束，输出顺序须与规则声明顺序一致。
        p = Policy("t", "1", rules=[
            Rule("keyword_block", "kb", {"keywords": ["bad"]}),
            Rule("length_bound", "lb", {"min": 1, "max": 100}),
            Rule("pattern_block", "pb", {"patterns": [r"a+@b\.c"]}),
        ])
        out = spec_to_rust_constraints(compile_policy(p))
        self.assertEqual(len(out), 3)
        self.assertIn("KeywordBlock", out[0])
        self.assertIn("LengthBound", out[1])
        self.assertIn("PatternBlock", out[2])
        # Pattern 变体携带编译后的 NFA spec——这是跨层契约的关键字段。
        self.assertTrue(out[2]["PatternBlock"]["specs"])
        self.assertGreaterEqual(len(out[2]["PatternBlock"]["specs"][0]["states"]), 2)

    def test_all_six_kinds_map(self):
        # 六种类型的变体名一个不能少，顺序也不能乱。
        p = Policy("t", "1", rules=[
            Rule("keyword_block", "kb", {"keywords": ["bad"]}),
            Rule("length_bound", "lb", {"min": 1, "max": 100}),
            Rule("pattern_block", "pb", {"patterns": [r"a+@b\.c"]}),
            Rule("format_check", "fc", {"format": "json"}),
            Rule("tool_arg_guard", "tg", {"forbidden_fields": ["token"]}),
            Rule("budget_bound", "bb", {"budget": 3, "unit": "calls"}),
        ])
        out = spec_to_rust_constraints(compile_policy(p))
        variants = [next(iter(o.keys())) for o in out]
        self.assertEqual(variants, ["KeywordBlock", "LengthBound", "PatternBlock",
                                    "FormatCheck", "ToolArgGuard", "BudgetBound"])

    def test_unknown_kind_raises(self):
        # 造一个电路中不存在对应变体的类型：必须显式抛错，而不是静默丢弃约束。
        spec = {"constraints": [{"kind": "made_up", "name": "x"}]}
        with self.assertRaises(NotImplementedError):
            spec_to_rust_constraints(spec)


if __name__ == "__main__":
    unittest.main()
