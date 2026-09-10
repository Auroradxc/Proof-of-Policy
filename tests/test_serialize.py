"""Tests for the ConstraintSpec -> ProofRequest (Rust serde enum) mapping."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.serialize import spec_to_rust_constraints  # noqa: E402


class TestSerialize(unittest.TestCase):
    def test_three_in_circuit_kinds(self):
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
        # Pattern carries the compiled NFA specs (cross-layer contract).
        self.assertTrue(out[2]["PatternBlock"]["specs"])
        self.assertGreaterEqual(len(out[2]["PatternBlock"]["specs"][0]["states"]), 2)

    def test_all_six_kinds_map(self):
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
        # a synthetic constraint kind that has no in-circuit variant
        spec = {"constraints": [{"kind": "made_up", "name": "x"}]}
        with self.assertRaises(NotImplementedError):
            spec_to_rust_constraints(spec)


if __name__ == "__main__":
    unittest.main()
