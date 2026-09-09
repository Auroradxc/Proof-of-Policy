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

    def test_unsupported_kind_raises(self):
        p = Policy("t", "1", rules=[Rule("format_check", "fc", {"format": "json"})])
        with self.assertRaises(NotImplementedError):
            spec_to_rust_constraints(compile_policy(p))


if __name__ == "__main__":
    unittest.main()
