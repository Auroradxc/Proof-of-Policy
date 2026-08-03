"""Unit tests for the Proof-of-Policy DSL (stdlib unittest)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl.compile import compile_policy  # noqa: E402
from policydsl.evaluate import check  # noqa: E402
from policydsl.model import Policy, PolicyError, Rule  # noqa: E402


class TestKeywordBlock(unittest.TestCase):
    def test_hit_is_violation(self):
        p = Policy("t", "1", rules=[Rule("keyword_block", "kb", {"keywords": ["bitcoin", "leverage"]})])
        r = check(p, "Buy bitcoin now!")
        self.assertFalse(r.passed)
        self.assertEqual(r.violations[0].evidence_kind, "keyword")
        self.assertIn("bitcoin", r.violations[0].evidence)

    def test_clean_passes(self):
        p = Policy("t", "1", rules=[Rule("keyword_block", "kb", {"keywords": ["bitcoin", "leverage"]})])
        self.assertTrue(check(p, "Safe financial advice").passed)


class TestLengthBound(unittest.TestCase):
    def test_too_long(self):
        p = Policy("t", "1", rules=[Rule("length_bound", "lb", {"min": 1, "max": 10})])
        self.assertFalse(check(p, "x" * 11).passed)

    def test_within_bounds(self):
        p = Policy("t", "1", rules=[Rule("length_bound", "lb", {"min": 1, "max": 10})])
        self.assertTrue(check(p, "short").passed)


class TestPatternBlock(unittest.TestCase):
    def test_email_detected(self):
        p = Policy("t", "1", rules=[Rule("pattern_block", "pb", {"patterns": [r"[\w.+-]+@[\w-]+\.[\w.]+"]})])
        self.assertFalse(check(p, "contact me at a@b.com").passed)

    def test_no_pattern_passes(self):
        p = Policy("t", "1", rules=[Rule("pattern_block", "pb", {"patterns": [r"sk-[A-Za-z0-9]{20,}"]})])
        self.assertTrue(check(p, "no secrets here").passed)


class TestAndSemantics(unittest.TestCase):
    def test_all_rules_required(self):
        p = Policy(
            "t", "1",
            rules=[
                Rule("keyword_block", "kb", {"keywords": ["bad"]}),
                Rule("length_bound", "lb", {"min": 1, "max": 5}),
            ],
        )
        self.assertFalse(check(p, "bad word here").passed)      # keyword hit
        self.assertFalse(check(p, "this is too long").passed)   # length hit
        self.assertTrue(check(p, "ok").passed)                  # both pass


class TestCompile(unittest.TestCase):
    def test_spec_shape(self):
        p = Policy("p", "0.1", rules=[Rule("keyword_block", "kb", {"keywords": ["a", "B"]})])
        s = compile_policy(p)
        self.assertEqual(s["spec_version"], "v1")
        self.assertEqual(s["constraints"][0]["keywords"], ["a", "b"])  # normalized + sorted
        self.assertEqual(len(s["sha256"]), 64)

    def test_spec_is_deterministic(self):
        p = Policy("p", "0.1", rules=[Rule("keyword_block", "kb", {"keywords": ["a", "B"]})])
        self.assertEqual(compile_policy(p)["sha256"], compile_policy(p)["sha256"])


class TestValidation(unittest.TestCase):
    def test_missing_keywords(self):
        with self.assertRaises(PolicyError):
            Policy("p", "1", rules=[Rule("keyword_block", "kb", {"keywords": []})]).validate()

    def test_bad_length_range(self):
        with self.assertRaises(PolicyError):
            Policy("p", "1", rules=[Rule("length_bound", "lb", {"min": 5, "max": 1})]).validate()


if __name__ == "__main__":
    unittest.main()
