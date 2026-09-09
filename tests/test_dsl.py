"""Unit tests for the Proof-of-Policy DSL (stdlib unittest)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl.compile import compile_policy  # noqa: E402
from policydsl.evaluate import check  # noqa: E402
from policydsl.model import Policy, PolicyError, Rule, ToolCall, Transcript  # noqa: E402


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


class TestFormatCheck(unittest.TestCase):
    def test_json_ok(self):
        p = Policy("t", "1", rules=[Rule("format_check", "fc", {"format": "json"})])
        self.assertTrue(check(p, '{"ok": true}').passed)

    def test_json_bad(self):
        p = Policy("t", "1", rules=[Rule("format_check", "fc", {"format": "json"})])
        r = check(p, "not a json document")
        self.assertFalse(r.passed)
        self.assertEqual(r.violations[0].evidence_kind, "format")

    def test_int_ok_and_bad(self):
        ok = Policy("t", "1", rules=[Rule("format_check", "fc", {"format": "int"})])
        bad = Policy("t", "1", rules=[Rule("format_check", "fc", {"format": "int"})])
        self.assertTrue(check(ok, " 42 ").passed)
        self.assertFalse(check(bad, "forty two").passed)

    def test_unknown_format_rejected(self):
        with self.assertRaises(PolicyError):
            Policy("t", "1", rules=[Rule("format_check", "fc", {"format": "yaml"})]).validate()


class TestToolArgGuard(unittest.TestCase):
    def test_forbidden_field_present(self):
        p = Policy("t", "1", rules=[
            Rule("tool_arg_guard", "tag", {"forbidden_fields": ["password", "token"]})])
        tx = Transcript(tool_calls=[ToolCall("search", {"q": "hi", "password": "secret"})])
        r = check(p, tx)
        self.assertFalse(r.passed)
        self.assertEqual(r.violations[0].evidence_kind, "tool_arg")
        self.assertEqual(r.violations[0].evidence["field"], "password")

    def test_clean_passes(self):
        p = Policy("t", "1", rules=[
            Rule("tool_arg_guard", "tag", {"forbidden_fields": ["password", "token"]})])
        tx = Transcript(tool_calls=[ToolCall("search", {"q": "hi"})])
        self.assertTrue(check(p, tx).passed)

    def test_tools_restriction(self):
        # Only inspect calls whose tool name is listed; the offending call is on another tool.
        p = Policy("t", "1", rules=[
            Rule("tool_arg_guard", "tag",
                 {"forbidden_fields": ["token"], "tools": ["search"]})])
        tx = Transcript(tool_calls=[
            ToolCall("http_get", {"url": "https://x?a", "token": "t"})])
        self.assertTrue(check(p, tx).passed)


class TestBudgetBound(unittest.TestCase):
    def test_call_count_over(self):
        p = Policy("t", "1", rules=[
            Rule("budget_bound", "bb", {"budget": 2, "unit": "calls"})])
        tx = Transcript(tool_calls=[ToolCall("a", {}), ToolCall("b", {}), ToolCall("c", {})])
        r = check(p, tx)
        self.assertFalse(r.passed)
        self.assertEqual(r.violations[0].evidence["total"], 3)

    def test_call_count_at_budget_passes(self):
        p = Policy("t", "1", rules=[
            Rule("budget_bound", "bb", {"budget": 2, "unit": "calls"})])
        tx = Transcript(tool_calls=[ToolCall("a", {}), ToolCall("b", {})])
        self.assertTrue(check(p, tx).passed)

    def test_token_budget(self):
        p = Policy("t", "1", rules=[
            Rule("budget_bound", "bb", {"budget": 100, "unit": "tokens"})])
        self.assertFalse(check(p, Transcript(tool_calls=[], token_count=150)).passed)
        with self.assertRaises(PolicyError):
            check(p, Transcript(tool_calls=[], token_count=None))

    def test_bad_budget(self):
        with self.assertRaises(PolicyError):
            Policy("t", "1", rules=[
                Rule("budget_bound", "bb", {"budget": -1, "unit": "calls"})]).validate()


class TestCompileExtendedKinds(unittest.TestCase):
    def test_new_kinds_compile(self):
        p = Policy(
            "p", "0.1", rules=[
                Rule("format_check", "fc", {"format": "json"}),
                Rule("tool_arg_guard", "tag",
                     {"forbidden_fields": ["password", "token"], "tools": ["http_get"]}),
                Rule("budget_bound", "bb", {"budget": 5, "unit": "calls"}),
            ])
        s = compile_policy(p)
        kinds = [c["kind"] for c in s["constraints"]]
        self.assertEqual(kinds, ["format_check", "tool_arg_guard", "budget_bound"])
        self.assertEqual(s["constraints"][1]["forbidden_fields"], ["password", "token"])
        self.assertEqual(s["constraints"][2]["budget"], 5)


if __name__ == "__main__":
    unittest.main()
