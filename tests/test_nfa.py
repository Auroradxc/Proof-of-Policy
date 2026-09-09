"""Tests for the minimal regex->NFA engine (policydsl.nfa).

Strategy: property-check the simulator against Python ``re`` for the supported
ASCII subset, plus explicit fail-fast cases for unsupported syntax and
serialization determinism.
"""

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import nfa  # noqa: E402


PATTERNS = [
    r"[\w.+-]+@[\w-]+\.[\w.]+",      # email
    r"sk-[A-Za-z0-9]{10,}",          # secret
    r"\+\d[\d\s-]{6,}",              # phone-ish
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
    def test_corpus_agrees_with_re_search(self):
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
        spec = nfa.compile_pattern(r"[\w.+-]+@[\w-]+\.[\w.]+")
        self.assertTrue(nfa.match_search(spec, "ping admin@example.com"))
        self.assertFalse(nfa.match_search(spec, "ping the admin"))
        sk = nfa.compile_pattern(r"sk-[A-Za-z0-9]{16,}")
        self.assertTrue(nfa.match_search(sk, "key=sk-abcdefghijklmnop123"))
        self.assertFalse(nfa.match_search(sk, "sk-short"))


class TestFailFast(unittest.TestCase):
    def test_unsupported_anchors(self):
        for pat in [r"^x", r"x$"]:
            with self.assertRaises(nfa.RegexSyntaxError):
                nfa.compile_pattern(pat)

    def test_lookaround_rejected(self):
        with self.assertRaises(nfa.RegexSyntaxError):
            nfa.compile_pattern(r"(?=abc)def")

    def test_backreference_rejected(self):
        with self.assertRaises(nfa.RegexSyntaxError):
            nfa.compile_pattern(r"(a)\1")

    def test_unbalanced_group(self):
        with self.assertRaises(nfa.RegexSyntaxError):
            nfa.compile_pattern(r"(ab")


class TestSpec(unittest.TestCase):
    def test_deterministic_and_json_roundtrip(self):
        s1 = nfa.compile_pattern(r"(a|b)+c?")
        s2 = json.loads(json.dumps(s1))  # survives JSON serialization
        self.assertEqual(s1, s2)
        self.assertEqual(nfa.compile_pattern(r"(a|b)+c?"), s1)
        self.assertTrue(nfa.match_search(s2, "abbbc"))
        self.assertFalse(nfa.match_search(s2, "q"))


if __name__ == "__main__":
    unittest.main()
