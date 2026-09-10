"""Tests for the matcher ablation switch (pike vs naive) across layers."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl import nfa, pii  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, PolicyError, Rule  # noqa: E402
from policydsl.serialize import spec_to_rust_constraints  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"

PATTERNS = [
    r"[\w.+-]+@[\w-]+\.[\w.]+",
    r"sk-[A-Za-z0-9]{16,}",
    r"\+\d[\d\s-]{6,}",
    r"a+", r"(cat|dog)s?", r"b{2,4}", r"\d{2,4}-\d{2,4}", r"a.*b",
]
TEXTS = [
    "contact a@b.com now", "plain text", "sk-abcdefghijklmnopqrstuvwxyz",
    "colours", "a cat and 3 dogs", "123-45 xy", "aaab", "", "no match here at all",
]


class TestMatcherParity(unittest.TestCase):
    def test_pike_equals_naive(self):
        for pat in PATTERNS:
            spec = nfa.compile_pattern(pat)
            for t in TEXTS:
                with self.subTest(pattern=pat, text=t):
                    self.assertEqual(nfa.match_search(spec, t),
                                     nfa.match_search_naive(spec, t))


class TestModeWiring(unittest.TestCase):
    def test_default_is_pike(self):
        spec = compile_policy(Policy("p", "1", rules=[
            Rule("pattern_block", "pb", {"patterns": [pii.PII_PATTERNS["email"]]})]))
        self.assertNotIn("mode", spec["constraints"][0])
        rt = spec_to_rust_constraints(spec)[0]["PatternBlock"]
        self.assertEqual(rt["mode"], "pike")

    def test_naive_mode_propagates(self):
        spec = compile_policy(Policy("p", "1", rules=[
            Rule("pattern_block", "pb", {"patterns": [pii.PII_PATTERNS["email"]],
                                         "match_mode": "naive"})]))
        self.assertEqual(spec["constraints"][0]["mode"], "naive")
        rt = spec_to_rust_constraints(spec)[0]["PatternBlock"]
        self.assertEqual(rt["mode"], "naive")

    def test_bad_mode_rejected(self):
        with self.assertRaises(PolicyError):
            Policy("p", "1", rules=[Rule("pattern_block", "pb", {
                "patterns": ["a"], "match_mode": "dfa"})]).validate()


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestRustNaivePath(unittest.TestCase):
    """The in-zkVM naive matcher must agree with pike (checked host-side, fast)."""

    def _run_check(self, mode: str, text: str) -> dict:
        spec = compile_policy(Policy("p", "1", rules=[
            Rule("pattern_block", "pb", {"patterns": [pii.PII_PATTERNS["email"]],
                                         "match_mode": mode})]))
        vectors = {"vectors": [{"name": f"{mode}", "response": text,
                                "constraints": spec_to_rust_constraints(spec)}]}
        with tempfile.TemporaryDirectory() as tmp:
            vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
            vp.write_text(json.dumps(vectors))
            subprocess.run([str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                           cwd=str(REPO), check=True, capture_output=True, text=True)
            return json.loads(op.read_text())[0]

    def test_naive_matches_pike_on_hit_and_clean(self):
        for text in ["reach me at a@b.com", "no address here", ""]:
            pike = self._run_check("pike", text)
            naive = self._run_check("naive", text)
            self.assertEqual(pike["passed"], naive["passed"], text)
            self.assertEqual([v["rule"] for v in pike["violations"]],
                             [v["rule"] for v in naive["violations"]], text)


if __name__ == "__main__":
    unittest.main()
