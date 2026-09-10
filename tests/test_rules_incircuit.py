"""In-circuit rule coverage: format_check / tool_arg_guard / budget_bound.

Host-side parity (python golden vs `pop-script --check`) plus private-mode
evidence-commitment parity (canonical evidence strings must match Rust exactly).
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl import commit  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.serialize import spec_to_rust_constraints  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"


def run_check(vector: dict) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
        vp.write_text(json.dumps({"vectors": [vector]}))
        subprocess.run([str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                       cwd=str(REPO), check=True, capture_output=True, text=True)
        return json.loads(op.read_text())[0]


def spec_of(rules):
    return compile_policy(Policy("t", "1", rules=rules))


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestRulesInCircuit(unittest.TestCase):
    def setUp(self):
        self.fmt = spec_of([Rule("format_check", "must_be_json", {"format": "json"})])
        self.tool = spec_of([Rule("tool_arg_guard", "no_secret_args",
                                  {"forbidden_fields": ["password", "token"]})])
        self.budget = spec_of([Rule("budget_bound", "call_budget",
                                    {"budget": 2, "unit": "calls"})])
        self.tokens = spec_of([Rule("budget_bound", "token_budget",
                                    {"budget": 100, "unit": "tokens"})])

    def _parity(self, spec, response, golden_kinds, extras=None):
        vector = {"name": "t", "response": response,
                  "constraints": spec_to_rust_constraints(spec)}
        vector.update(extras or {})
        got = run_check(vector)
        canon = commit.canonical_violations(spec, response,
                                            (extras or {}).get("tool_calls"),
                                            (extras or {}).get("token_count"))
        self.assertEqual(sorted(v["kind"] for v in canon), sorted(golden_kinds))
        self.assertEqual(sorted(v["kind"] for v in got["violations"]), sorted(golden_kinds))
        self.assertEqual(got["passed"], not golden_kinds)
        return got

    def test_format_json(self):
        self._parity(self.fmt, '{"a": 1}', [])
        self._parity(self.fmt, "not json", ["format_check"])

    def test_format_int_canonical_subset(self):
        intspec = spec_of([Rule("format_check", "must_be_int", {"format": "int"})])
        self._parity(intspec, " 42 ", [])
        self._parity(intspec, "-7", [])
        self._parity(intspec, "1_000", ["format_check"])      # underscores rejected
        self._parity(intspec, "9" * 20, ["format_check"])     # >19 digits rejected
        self._parity(intspec, "12a", ["format_check"])

    def test_format_float_canonical_subset(self):
        fspec = spec_of([Rule("format_check", "must_be_float", {"format": "float"})])
        self._parity(fspec, "3.14", [])
        self._parity(fspec, "1e5", [])
        self._parity(fspec, "nan", ["format_check"])
        self._parity(fspec, "inf", ["format_check"])
        self._parity(fspec, "1_0.5", ["format_check"])

    def test_json_rejects_non_finite(self):
        self._parity(self.fmt, "NaN", ["format_check"])

    def test_tool_arg_guard(self):
        self._parity(self.tool, "", [], {"tool_calls": [{"name": "s", "args": {"q": "x"}}]})
        self._parity(self.tool, "", ["tool_arg_guard"],
                     {"tool_calls": [{"name": "s", "args": {"q": "x", "token": "t"}}]})

    def test_tool_arg_guard_tools_restriction(self):
        spec = spec_of([Rule("tool_arg_guard", "g",
                             {"forbidden_fields": ["token"], "tools": ["search_kb"]})])
        self._parity(spec, "", [], {"tool_calls": [{"name": "other", "args": {"token": "t"}}]})
        self._parity(spec, "", ["tool_arg_guard"],
                     {"tool_calls": [{"name": "search_kb", "args": {"token": "t"}}]})

    def test_budget_calls_and_tokens(self):
        self._parity(self.budget, "", [], {"tool_calls": [{"name": "a", "args": {}}]})
        self._parity(self.budget, "", ["budget_bound"],
                     {"tool_calls": [{"name": "a", "args": {}}, {"name": "b", "args": {}},
                                     {"name": "c", "args": {}}]})
        self._parity(self.tokens, "", [], {"token_count": 50})
        self._parity(self.tokens, "", ["budget_bound"], {"token_count": 150})


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestEvidenceCommitmentParity(unittest.TestCase):
    """Private-mode evidence commitments must match the Rust canonical strings."""

    def test_tool_and_format_commitments(self):
        spec = compile_policy(Policy("t", "1", rules=[
            Rule("format_check", "must_be_json", {"format": "json"}),
            Rule("tool_arg_guard", "no_secret_args", {"forbidden_fields": ["password", "token"]}),
        ]))
        response = "not json"
        calls = [{"name": "search_kb", "args": {"query": "x", "token": "s"}}]
        vector = {"name": "p", "response": response, "private": True,
                  "constraints": spec_to_rust_constraints(spec), "tool_calls": calls}
        got = run_check(vector)

        canon = commit.canonical_violations(spec, response, calls, None)
        expected = sorted((v["rule"], v["kind"], commit.evidence_commitment(v["evidence"]))
                          for v in canon)
        seen = sorted((v["rule"], v["kind"], v["evidence_commitment"])
                      for v in got["violations"])
        self.assertEqual(seen, expected)
        self.assertFalse(got["passed"])


if __name__ == "__main__":
    unittest.main()
