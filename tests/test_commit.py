"""Tests for private-mode primitives (policydsl.commit)."""

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import commit, nfa, pii  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.evaluate import check  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402


def _spec(rules):
    return compile_policy(Policy("t", "1", rules=rules))


class TestCommitment(unittest.TestCase):
    def test_matches_hashlib_and_is_hex32(self):
        t = "hello world"
        self.assertEqual(commit.commitment(t), hashlib.sha256(t.encode()).hexdigest())
        self.assertEqual(len(commit.commitment(t)), 64)

    def test_binding_distinct_inputs(self):
        self.assertNotEqual(commit.commitment("a"), commit.commitment("b"))
        # deterministic
        self.assertEqual(commit.commitment("a"), commit.commitment("a"))


class TestSpansAndMask(unittest.TestCase):
    def test_email_span_and_mask(self):
        text = "ping dev@example.com now"
        mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], text)
        self.assertEqual(mask, list(range(5, 20)))  # "dev@example.com" is 15 chars at [5,20)

    def test_redaction_roundtrip(self):
        text = "ping dev@example.com now"
        mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], text)
        red = commit.redact(text, mask)
        self.assertTrue(commit.redaction_ok(text, red, mask))
        # masked positions are '*'
        self.assertEqual(red[5:20], "*" * 15)
        # tampering outside the mask breaks it
        bad = red[:0] + "X" + red[1:]
        self.assertFalse(commit.redaction_ok(text, bad, mask))
        # wrong length
        self.assertFalse(commit.redaction_ok(text, red + "!", mask))
        # a masked position not holding the mask char
        bad2 = red[:5] + "d" + red[6:]
        self.assertFalse(commit.redaction_ok(text, bad2, mask))


class TestCanonicalViolations(unittest.TestCase):
    def test_matches_evaluate_semantics(self):
        p = Policy("t", "1", rules=[
            Rule("keyword_block", "kb", {"keywords": ["exploit", "DOXXING"]}),
            Rule("length_bound", "lb", {"min": 1, "max": 10}),
            Rule("pattern_block", "pb", {"patterns": [pii.PII_PATTERNS["email"]]}),
        ])
        spec = compile_policy(p)
        resp = "DOXXING someone at a@b.com"  # 26 chars -> length too
        golden = check(p, resp)
        kind_map = {"keyword": "keyword_block", "length": "length_bound", "pattern": "pattern_block"}
        cset = sorted({(v.rule.name, kind_map[v.evidence_kind]) for v in golden.violations})
        canon = commit.canonical_violations(spec, resp)
        self.assertEqual(sorted({(v["rule"], v["kind"]) for v in canon}), cset)
        self.assertEqual(len(canon), 3)  # keyword + length + pattern all violated
        # canonical evidence strings
        ev = {v["rule"]: v["evidence"] for v in canon}
        self.assertEqual(ev["kb"], "doxxing")     # ASCII-lowered, spec order
        self.assertEqual(ev["lb"], "len=26")
        self.assertEqual(ev["pb"], pii.PII_PATTERNS["email"])


class TestPrivateOutput(unittest.TestCase):
    def test_shape_and_no_leak(self):
        p = Policy("t", "1", rules=[Rule("pattern_block", "no_email",
                                         {"patterns": [pii.PII_PATTERNS["email"]]})])
        spec = compile_policy(p)
        resp = "Contact a@b.com for details"
        out = commit.private_output(spec, resp)
        self.assertFalse(out["passed"])
        self.assertEqual(out["response_commitment"], commit.commitment(resp))
        # violations reveal only commitments, never evidence text
        blob = json.dumps(out)
        self.assertNotIn("a@b.com", blob)
        self.assertNotIn("no_email", "".join(v["evidence_commitment"] for v in out["violations"]))
        self.assertEqual(len(out["violations"][0]["evidence_commitment"]), 64)
        self.assertIsNone(out["redaction"])

    def test_private_output_with_redaction(self):
        p = Policy("t", "1", rules=[Rule("pattern_block", "no_email",
                                         {"patterns": [pii.PII_PATTERNS["email"]]})])
        spec = compile_policy(p)
        resp = "Contact a@b.com for details"
        mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], resp)
        red = commit.redact(resp, mask)
        spans = commit.spec_spans(spec, resp)
        out = commit.private_output(spec, resp, mask, red, spans)
        self.assertEqual(out["redaction"]["mask_count"], len(mask))
        self.assertTrue(out["redaction"]["redaction_ok"])
        self.assertTrue(out["redaction"]["mask_covered"])
        self.assertEqual(out["redaction"]["redacted_commitment"], commit.commitment(red))


class TestMaskCoverage(unittest.TestCase):
    def _case(self):
        p = Policy("t", "1", rules=[Rule("pattern_block", "no_email",
                                         {"patterns": [pii.PII_PATTERNS["email"]]})])
        spec = compile_policy(p)
        resp = "Contact a@b.com for details"
        return spec, resp

    def test_real_span_valid_and_covers(self):
        spec, resp = self._case()
        spans = commit.spec_spans(spec, resp)
        self.assertTrue(commit.spans_valid(spec, resp, spans))
        mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], resp)
        self.assertTrue(commit.mask_covered(mask, spans))

    def test_fabricated_span_invalid(self):
        spec, resp = self._case()
        # "Contact" (0..7) is not an email match -> span must be rejected
        bad = [(0, 7)]
        self.assertFalse(commit.spans_valid(spec, resp, bad))
        # an empty witness cannot cover any masked position
        self.assertFalse(commit.mask_covered([0, 1], []))

    def test_private_output_rejects_mask_outside_spans(self):
        spec, resp = self._case()
        mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], resp)
        spans = commit.spec_spans(spec, resp)
        red = commit.redact(resp, mask)
        # claim a span that does NOT cover the mask (fabricated short span)
        out = commit.private_output(spec, resp, mask, red, [(0, 1)])
        self.assertFalse(out["redaction"]["mask_covered"])
        # and an empty witness cannot cover a non-empty mask
        out2 = commit.private_output(spec, resp, mask, red, [])
        self.assertFalse(out2["redaction"]["mask_covered"])


class TestEvidenceOpening(unittest.TestCase):
    def test_open_matches_and_rejects(self):
        frag = "dev@example.com"
        c = commit.evidence_commitment(frag)
        self.assertTrue(commit.open_evidence(c, frag))
        self.assertFalse(commit.open_evidence(c, "other@example.com"))
        self.assertFalse(commit.open_evidence(c, ""))

    def test_bundle_roundtrip(self):
        p = Policy("t", "1", rules=[
            Rule("keyword_block", "kb", {"keywords": ["exploit"]}),
            Rule("pattern_block", "pb", {"patterns": [pii.PII_PATTERNS["email"]]}),
        ])
        spec = compile_policy(p)
        bundle = commit.evidence_bundle(spec, "exploit a@b.com")
        self.assertEqual(len(bundle), 2)
        self.assertTrue(commit.verify_bundle(bundle))
        # tampering the disclosed evidence breaks verification
        bundle[0]["evidence"] = "tampered"
        self.assertFalse(commit.verify_bundle(bundle))


if __name__ == "__main__":
    unittest.main()
