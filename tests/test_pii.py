"""Tests for PII patterns and check-digit validators (policydsl.pii)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl.evaluate import check  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl import pii  # noqa: E402


class TestPatternDetection(unittest.TestCase):
    def test_email(self):
        self.assertTrue(pii.contains("email", "reach dev@example.com"))
        self.assertFalse(pii.contains("email", "no address here"))

    def test_phone(self):
        self.assertTrue(pii.contains("phone", "call +1 234 567 8901"))
        self.assertTrue(pii.contains("phone", "fax (555) 123-4567 x"))
        self.assertFalse(pii.contains("phone", "plain text without digits"))

    def test_secret_key(self):
        self.assertTrue(pii.contains("secret_key", "export sk-abcdefghijklmnopqrstuvwxy"))
        self.assertFalse(pii.contains("secret_key", "export SK-abcdefghijklmnopqrstuvwxy"))
        self.assertFalse(pii.contains("secret_key", "sk-tiny"))

    def test_bearer_token(self):
        self.assertTrue(pii.contains("bearer_token",
                                     "Authorization: Bearer abcdefghijklmnop1234567"))
        self.assertFalse(pii.contains("bearer_token", "Bearer short"))


class TestIban(unittest.TestCase):
    VALID = ["GB82WEST12345698765432", "DE89 3704 0044 0532 0130 00", "GB29NWBK60161331926819"]

    def test_valid_ibans(self):
        for iban in self.VALID:
            with self.subTest(iban=iban):
                self.assertTrue(pii.is_valid_iban(iban))

    def test_invalid_ibans(self):
        for iban in ["GB00WEST12345698765432", "DE89 3704 0044 0532 0130 01", "short"]:
            with self.subTest(iban=iban):
                self.assertFalse(pii.is_valid_iban(iban))


class TestPiiPolicyPack(unittest.TestCase):
    def test_pack_rules_detect_violations(self):
        rules = [Rule("pattern_block", f"no_{n}", {"patterns": [pii.PII_PATTERNS[n]]})
                 for n in ["email", "phone", "secret_key", "bearer_token"]]
        policy = Policy("pii", "1", rules=rules)
        # Contains an email -> violated.
        r = check(policy, "My details: a@b.com")
        self.assertFalse(r.passed)
        self.assertEqual(r.violations[0].rule.name, "no_email")
        # Clean text -> passes (no PII-shaped substring).
        self.assertTrue(check(policy, "This is a plain advisory with no identifiers.").passed)

    def test_all_patterns_compile_within_subset(self):
        # pii module compiles eagerly at import; asserting names reachable is enough.
        self.assertIn("email", pii.pattern_names())


if __name__ == "__main__":
    unittest.main()
