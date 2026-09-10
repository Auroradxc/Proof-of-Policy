"""Tests for compliance certificates (policydsl.cert)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import cert  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402

KEY = b"test-key"
OTHER = b"other-key"


def _spec():
    return compile_policy(Policy("p", "1", rules=[Rule("keyword_block", "kb", {"keywords": ["bad"]})]))


class TestCertificate(unittest.TestCase):
    def test_build_sign_verify(self):
        spec = _spec()
        payload = cert.build_payload("p", "1", spec, "public",
                                     {"passed": True, "violations": []}, "vk123", None, "2026-01-01T00:00:00Z")
        self.assertEqual(payload["cert_version"], cert.CERT_VERSION)
        self.assertEqual(payload["policy_hash"], spec["sha256"])
        self.assertIn("art12_record_keeping", payload["ai_act"])
        self.assertIn("art13_transparency", payload["ai_act"])
        env = cert.sign_payload(payload, KEY)
        self.assertEqual(cert.envelope_keyid(env), cert.DEFAULT_KEYID)
        ok, got = cert.verify_envelope(env, KEY)
        self.assertTrue(ok)
        self.assertEqual(got, payload)

    def test_wrong_key_fails(self):
        env = cert.sign_payload(cert.build_payload("p", "1", _spec(), "public",
                                                   {"passed": True}, "vk"), OTHER)
        ok, _ = cert.verify_envelope(env, KEY)
        self.assertFalse(ok)

    def test_tampered_payload_fails(self):
        import base64
        import json
        env = cert.sign_payload(cert.build_payload("p", "1", _spec(), "public",
                                                   {"passed": True}, "vk"), KEY)
        payload = json.loads(base64.b64decode(env["payload"]))
        payload["outcome"]["passed"] = False  # forge
        env["payload"] = base64.b64encode(cert.canonical(payload)).decode()
        ok, _ = cert.verify_envelope(env, KEY)
        self.assertFalse(ok)

    def test_digest_stable_and_sensitive(self):
        spec = _spec()
        p1 = cert.build_payload("p", "1", spec, "public", {"passed": True}, "vk", None, "TS")
        p2 = cert.build_payload("p", "1", spec, "public", {"passed": True}, "vk", None, "TS")
        self.assertEqual(cert.cert_digest(p1), cert.cert_digest(p2))
        p3 = cert.build_payload("p", "1", spec, "public", {"passed": False}, "vk", None, "TS")
        self.assertNotEqual(cert.cert_digest(p1), cert.cert_digest(p3))


if __name__ == "__main__":
    unittest.main()
