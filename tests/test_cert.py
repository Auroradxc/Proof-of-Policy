"""合规证书（policydsl.cert）的单元测试。

证书是「合规判定可被第三方审计」的载体：载荷（payload）声明策略哈希与
AI Act 条款，信封（envelope）用 HMAC 签名保证不可伪造。这里锁定三件事——
签名/验签往返、换密钥或改载荷必须验签失败、摘要对内容敏感且稳定。
"""

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
    """极简 spec：只含一条关键词拦截规则，保证 payload 里带非空策略哈希。"""
    return compile_policy(Policy("p", "1", rules=[Rule("keyword_block", "kb", {"keywords": ["bad"]})]))


class TestCertificate(unittest.TestCase):
    """证书的信封：构造 → 签名 → 验签，以及各类篡改场景的拒绝。"""

    # 正常路径：版本号、策略哈希、AI Act 条款齐全，且验签后能原样取回载荷。
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

    # 换一把密钥验签必须失败：否则任何人都能伪造一张「合规」证书。
    def test_wrong_key_fails(self):
        env = cert.sign_payload(cert.build_payload("p", "1", _spec(), "public",
                                                   {"passed": True}, "vk"), OTHER)
        ok, _ = cert.verify_envelope(env, KEY)
        self.assertFalse(ok)

    # 保留合法签名但把载荷改成「通过」：验签必须失败（签名覆盖整个载荷字节）。
    def test_tampered_payload_fails(self):
        import base64
        import json
        env = cert.sign_payload(cert.build_payload("p", "1", _spec(), "public",
                                                   {"passed": True}, "vk"), KEY)
        payload = json.loads(base64.b64decode(env["payload"]))
        payload["outcome"]["passed"] = False  # 伪造判定结果
        env["payload"] = base64.b64encode(cert.canonical(payload)).decode()
        ok, _ = cert.verify_envelope(env, KEY)
        self.assertFalse(ok)

    # 摘要稳定性：同输入同摘要（可作数据库唯一键）；内容一变摘要就变（能发现改动）。
    def test_digest_stable_and_sensitive(self):
        spec = _spec()
        p1 = cert.build_payload("p", "1", spec, "public", {"passed": True}, "vk", None, "TS")
        p2 = cert.build_payload("p", "1", spec, "public", {"passed": True}, "vk", None, "TS")
        self.assertEqual(cert.cert_digest(p1), cert.cert_digest(p2))
        p3 = cert.build_payload("p", "1", spec, "public", {"passed": False}, "vk", None, "TS")
        self.assertNotEqual(cert.cert_digest(p1), cert.cert_digest(p3))


if __name__ == "__main__":
    unittest.main()
