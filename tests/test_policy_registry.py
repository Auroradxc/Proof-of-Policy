"""P-PP 策略签发清单（``policydsl.evidence.policy_registry``）的单元测试。

覆盖五组性质：

1. **签发 → 验签**：Ed25519 清单能通过，哈希等于带盐承诺；
2. **任何被签字段的篡改都被拒**（哈希 / id / version / 时间 / keyid / 签名）；
3. **清单不泄露盐与策略正文** —— 这是带盐承诺不被清单抵消的前提；
4. **签发记录** save/load 往返，未知哈希被 ``verify_cert_policy`` 拒绝；
5. **带盐策略不可互换**：同一策略不同 nonce 得到不同 manifests，
   证书 B 的哈希在只含 manifest A 的记录里查不到。

**边界**：本文件只测证书层的「哈希是否被签发」。策略内容对第三方是否可见、
``core`` 证明工件是否泄露见证、``delegated`` 如何披露，均不在本层，
见 ``docs/design-policy-pp.md`` 与 ``docs/certificate-binding-framework.md`` §7.3。
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from policydsl.core.compile import compile_policy
from policydsl.core.model import Policy
from policydsl.evidence import cert
from policydsl.evidence.policy_registry import (
    MANIFEST_FIELDS,
    PolicyRegistry,
    canonical_manifest_bytes,
    issue_manifest,
    manifest_problem,
    verify_cert_policy,
    verify_manifest,
)
from policydsl.privacy.policy_commit import (
    attach_nonce,
    policy_commitment,
    verify_commitment,
)

REPO = Path(__file__).resolve().parents[1]
BASE_PACK = REPO / "policy_packs" / "agent_content_v1.json"

NONCE_A = "a1" * 16
NONCE_B = "b2" * 16


def _base_pack():
    return json.loads(BASE_PACK.read_text(encoding="utf-8"))


def _pack(nonce=None):
    pack = _base_pack()
    return attach_nonce(pack, nonce) if nonce is not None else pack


def _payload(pack, policy_id=None, policy_version=None):
    """用现有 ``cert.build_payload`` 组一张最小证书载荷（不改 cert 模块）。"""
    spec = compile_policy(Policy.from_dict(pack))
    return cert.build_payload(
        policy_id if policy_id is not None else pack["id"],
        policy_version if policy_version is not None else pack.get("version", "0.1.0"),
        spec, "public", {"passed": True, "violations": []}, "vk123", None,
        "2026-11-01T00:00:00Z")


class TestIssueAndVerify(unittest.TestCase):
    """正常路径：签发 → 字段齐全 → 权威公钥验签通过。"""

    def setUp(self):
        self.signer = cert.Ed25519Signer.generate()
        self.pack = _pack(NONCE_A)
        self.manifest = issue_manifest(self.pack, self.signer,
                                       issued_at="2026-11-01T00:00:00Z")

    def test_manifest_fields_are_complete(self):
        self.assertEqual(set(self.manifest), set(MANIFEST_FIELDS))
        self.assertEqual(self.manifest["manifest_version"], "v1")
        self.assertEqual(self.manifest["policy_id"], self.pack["id"])
        self.assertEqual(self.manifest["policy_version"], self.pack["version"])
        self.assertEqual(self.manifest["authority_keyid"], self.signer.keyid)

    def test_hash_is_the_salted_commitment(self):
        self.assertEqual(self.manifest["policy_hash"], policy_commitment(self.pack))
        self.assertTrue(verify_commitment(self.pack, self.manifest["policy_hash"]))
        # 未加盐的同一策略是另一个哈希 —— 清单签的是带盐的那一个。
        self.assertNotEqual(self.manifest["policy_hash"],
                            policy_commitment(_base_pack()))

    def test_verify_with_public_key_signer_and_hex(self):
        self.assertTrue(verify_manifest(self.manifest, self.signer.public_key))
        self.assertTrue(verify_manifest(self.manifest, self.signer))
        self.assertTrue(verify_manifest(self.manifest, self.signer.public_hex))
        self.assertIsNone(manifest_problem(self.manifest, self.signer.public_key))

    def test_manifest_is_deterministic(self):
        again = issue_manifest(self.pack, self.signer,
                               issued_at="2026-11-01T00:00:00Z")
        self.assertEqual(canonical_manifest_bytes(self.manifest),
                         canonical_manifest_bytes(again))
        self.assertEqual(self.manifest["sig"], again["sig"])


class TestTamperingIsRejected(unittest.TestCase):
    """字段完整性 + 签名覆盖所有非 sig 字段；改任何一个都验不过。"""

    def setUp(self):
        self.signer = cert.Ed25519Signer.generate()
        self.manifest = issue_manifest(_pack(NONCE_A), self.signer,
                                       issued_at="2026-11-01T00:00:00Z")

    def _tampered(self, field, value):
        m = copy.deepcopy(self.manifest)
        m[field] = value
        return m

    def test_tampered_policy_hash_rejected(self):
        m = self._tampered("policy_hash", "0" * 64)
        self.assertFalse(verify_manifest(m, self.signer.public_key))

    def test_tampered_policy_id_rejected(self):
        m = self._tampered("policy_id", "eu-ai-act-v1")
        self.assertFalse(verify_manifest(m, self.signer.public_key))

    def test_tampered_policy_version_rejected(self):
        m = self._tampered("policy_version", "9.9.9")
        self.assertFalse(verify_manifest(m, self.signer.public_key))

    def test_tampered_issued_at_rejected(self):
        m = self._tampered("issued_at", "2027-01-01T00:00:00Z")
        self.assertFalse(verify_manifest(m, self.signer.public_key))

    def test_tampered_authority_keyid_rejected(self):
        other = cert.Ed25519Signer.generate()
        m = self._tampered("authority_keyid", other.keyid)
        self.assertFalse(verify_manifest(m, self.signer.public_key))
        # 换成 other 的公钥也救不回来：签名仍是 self.signer 的。
        self.assertFalse(verify_manifest(m, other.public_key))

    def test_tampered_signature_rejected(self):
        m = copy.deepcopy(self.manifest)
        raw = bytearray(__import__("base64").b64decode(m["sig"]))
        raw[0] ^= 0x01
        m["sig"] = __import__("base64").b64encode(bytes(raw)).decode("ascii")
        self.assertFalse(verify_manifest(m, self.signer.public_key))

    def test_missing_field_rejected(self):
        m = copy.deepcopy(self.manifest)
        del m["issued_at"]
        self.assertFalse(verify_manifest(m, self.signer.public_key))

    def test_wrong_public_key_rejected(self):
        other = cert.Ed25519Signer.generate()
        self.assertFalse(verify_manifest(self.manifest, other.public_key))
        self.assertFalse(verify_manifest(self.manifest, other.keyid))

    def test_forbidden_nonce_field_rejected(self):
        m = copy.deepcopy(self.manifest)
        m["policy_nonce"] = NONCE_A
        self.assertFalse(verify_manifest(m, self.signer.public_key))


class TestManifestDoesNotLeakSaltOrPolicyText(unittest.TestCase):
    """清单是公开分发的：盐与策略正文不能出现在任何字段/规范字节里。"""

    def setUp(self):
        self.signer = cert.Ed25519Signer.generate()
        self.pack = _pack(NONCE_A)
        self.manifest = issue_manifest(self.pack, self.signer,
                                       issued_at="2026-11-01T00:00:00Z")

    def test_no_nonce_field_or_value(self):
        self.assertNotIn("policy_nonce", self.manifest)
        raw = canonical_manifest_bytes(self.manifest)
        self.assertNotIn(b"policy_nonce", raw)
        self.assertNotIn(NONCE_A.encode(), raw)
        self.assertNotIn(bytes.fromhex(NONCE_A), raw)

    def test_no_policy_text(self):
        raw = canonical_manifest_bytes(self.manifest).decode("utf-8")
        for keyword in ("exploit", "doxxing", "weaponize", "no_bad_topics",
                        "bounded_reply", "no_secret", "keyword_block",
                        "length_bound", "pattern_block", "rules"):
            self.assertNotIn(keyword, raw, keyword)

    def test_nonce_disclosed_only_by_authority(self):
        """审计路径：权威开示 (π, nonce) 后，验证者可重算清单里的哈希。"""
        disclosed = _pack(NONCE_A)
        self.assertTrue(verify_commitment(disclosed, self.manifest["policy_hash"]))
        wrong = _pack(NONCE_B)
        self.assertFalse(verify_commitment(wrong, self.manifest["policy_hash"]))


class TestRegistry(unittest.TestCase):
    """签发记录的增删查与 JSON 往返。"""

    def setUp(self):
        self.signer = cert.Ed25519Signer.generate()
        self.m_a = issue_manifest(_pack(NONCE_A), self.signer,
                                  issued_at="2026-11-01T00:00:00Z")
        self.m_b = issue_manifest(_pack(NONCE_B), self.signer,
                                  issued_at="2026-11-02T00:00:00Z")

    def test_add_get_contains(self):
        reg = PolicyRegistry()
        h = reg.add(self.m_a)
        self.assertEqual(h, self.m_a["policy_hash"])
        self.assertTrue(reg.contains(h))
        self.assertEqual(reg.get(h), self.m_a)
        self.assertIsNone(reg.get("0" * 64))
        self.assertEqual(len(reg), 1)

    def test_add_is_idempotent_but_conflicts_are_rejected(self):
        reg = PolicyRegistry([self.m_a])
        reg.add(copy.deepcopy(self.m_a))                 # 同内容：幂等
        self.assertEqual(len(reg), 1)
        conflict = copy.deepcopy(self.m_a)
        conflict["policy_id"] = "eu-ai-act-v1"           # 同哈希、不同内容
        with self.assertRaises(ValueError):
            reg.add(conflict)

    def test_missing_field_rejected_on_add(self):
        broken = copy.deepcopy(self.m_a)
        del broken["sig"]
        with self.assertRaises(ValueError):
            PolicyRegistry().add(broken)

    def test_save_load_roundtrip(self):
        reg = PolicyRegistry([self.m_b, self.m_a])       # 故意乱序
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            reg.save(path)
            loaded = PolicyRegistry.load(path)
        self.assertEqual(loaded.hashes(), reg.hashes())
        for h in reg.hashes():
            self.assertEqual(canonical_manifest_bytes(loaded.get(h)),
                             canonical_manifest_bytes(reg.get(h)))
        self.assertTrue(verify_manifest(loaded.get(self.m_a["policy_hash"]),
                                        self.signer.public_key))

    def test_load_accepts_bare_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bare.json"
            path.write_text(json.dumps([self.m_a]), encoding="utf-8")
            reg = PolicyRegistry.load(path)
        self.assertTrue(reg.contains(self.m_a["policy_hash"]))


class TestVerifyCertPolicy(unittest.TestCase):
    """证书 × 签发记录的端到端判定。"""

    def setUp(self):
        self.signer = cert.Ed25519Signer.generate()
        self.pack = _pack(NONCE_A)
        self.manifest = issue_manifest(self.pack, self.signer,
                                       issued_at="2026-11-01T00:00:00Z")
        self.payload = _payload(self.pack)
        self.registry = PolicyRegistry([self.manifest])

    def test_issued_policy_passes(self):
        ok, detail = verify_cert_policy(self.payload, self.registry,
                                        self.signer.public_key)
        self.assertTrue(ok, detail)
        self.assertIn(self.pack["id"], detail)

    def test_unknown_hash_is_rejected(self):
        """证书里的哈希不在一份被签发的清单里 —— P-PP 的核心否定用例。"""
        other = _payload(_pack(NONCE_B))
        ok, detail = verify_cert_policy(other, self.registry,
                                        self.signer.public_key)
        self.assertFalse(ok)
        self.assertIn("不在签发记录", detail)

    def test_registry_entry_hash_must_match_lookup_key(self):
        """裸 dict 记录里「按 A 查、拿 B 的签名」不能通过。"""
        other = issue_manifest(_pack(NONCE_B), self.signer,
                               issued_at="2026-11-01T00:00:00Z")
        swapped = {self.manifest["policy_hash"]: other}
        ok, detail = verify_cert_policy(self.payload, swapped,
                                        self.signer.public_key)
        self.assertFalse(ok)
        self.assertIn("不一致", detail)

    def test_manifest_signature_failure_is_rejected(self):
        other = cert.Ed25519Signer.generate()
        ok, detail = verify_cert_policy(self.payload, self.registry,
                                        other.public_key)
        self.assertFalse(ok)
        self.assertIn("签发清单校验失败", detail)

    def test_policy_id_version_must_match_manifest(self):
        forged = _payload(self.pack, policy_id="eu-ai-act-v1")
        ok, detail = verify_cert_policy(forged, self.registry,
                                        self.signer.public_key)
        self.assertFalse(ok)
        self.assertIn("id 与签发记录不符", detail)

        forged = _payload(self.pack, policy_version="9.9.9")
        ok, detail = verify_cert_policy(forged, self.registry,
                                        self.signer.public_key)
        self.assertFalse(ok)
        self.assertIn("版本与签发记录不符", detail)

    def test_registry_file_roundtrip_still_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            self.registry.save(path)
            loaded = PolicyRegistry.load(path)
        ok, detail = verify_cert_policy(self.payload, loaded,
                                        self.signer.public_hex)
        self.assertTrue(ok, detail)


class TestSaltedManifestsAreNotInterchangeable(unittest.TestCase):
    """同一策略、不同 nonce：两份清单哈希不同，不能拿来互相背书。"""

    def setUp(self):
        self.signer = cert.Ed25519Signer.generate()
        self.m_a = issue_manifest(_pack(NONCE_A), self.signer,
                                  issued_at="2026-11-01T00:00:00Z")
        self.m_b = issue_manifest(_pack(NONCE_B), self.signer,
                                  issued_at="2026-11-01T00:00:00Z")

    def test_same_policy_different_nonce_different_manifest(self):
        self.assertEqual(self.m_a["policy_id"], self.m_b["policy_id"])
        self.assertNotEqual(self.m_a["policy_hash"], self.m_b["policy_hash"])
        # 两份都各自有效 —— 差别只在盐与时间。
        self.assertTrue(verify_manifest(self.m_a, self.signer.public_key))
        self.assertTrue(verify_manifest(self.m_b, self.signer.public_key))

    def test_cert_b_cannot_be_vouched_by_registry_with_only_a(self):
        reg = PolicyRegistry([self.m_a])
        payload_b = _payload(_pack(NONCE_B))
        ok, detail = verify_cert_policy(payload_b, reg, self.signer.public_key)
        self.assertFalse(ok)
        self.assertIn("不在签发记录", detail)

    def test_manifest_a_cannot_cover_cert_b_by_relabeling(self):
        """把 A 的哈希改成 B 的哈希会让签名失效 —— 互换路径被堵死。"""
        relabeled = copy.deepcopy(self.m_a)
        relabeled["policy_hash"] = self.m_b["policy_hash"]
        self.assertFalse(verify_manifest(relabeled, self.signer.public_key))


if __name__ == "__main__":
    unittest.main()
