"""带盐策略承诺（BHV 定理 D / E4a）的单元测试。

覆盖三件事：

1. **不改变旧行为**：没有 ``policy_nonce`` 的 7 个随包策略，``policy_hash``
   必须逐字节不变（``test_acceptance_baseline`` 钉的是端到端基线；这里钉的是
   “盐字段不出现在规范字节里”这条更局部的机制）。
2. **有盐即变**：加盐改变哈希、盐进规范字节、大小写归一。
3. **枚举攻击**：无盐可恢复；有盐（攻击者不知道盐）不可恢复；盐泄露后可恢复。

**边界**：这些测试只覆盖公开值通道。``core`` 证明工件的见证泄露不在本文件，
见 ``docs/sp1-zk-audit.md`` 与 ``docs/certificate-binding-framework.md`` §7.3。
"""

import copy
import json
import unittest
from pathlib import Path

from policydsl.core.compile import canonical_spec_bytes, compile_policy
from policydsl.core.model import Policy, PolicyError
from policydsl.privacy.policy_commit import (
    POLICY_NONCE_BYTES,
    attach_nonce,
    new_policy_nonce,
    policy_commitment,
    verify_commitment,
)

REPO = Path(__file__).resolve().parents[1]
BASE_PACK = REPO / "policy_packs" / "agent_content_v1.json"


def _load_base():
    return json.loads(BASE_PACK.read_text(encoding="utf-8"))


def _candidates(base, n):
    out = []
    for i in range(n):
        p = copy.deepcopy(base)
        for rule in p.get("rules", []):
            if rule.get("kind") == "keyword_block":
                rule["params"]["keywords"] = [f"w{i:04d}", "doxxing", "weaponize"]
                break
        out.append(p)
    return out


def _hash(pack):
    pol = Policy.from_dict(pack)
    pol.validate()
    return compile_policy(pol)["sha256"]


class TestNoNonceBackwardCompatibility(unittest.TestCase):
    def setUp(self):
        self.base = _load_base()

    def test_no_nonce_absent_from_canonical_bytes(self):
        spec = compile_policy(Policy.from_dict(self.base))
        self.assertNotIn("policy_nonce", spec)
        self.assertNotIn(b"policy_nonce", canonical_spec_bytes(spec))

    def test_compile_is_deterministic(self):
        h1 = _hash(self.base)
        h2 = _hash(copy.deepcopy(self.base))
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)


class TestSaltedCommitment(unittest.TestCase):
    def setUp(self):
        self.base = _load_base()

    def test_nonce_changes_hash_and_appears_in_canonical(self):
        plain = _hash(self.base)
        salted_pack = attach_nonce(self.base, "ab" * 16)
        salted = _hash(salted_pack)
        self.assertNotEqual(plain, salted)
        spec = compile_policy(Policy.from_dict(salted_pack))
        self.assertIn(b"policy_nonce", canonical_spec_bytes(spec))
        self.assertIn(b"ab", canonical_spec_bytes(spec))  # 盐确实在字节里

    def test_nonce_is_lowercased(self):
        upper = attach_nonce(self.base, "AB" * 16)
        lower = attach_nonce(self.base, "ab" * 16)
        self.assertEqual(_hash(upper), _hash(lower))

    def test_verify_commitment_roundtrip_and_tamper(self):
        pack = attach_nonce(self.base, "cd" * 16)
        c = policy_commitment(pack)
        self.assertTrue(verify_commitment(pack, c))

        tampered = copy.deepcopy(pack)
        tampered["rules"][0]["params"]["keywords"].append("extra")
        self.assertFalse(verify_commitment(tampered, c))

        no_nonce = copy.deepcopy(self.base)
        self.assertFalse(verify_commitment(no_nonce, c))

    def test_new_nonce_is_128_bit_and_distinct(self):
        a, b = new_policy_nonce(), new_policy_nonce()
        self.assertEqual(len(a), POLICY_NONCE_BYTES * 2)
        self.assertNotEqual(a, b)
        int(a, 16)  # 必须是合法 hex


class TestNonceValidation(unittest.TestCase):
    def setUp(self):
        self.base = _load_base()

    def test_short_nonce_rejected(self):
        pack = attach_nonce(self.base, "ab" * 8)  # 64 bit
        with self.assertRaises(PolicyError):
            compile_policy(Policy.from_dict(pack))

    def test_non_hex_nonce_rejected(self):
        pack = copy.deepcopy(self.base)
        pack["policy_nonce"] = "zz" * 16
        with self.assertRaises(PolicyError):
            compile_policy(Policy.from_dict(pack))

    def test_odd_length_nonce_rejected(self):
        pack = copy.deepcopy(self.base)
        pack["policy_nonce"] = "a" * 33
        with self.assertRaises(PolicyError):
            compile_policy(Policy.from_dict(pack))


class TestEnumerationAttack(unittest.TestCase):
    """E4a 的单测版：候选空间小，但攻击形状与 bench 脚本一致。"""

    def setUp(self):
        self.base = _load_base()
        self.candidates = _candidates(self.base, 64)

    def test_unsalted_is_recoverable(self):
        target = self.candidates[17]
        target_hash = _hash(target)
        hit = next((i for i, p in enumerate(self.candidates)
                    if _hash(p) == target_hash), -1)
        self.assertEqual(hit, 17)

    def test_salted_is_not_recoverable_without_nonce(self):
        target = attach_nonce(self.candidates[17], "ef" * 16)
        target_hash = _hash(target)
        wrong_nonce = "00" * POLICY_NONCE_BYTES
        hits = []
        for p in self.candidates:
            q = copy.deepcopy(p)
            q["policy_nonce"] = wrong_nonce
            if _hash(q) == target_hash:
                hits.append(q)
        self.assertEqual(hits, [])

    def test_salt_leak_restores_recovery(self):
        nonce = "ef" * 16
        target = attach_nonce(self.candidates[17], nonce)
        target_hash = _hash(target)
        hit = next((i for i, p in enumerate(self.candidates)
                    if _hash({"policy_nonce": nonce, **p}) == target_hash), -1)
        self.assertEqual(hit, 17)


class TestMultipartyCarriesNonce(unittest.TestCase):
    def test_every_slice_carries_parent_nonce(self):
        from policydsl.proofs.multiparty import shard

        pack = attach_nonce(_load_base(), "12" * 16)
        parent = Policy.from_dict(pack)
        slices = shard(parent)
        self.assertTrue(slices)
        for role, sub in slices.items():
            self.assertEqual(sub.policy_nonce, parent.policy_nonce, role)


if __name__ == "__main__":
    unittest.main()
