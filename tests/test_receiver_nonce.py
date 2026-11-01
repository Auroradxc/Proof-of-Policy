"""接收方 nonce（P1-07）的单元与端到端测试。

覆盖三个场景与两类篡改：

* f=0（空 nonce）：同一张证书可被原样重放；
* verifier-only：V 的 nonce 能核对 V 手上的 T，但**不**保护 U 的交付；
* end-user：U 的 nonce 走新域 ``pop-bind-enduser-v1``，换 T / 换 nonce 都失败；
* 篡改 nonce / T / ``end_user_binding`` / issuer / scheme 一律拒绝（fail closed）。

边界：电路仍只算 verifier 域；end-user 绑定是证书 challenge 块的附加字段。
见 ``policydsl/privacy/challenge.py`` 模块文档与 ``docs/blockers/C1.md``。
"""

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl.core.compile import compile_policy  # noqa: E402
from policydsl.core.model import Policy, Rule  # noqa: E402
from policydsl.evidence import anchor, cert, keys  # noqa: E402
from policydsl.privacy import challenge, commit  # noqa: E402

POLICY = Policy("recv", "1.0.0", rules=[
    Rule("keyword_block", "no-secret", {"keywords": ["secret"]}),
])
GOOD_T = "all clear, nothing sensitive here"
BAD_T = "here is the secret you asked for"


def _spec() -> dict:
    return compile_policy(POLICY)


def _pack_dict() -> dict:
    return {"id": POLICY.id, "version": POLICY.version,
            "rules": [{"kind": r.kind, "name": r.name, "params": r.params}
                      for r in POLICY.rules]}


class TestVerifierNonce(unittest.TestCase):
    """verifier 域：旧行为、旧块兼容、未知 issuer fail closed。"""

    def setUp(self):
        self.nonce = bytes(range(32))
        self.binding = commit.response_binding(self.nonce, GOOD_T)

    def test_block_records_issuer_and_scheme(self):
        blk = challenge.challenge_block(self.nonce, self.binding)
        self.assertEqual(blk["issuer"], challenge.ISSUER_VERIFIER)
        self.assertEqual(blk["scheme"], commit.BIND_SCHEME)
        self.assertEqual(challenge.challenge_issuer(blk), "verifier")
        challenge.validate_challenge_block(blk)   # 不抛
        payload = {"challenge": blk}
        self.assertTrue(challenge.check_challenge(payload, GOOD_T))
        self.assertFalse(challenge.check_challenge(payload, BAD_T))
        # 强制期望 end-user 时，verifier 块必须被拒
        self.assertFalse(challenge.check_challenge(payload, GOOD_T, issuer="end-user"))

    def test_legacy_block_without_issuer_is_verifier(self):
        legacy = {"scheme": commit.BIND_SCHEME,
                  "nonce": self.nonce.hex(),
                  "response_binding": self.binding}
        self.assertEqual(challenge.challenge_issuer(legacy), "verifier")
        challenge.validate_challenge_block(legacy)
        self.assertTrue(challenge.check_challenge({"challenge": legacy}, GOOD_T))

    def test_tampered_nonce_or_response_rejected(self):
        payload = {"challenge": challenge.challenge_block(self.nonce, self.binding)}
        self.assertFalse(challenge.check_challenge(payload, GOOD_T + "!"))
        other = bytes(32)
        self.assertFalse(commit.verify_binding(other, GOOD_T, self.binding))
        blk = dict(payload["challenge"])
        blk["nonce"] = other.hex()
        self.assertFalse(challenge.check_challenge({"challenge": blk}, GOOD_T))

    def test_unknown_issuer_and_scheme_mismatch_fail(self):
        blk = challenge.challenge_block(self.nonce, self.binding)
        for bad in ({**blk, "issuer": "middlebox"},
                    {**blk, "scheme": commit.END_USER_BIND_SCHEME}):
            with self.subTest(bad=bad.get("issuer", bad.get("scheme"))):
                with self.assertRaises(ValueError):
                    challenge.validate_challenge_block(bad)
                self.assertFalse(challenge.check_challenge({"challenge": bad}, GOOD_T))


class TestEndUserNonce(unittest.TestCase):
    """end-user 域：新域、新字段、换 T/换 nonce/缺字段都拒绝。"""

    def setUp(self):
        self.nonce = bytes(range(32))
        self.verifier_binding = commit.response_binding(self.nonce, GOOD_T)
        self.end_binding = commit.end_user_response_binding(self.nonce, GOOD_T)

    def test_domains_are_separated(self):
        # 同一个 (nonce, T) 在两个域上必须不同 —— 否则角色可以互换。
        self.assertNotEqual(self.verifier_binding, self.end_binding)
        self.assertNotEqual(commit.end_user_response_binding(self.nonce, GOOD_T),
                            commit.end_user_response_binding(bytes(32), GOOD_T))

    def test_block_records_both_bindings_and_issuer(self):
        blk = challenge.end_user_challenge_block(
            self.nonce, self.verifier_binding, GOOD_T)
        self.assertEqual(blk["issuer"], "end-user")
        self.assertEqual(blk["scheme"], commit.END_USER_BIND_SCHEME)
        self.assertEqual(blk["nonce"], self.nonce.hex())
        self.assertEqual(blk["response_binding"], self.verifier_binding)
        self.assertEqual(blk["end_user_binding"], self.end_binding)
        challenge.validate_challenge_block(blk)

    def test_honest_delivery_accepts_divergent_rejects(self):
        blk = challenge.end_user_challenge_block(
            self.nonce, self.verifier_binding, GOOD_T)
        payload = {"challenge": blk}
        self.assertTrue(challenge.check_challenge(payload, GOOD_T, issuer="end-user"))
        self.assertFalse(challenge.check_challenge(payload, BAD_T, issuer="end-user"))
        # 强制按 verifier 解释 end-user 块也必须失败（角色不能混）
        self.assertFalse(challenge.check_challenge(payload, GOOD_T, issuer="verifier"))

    def test_tampered_nonce_or_end_binding_rejected(self):
        blk = challenge.end_user_challenge_block(
            self.nonce, self.verifier_binding, GOOD_T)
        cases = [
            {**blk, "nonce": bytes(32).hex()},
            {**blk, "end_user_binding": "00" * 32},
            {**blk, "end_user_binding": commit.end_user_response_binding(
                self.nonce, BAD_T)},
        ]
        for bad in cases:
            with self.subTest(case=list(bad)[0]):
                self.assertFalse(challenge.check_challenge({"challenge": bad},
                                                           GOOD_T, issuer="end-user"))

    def test_end_user_block_requires_end_user_binding(self):
        with self.assertRaises(ValueError):
            challenge.challenge_block(self.nonce, self.verifier_binding,
                                      issuer="end-user")
        blk = challenge.end_user_challenge_block(
            self.nonce, self.verifier_binding, GOOD_T)
        bad = dict(blk)
        del bad["end_user_binding"]
        with self.assertRaises(ValueError):
            challenge.validate_challenge_block(bad)
        self.assertFalse(challenge.check_challenge({"challenge": bad},
                                                   GOOD_T, issuer="end-user"))


class TestThreeScenarios(unittest.TestCase):
    """f=0 重放、verifier-only 缺口、end-user 拦截 —— 与 demo/bench 同口径。"""

    def test_f0_replay_succeeds(self):
        binding = commit.response_binding(b"", GOOD_T)
        payload = {"challenge": challenge.challenge_block(b"", binding)}
        self.assertTrue(challenge.check_challenge(payload, GOOD_T))
        self.assertTrue(challenge.check_challenge(payload, GOOD_T))  # 原样重放

    def test_verifier_only_does_not_protect_receiver(self):
        nonce_v = challenge.new_nonce()
        blk = challenge.challenge_block(
            nonce_v, commit.response_binding(nonce_v, GOOD_T))
        payload = {"challenge": blk}
        # V 能核对；U 没有 nonce_v，也没有 end_user_binding，无法发现换货。
        self.assertTrue(challenge.check_challenge(payload, GOOD_T, issuer="verifier"))
        self.assertNotIn(challenge.END_USER_BINDING_FIELD, blk)
        self.assertFalse(challenge.check_challenge(payload, BAD_T, issuer="verifier"))

    def test_end_user_blocks_divergent_delivery(self):
        nonce_u = challenge.new_nonce()
        blk = challenge.end_user_challenge_block(
            nonce_u, commit.response_binding(nonce_u, GOOD_T), GOOD_T)
        payload = {"challenge": blk}
        self.assertTrue(challenge.check_challenge(payload, GOOD_T, issuer="end-user"))
        self.assertFalse(challenge.check_challenge(payload, BAD_T, issuer="end-user"))


class TestVerifyCertEndUserCli(unittest.TestCase):
    """端到端：verify_cert.py 按 issuer 检查 end-user 绑定。"""

    def _issue(self, tmp: Path, nonce: bytes, proven: str) -> Path:
        spec = _spec()
        outcome = {"policy_hash": spec["sha256"], "passed": True,
                   "response_binding": commit.response_binding(nonce, proven),
                   "violations": []}
        block = challenge.end_user_challenge_block(
            nonce, outcome["response_binding"], proven)
        payload = cert.build_payload(POLICY.id, POLICY.version, spec, "public",
                                     outcome, vkey_hash="unproven",
                                     ts="2026-01-01T00:00:00Z", challenge=block)
        signer = cert.Ed25519Signer.generate()
        (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
        (tmp / "cert.json").write_text(json.dumps(cert.sign_payload(payload, signer)))
        (tmp / "pack.json").write_text(json.dumps(_pack_dict()))
        anchor.append_anchor(tmp / "ledger.jsonl", cert.cert_digest(payload))
        return tmp / "cert.json"

    def _verify(self, tmp: Path, cert_file: Path, response: Path):
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify" / "verify_cert.py"),
             "--cert", str(cert_file), "--pack", str(tmp / "pack.json"),
             "--ledger", str(tmp / "ledger.jsonl"), "--response", str(response)],
            cwd=str(REPO), capture_output=True, text=True)

    def test_end_user_honest_delivery_passes(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            nonce = challenge.new_nonce()
            cert_file = self._issue(tmp, nonce, GOOD_T)
            (tmp / "T.txt").write_text(GOOD_T)
            proc = self._verify(tmp, cert_file, tmp / "T.txt")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] challenge_issuer", proc.stdout)
        self.assertIn("issuer=end-user", proc.stdout)
        self.assertIn("[PASS] response_binding_end_user", proc.stdout)
        self.assertIn("RESULT: PASS", proc.stdout)

    def test_end_user_divergent_delivery_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            nonce = challenge.new_nonce()
            cert_file = self._issue(tmp, nonce, GOOD_T)
            (tmp / "T.txt").write_text(BAD_T)
            proc = self._verify(tmp, cert_file, tmp / "T.txt")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] response_binding", proc.stdout)
        self.assertIn("[FAIL] response_binding_end_user", proc.stdout)
        self.assertIn("RESULT: FAIL", proc.stdout)

    def test_tampered_end_user_binding_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            nonce = challenge.new_nonce()
            cert_file = self._issue(tmp, nonce, GOOD_T)
            env = json.loads(cert_file.read_text())
            payload = json.loads(base64.b64decode(env["payload"]))
            payload["challenge"]["end_user_binding"] = "00" * 32
            signer = cert.Ed25519Signer.generate()
            (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
            cert_file.write_text(json.dumps(cert.sign_payload(payload, signer)))
            anchor.append_anchor(tmp / "ledger.jsonl", cert.cert_digest(payload))
            (tmp / "T.txt").write_text(GOOD_T)
            proc = self._verify(tmp, cert_file, tmp / "T.txt")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] response_binding_end_user", proc.stdout)


if __name__ == "__main__":
    unittest.main()
