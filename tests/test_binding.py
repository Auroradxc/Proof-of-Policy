"""挑战-响应绑定（P0-2）的接受测试。

## 被堵住的洞

P0-1 之后，证明承诺了「**策略 π** 判定通过」。但「判定的是**哪条响应 T**」
依然悬空：

* 公开模式下 T 只是证明的**私有输入**，证书里从头到尾不出现它；
* 私有模式下更只剩一个 ``response_commitment = SHA256(T)`` —— 它说明「存在某条
  T 通过了」，却说不出是哪一条。

于是中间人可以用一条合规的 T 去换一条不合规的 T′ 送达客户端：证明依然有效，
因为它压根没提过 T′。验证方即便手握 T′，也没有任何东西能把它跟证明对上。

## 修复

**验证者出题**：客户端给一个一次性 ``nonce``，电路把
``response_binding = SHA256("pop-bind-v1" ‖ len(nonce) ‖ nonce ‖ T_utf8)``
与判定结果一起承诺进公开值。持 ``(T′, nonce)`` 的任何一方都能**离线**重算并
比对 —— 不需要网络、不需要证明器、不需要看到 T。

## 本文件的四层锁

1. :class:`TestBindingPrimitive`：绑定原语本身（含**拼接无歧义**与域分离）。
2. :class:`TestPythonRustParity`：真跑 ``pop-script --check``，电路算出来的
   ``response_binding`` 必须与 Python golden 逐字节相同 —— 两端分叉的话，
   验证方拿 Python 重算去核对就永远失败（或更糟：永远通过）。
3. :class:`TestChallengedCertificateEndToEnd`：签一张带挑战块的证书，用
   ``verify_cert.py --response`` 走完整验证。**换一条 T′ 必须被判 FAIL**。
4. :class:`TestReplayAndDomain`：换 nonce / 空 nonce / 重放 nonce 的行为。
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl import anchor, cert, challenge, commit, keys  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.serialize import spec_canonical_text  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"

#: 一条会被下面策略拒绝的响应（用于「换货」攻击的对照）。
POLICY = Policy("bind", "1.0.0", rules=[
    Rule("keyword_block", "no-secret", {"keywords": ["secret"]}),
])
#: 被证明的 T：合规。
GOOD_T = "all clear, nothing sensitive here"
#: 中间人**送达**的 T′：违规。证明里承诺的是 GOOD_T。
BAD_T = "here is the secret you asked for"


class TestBindingPrimitive(unittest.TestCase):
    """绑定原语：正确能开、换任一项都开不了。"""

    def setUp(self):
        self.nonce = bytes(range(32))
        self.binding = commit.response_binding(self.nonce, GOOD_T)

    def test_correct_pair_verifies(self):
        # ① 正确的 (nonce, T) 必须通过。
        self.assertTrue(commit.verify_binding(self.nonce, GOOD_T, self.binding))
        self.assertEqual(commit.response_binding(self.nonce, GOOD_T), self.binding)

    def test_wrong_response_fails(self):
        # ② 换 T 失败 —— 这就是「证明的 T ≠ 送达的 T′」被抓住的地方。
        self.assertFalse(commit.verify_binding(self.nonce, BAD_T, self.binding))

    def test_wrong_nonce_fails(self):
        # ③ 换 nonce 失败（重放防护的基础：另一轮会话的 nonce 开不了这一轮的绑定）。
        other = bytes(32)
        self.assertNotEqual(other, self.nonce)
        self.assertFalse(commit.verify_binding(other, GOOD_T, self.binding))

    def test_empty_nonce_is_a_distinct_domain(self):
        # ④ 空 nonce 与真 nonce 算出的绑定不同（域分离）。
        self.assertNotEqual(commit.response_binding(b"", GOOD_T), self.binding)
        self.assertTrue(commit.verify_binding(b"", GOOD_T,
                                              commit.response_binding(b"", GOOD_T)))

    def test_length_prefix_closes_concatenation_ambiguity(self):
        # 长度前缀的用途：没有它，nonce 与 T 之间的字节可以任意搬运而哈希不变
        # （下面的 (b"ab","cd") 与 (b"abcd","") 就会撞成同一个值）。
        self.assertNotEqual(commit.response_binding(b"ab", "cd"),
                            commit.response_binding(b"abcd", ""))

    def test_deterministic_and_sensitive(self):
        self.assertEqual(commit.response_binding(self.nonce, GOOD_T),
                         commit.response_binding(self.nonce, GOOD_T))
        self.assertNotEqual(commit.response_binding(self.nonce, GOOD_T),
                            commit.response_binding(self.nonce, GOOD_T + " "))

    def test_challenge_block_round_trip(self):
        blk = challenge.challenge_block(self.nonce, self.binding)
        self.assertEqual(blk["scheme"], commit.BIND_SCHEME)
        self.assertEqual(challenge.parse_nonce(blk["nonce"]), self.nonce)
        payload = {"challenge": blk}
        self.assertTrue(challenge.check_challenge(payload, GOOD_T))
        self.assertFalse(challenge.check_challenge(payload, BAD_T))
        # 方案名不认识 / 缺块 / nonce 非法 → 一律 False（不区分攻击与损坏）
        self.assertFalse(challenge.check_challenge({"challenge": {**blk, "scheme": "x"}}, GOOD_T))
        self.assertFalse(challenge.check_challenge({}, GOOD_T))
        self.assertFalse(challenge.check_challenge(
            {"challenge": {**blk, "nonce": "zz"}}, GOOD_T))

    def test_parse_nonce_rejects_bad_input(self):
        for bad in ("abc", "xy", "0g"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    challenge.parse_nonce(bad)

    def test_private_output_carries_binding(self):
        # 私有模式的公开输出必须同时带 response_commitment（存在某条 T 通过了）
        # 与 response_binding（是这一条 T）—— 二者回答的是不同的问题。
        spec = compile_policy(POLICY)
        out = commit.private_output(spec, GOOD_T, nonce=self.nonce)
        self.assertEqual(out["response_binding"], self.binding)
        self.assertEqual(out["response_commitment"], commit.commitment(GOOD_T))
        self.assertTrue(out["passed"])
        # 缺省（不给 nonce）也要有绑定，只是退化成空挑战的绑定
        self.assertEqual(commit.private_output(spec, GOOD_T)["response_binding"],
                         commit.response_binding(b"", GOOD_T))


class TestReplayAndDomain(unittest.TestCase):
    """一次性：同一个 nonce 不允许被消费两次。"""

    def test_nonce_store_rejects_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = challenge.NonceStore(Path(tmp) / "used.txt")
            n = challenge.new_nonce()
            self.assertFalse(store.seen(n))
            store.consume(n)
            self.assertTrue(store.seen(n))
            with self.assertRaises(ValueError):
                store.consume(n)
            # 换一个 nonce 正常
            store.consume(challenge.new_nonce())

    def test_nonce_store_persists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "used.txt"
            n = challenge.new_nonce()
            challenge.NonceStore(path).consume(n)
            self.assertTrue(challenge.NonceStore(path).seen(n))

    def test_new_nonce_is_32_bytes_and_fresh(self):
        a, b = challenge.new_nonce(), challenge.new_nonce()
        self.assertEqual(len(a), challenge.NONCE_BYTES)
        self.assertNotEqual(a, b)


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestPythonRustParity(unittest.TestCase):
    """电路算出的 response_binding 必须与 Python golden 逐字节相同。"""

    def _check(self, vector: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
            vp.write_text(json.dumps({"vectors": [vector]}))
            proc = subprocess.run(
                [str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                cwd=str(REPO), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(op.read_text())[0]

    def test_public_mode_binding_matches_python(self):
        spec = compile_policy(POLICY)
        for nonce in (challenge.new_nonce(), b"", b"\x00", bytes(range(64))):
            with self.subTest(nonce_len=len(nonce)):
                got = self._check({"name": "t", "response": GOOD_T,
                                   "spec_canonical": spec_canonical_text(spec),
                                   "nonce": list(nonce)})
                self.assertEqual(got["response_binding"],
                                 commit.response_binding(nonce, GOOD_T))
                # 判定本身不受 nonce 影响
                self.assertTrue(got["passed"])

    def test_private_mode_binding_matches_python(self):
        spec = compile_policy(POLICY)
        nonce = challenge.new_nonce()
        got = self._check({"name": "p", "response": GOOD_T, "private": True,
                           "spec_canonical": spec_canonical_text(spec),
                           "nonce": list(nonce)})
        golden = commit.private_output(spec, GOOD_T, nonce=nonce)
        self.assertEqual(got["response_binding"], golden["response_binding"])
        self.assertEqual(got["response_commitment"], golden["response_commitment"])

    def test_violating_response_binds_too(self):
        # 绑定与判定是两条正交的信息：违规的响应照样有（它自己的）绑定。
        spec = compile_policy(POLICY)
        nonce = challenge.new_nonce()
        got = self._check({"name": "t", "response": BAD_T,
                           "spec_canonical": spec_canonical_text(spec),
                           "nonce": list(nonce)})
        self.assertFalse(got["passed"])
        self.assertEqual(got["response_binding"], commit.response_binding(nonce, BAD_T))
        # 关键：这条违规响应的绑定，绝不能等于合规响应 GOOD_T 的绑定
        self.assertNotEqual(got["response_binding"], commit.response_binding(nonce, GOOD_T))


class TestChallengedCertificateEndToEnd(unittest.TestCase):
    """端到端：``verify_cert.py --response`` 必须把换过货的 T′ 判 FAIL。"""

    def _issue(self, tmp: Path, nonce: bytes) -> Path:
        """签一张带挑战块的证书（无证明，host-check 层的绑定检查足够）并锚定。"""
        spec = compile_policy(POLICY)
        outcome = {"policy_hash": spec["sha256"],
                   "response_binding": commit.response_binding(nonce, GOOD_T),
                   "passed": True, "violations": []}
        payload = cert.build_payload(
            POLICY.id, POLICY.version, spec, "public", outcome, vkey_hash="unproven",
            ts="2026-01-01T00:00:00Z",
            challenge=challenge.challenge_block(nonce, outcome["response_binding"]))
        signer = cert.Ed25519Signer.generate()
        # 公钥放进 key.json —— verify_cert.py 缺省就找它（P0-3）
        (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
        (tmp / "cert.json").write_text(json.dumps(cert.sign_payload(payload, signer)))
        (tmp / "pack.json").write_text(json.dumps({
            "id": POLICY.id, "version": POLICY.version,
            "rules": [{"kind": r.kind, "name": r.name, "params": r.params}
                      for r in POLICY.rules]}))
        anchor.append_anchor(tmp / "ledger.jsonl", cert.cert_digest(payload))
        return tmp / "cert.json"

    def _verify(self, tmp: Path, cert_file: Path, response: Path,
                extra: list | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify_cert.py"),
             "--cert", str(cert_file), "--pack", str(tmp / "pack.json"),
             "--ledger", str(tmp / "ledger.jsonl"), "--response", str(response),
             *(extra or [])],
            cwd=str(REPO), capture_output=True, text=True)

    def test_delivered_response_passes(self):
        # ① 送达的 T′ == 被证明的 T ⇒ 通过（而且 response_binding 这一卡确实跑了）
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            nonce = challenge.new_nonce()
            cert_file = self._issue(tmp, nonce)
            (tmp / "T.txt").write_text(GOOD_T)
            proc = self._verify(tmp, cert_file, tmp / "T.txt")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] response_binding", proc.stdout)
        self.assertIn("送达的 T′ 就是被证明的 T", proc.stdout)

    def test_substituted_response_is_rejected(self):
        # ③ 攻击的完整形态：证书、签名、锚定全部完好，只有**送达的响应**被换成
        #    一条不合规的 T′。策略绑定完全看不出来（它对 T 一无所知），
        #    响应绑定必须当场抓住。
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            nonce = challenge.new_nonce()
            cert_file = self._issue(tmp, nonce)
            (tmp / "T.txt").write_text(BAD_T)   # 中间人送达的是这一条
            proc = self._verify(tmp, cert_file, tmp / "T.txt")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[PASS] policy_hash", proc.stdout)       # 策略确实绑对了
        self.assertIn("[FAIL] response_binding", proc.stdout)  # 但响应不是那一条
        self.assertIn("对不上", proc.stdout)
        self.assertIn("RESULT: FAIL", proc.stdout)

    def test_wrong_nonce_rejected_via_cli(self):
        # ③′ 换 nonce（另一轮会话的挑战值）同样必须失败 —— 重放防护。
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            nonce = challenge.new_nonce()
            cert_file = self._issue(tmp, nonce)
            (tmp / "T.txt").write_text(GOOD_T)
            other = bytes(len(nonce))
            proc = self._verify(tmp, cert_file, tmp / "T.txt",
                                extra=["--nonce", other.hex()])
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] response_binding", proc.stdout)

    def test_certificate_without_challenge_skips_honestly(self):
        # 无挑战块的证书（流式/工具路径那一类）不该被误判为 FAIL，报告要如实
        # 说明「这张证书本来就没绑定响应」，而不是含糊地说「通过」。
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            spec = compile_policy(POLICY)
            payload = cert.build_payload(POLICY.id, POLICY.version, spec, "public",
                                         {"policy_hash": spec["sha256"], "passed": True,
                                          "violations": []},
                                         vkey_hash="unproven", ts="2026-01-01T00:00:00Z")
            signer = cert.Ed25519Signer.generate()
            (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
            (tmp / "cert.json").write_text(json.dumps(cert.sign_payload(payload, signer)))
            (tmp / "pack.json").write_text(json.dumps({
                "id": POLICY.id, "version": POLICY.version,
                "rules": [{"kind": r.kind, "name": r.name, "params": r.params}
                          for r in POLICY.rules]}))
            anchor.append_anchor(tmp / "ledger.jsonl", cert.cert_digest(payload))
            (tmp / "T.txt").write_text(GOOD_T)
            proc = self._verify(tmp, tmp / "cert.json", tmp / "T.txt")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] response_binding", proc.stdout)
        self.assertIn("not challenge-bound", proc.stdout)


if __name__ == "__main__":
    unittest.main()
