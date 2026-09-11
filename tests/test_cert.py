"""合规证书（policydsl.cert）的单元测试。

证书是「合规判定可被第三方审计」的载体：载荷（payload）声明策略哈希与
AI Act 条款，信封（envelope）用 **Ed25519** 签名（P0-3）保证不可伪造 ——
验证方只持公钥，因此**无法**伪造签名，这正是审计方需要的不可否认性。

签名方案由信封 ``keyid`` 的前缀分发（``ed25519`` / ``test-hmac-sha256``）。
``TestSchemeDispatch`` 专门锁住 P0-3 的验收条件：错密钥被拒、篡改被拒、
**旧 ``demo-hmac-sha256`` 信封被拒**；并且用「同一份代码下合法方案仍然通过」
证明那个拒绝不是恒真。
"""

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import cert  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402

#: 仅测试用的对称 HMAC 密钥（方案前缀 ``test-hmac-sha256``，非历史的 demo 方案）。
HMAC_KEY = b"test-key"
HMAC_OTHER = b"other-key"


def _spec():
    """极简 spec：只含一条关键词拦截规则，保证 payload 里带非空策略哈希。"""
    return compile_policy(Policy("p", "1", rules=[Rule("keyword_block", "kb", {"keywords": ["bad"]})]))


def _payload(mode: str = "public", outcome: dict | None = None) -> dict:
    """一份最小可签载荷。"""
    return cert.build_payload("p", "1", _spec(), mode,
                              outcome or {"passed": True, "violations": []},
                              "vk123", None, "2026-01-01T00:00:00Z")


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
        signer = cert.Ed25519Signer.generate()
        env = cert.sign_payload(payload, signer)
        self.assertEqual(cert.envelope_keyid(env), signer.keyid)
        self.assertEqual(cert.envelope_scheme(env), cert.ED25519_SCHEME)
        ok, got = cert.verify_envelope(env, signer.public_key)
        self.assertTrue(ok)
        self.assertEqual(got, payload)

    # P0-3 的核心性质：验证方**只需要公钥**。它拿不到私钥，所以伪造不出来。
    def test_public_key_alone_verifies(self):
        signer = cert.Ed25519Signer.generate()
        env = cert.sign_payload(_payload(), signer)
        pub = signer.public_key
        self.assertTrue(cert.verify_envelope(env, pub)[0])
        self.assertTrue(cert.verify_envelope(env, cert.keyring(pub))[0])
        # keyid 就是公钥的指纹：由公钥可现算，不需要任何别的信息
        self.assertEqual(cert.ed25519_keyid(pub),
                         cert.ED25519_SCHEME + ":" + cert.public_fingerprint(signer.public_bytes))

    # 换一把密钥验签必须失败：否则任何人都能伪造一张「合规」证书。
    def test_wrong_key_fails(self):
        signer = cert.Ed25519Signer.generate()
        other = cert.Ed25519Signer.generate()
        env = cert.sign_payload(_payload(), signer)
        self.assertFalse(cert.verify_envelope(env, other.public_key)[0])
        self.assertFalse(cert.verify_envelope(env, {})[0])

    # 保留合法签名但把载荷改成「通过」：验签必须失败（签名覆盖整个载荷字节）。
    def test_tampered_payload_fails(self):
        signer = cert.Ed25519Signer.generate()
        env = cert.sign_payload(_payload(outcome={"passed": True}), signer)
        payload = json.loads(base64.b64decode(env["payload"]))
        payload["outcome"]["passed"] = False  # 伪造判定结果
        env["payload"] = base64.b64encode(cert.canonical(payload)).decode()
        self.assertFalse(cert.verify_envelope(env, signer.public_key)[0])

    # 摘要稳定性：同输入同摘要（可作数据库唯一键）；内容一变摘要就变（能发现改动）。
    def test_digest_stable_and_sensitive(self):
        spec = _spec()
        p1 = cert.build_payload("p", "1", spec, "public", {"passed": True}, "vk", None, "TS")
        p2 = cert.build_payload("p", "1", spec, "public", {"passed": True}, "vk", None, "TS")
        self.assertEqual(cert.cert_digest(p1), cert.cert_digest(p2))
        p3 = cert.build_payload("p", "1", spec, "public", {"passed": False}, "vk", None, "TS")
        self.assertNotEqual(cert.cert_digest(p1), cert.cert_digest(p3))


class TestSchemeDispatch(unittest.TestCase):
    """按 ``keyid`` 前缀分发验签器；未知/废弃方案**结构性**被拒（P0-3 验收）。"""

    # 非恒真对照：同一份代码下，``test-hmac-sha256`` 方案仍然能正常往返。
    # 有这一例，下面两个「旧信封被拒」才说明是**方案被拒**，而非验签全坏。
    def test_test_hmac_scheme_still_works(self):
        signer = cert.HmacSigner(HMAC_KEY)
        self.assertEqual(cert.envelope_scheme(cert.sign_payload(_payload(), signer)),
                         cert.HMAC_TEST_SCHEME)
        env = cert.sign_payload(_payload(), signer)
        self.assertTrue(cert.verify_envelope(env, signer)[0])
        # 裸 bytes 会被包成 test-hmac 方案（旧式调用方式的兼容路径）
        env2 = cert.sign_payload(_payload(), HMAC_KEY)
        self.assertEqual(cert.envelope_scheme(env2), cert.HMAC_TEST_SCHEME)
        self.assertTrue(cert.verify_envelope(env2, HMAC_KEY)[0])
        # 错密钥仍须被拒
        self.assertFalse(cert.verify_envelope(env, HMAC_OTHER)[0])

    # 验收 ③（负例）：P0-3 之前用 DEMO_KEY 签出的信封**必须被拒**。
    def test_legacy_demo_envelope_rejected(self):
        legacy = cert.HmacSigner(cert.DEMO_KEY, keyid=cert.DEFAULT_KEYID)
        env = cert.sign_payload(_payload(), legacy)
        self.assertEqual(cert.envelope_scheme(env), "demo-hmac-sha256")
        ok, payload = cert.verify_envelope(env, cert.DEMO_KEY)
        self.assertFalse(ok)
        self.assertIsNone(payload)

    # 这个拒绝是**结构性**的：把配对的密钥放进 keyring 也没用 —— 方案先被否掉，
    # 根本走不到「按 keyid 取密钥」那一步。否则「拒绝」只是配置疏漏。
    def test_legacy_rejected_even_with_matching_key_in_ring(self):
        legacy = cert.HmacSigner(cert.DEMO_KEY, keyid=cert.DEFAULT_KEYID)
        env = cert.sign_payload(_payload(), legacy)
        ring = {cert.DEFAULT_KEYID: legacy}  # 密钥就在 ring 里，且就是签名那把
        self.assertEqual(legacy.keyid, cert.DEFAULT_KEYID)
        self.assertTrue(legacy.verify(base64.b64decode(env["payload"]),
                                      base64.b64decode(env["signatures"][0]["sig"])))
        self.assertFalse(cert.verify_envelope(env, ring)[0])  # 仍然被拒

    # 未知方案一律拒绝，且不因 keyring 里有同名 keyid 而放行。
    def test_unknown_scheme_rejected(self):
        env = cert.sign_payload(_payload(), cert.Ed25519Signer.generate())
        env["signatures"][0]["keyid"] = "rsa-pkcs1v15:" + "0" * 32
        self.assertFalse(cert.verify_envelope(env, {env["signatures"][0]["keyid"]: object()})[0])

    # 失败一律返回 (False, None)：调用方拿不到未经验签的载荷，就不会误用。
    def test_failure_never_returns_payload(self):
        signer = cert.Ed25519Signer.generate()
        env = cert.sign_payload(_payload(), signer)
        for ring in ({}, cert.Ed25519Signer.generate().public_key, None):
            ok, payload = cert.verify_envelope(env, ring)
            self.assertFalse(ok)
            self.assertIsNone(payload)
        # 信封本身残缺时也不能抛异常
        self.assertEqual(cert.verify_envelope({"payload": "!!"}, {}), (False, None))
        self.assertEqual(cert.verify_envelope({}, {}), (False, None))


class TestProofModeLabeling(unittest.TestCase):
    """``binding.proof_mode`` 的诚实标注（P0-4）。

    背景：``core``/``compressed`` 的 STARK 证明**不是零知识**的
    （见 ``docs/sp1-zk-audit.md``）—— 只用 ``vkey_hash`` 说「附了证明」，
    第三方无从知道见证有没有被暴露。``proof_mode`` 把这一档如实写进证书，
    并在此处锁住两条：**没有工件只能自称 unproven**；**未知模式不得被
    猜成已知档**（``proof_hiding`` 返回 ``"unknown"`` 而不是默认值）。
    """

    def test_no_artifact_is_labeled_unproven(self):
        # 默认（既不传 proof_mode 也不传 proof_sha256）→ 只能自称「未证明」。
        p = cert.build_payload("p", "1", _spec(), "public", {"passed": True}, "vk", None, "TS")
        self.assertEqual(p["binding"]["proof_mode"], cert.PROOF_MODE_UNPROVEN)
        self.assertEqual(p["binding"]["proof_sha256"], None)

    def test_explicit_mode_is_preserved(self):
        # 真附了工件时，调用方给出的档位原样写进证书（不被推断覆盖）。
        for mode in ("core", "compressed", "groth16", "plonk"):
            with self.subTest(mode=mode):
                p = cert.build_payload("p", "1", _spec(), "public", {"passed": True},
                                       "vk", "aa" * 32, "TS", proof_mode=mode)
                self.assertEqual(p["binding"]["proof_mode"], mode)

    def test_mode_reaches_the_digest(self):
        # proof_mode 是**稳定字段**：改它会改 cert_digest（锚定因此能发现改写）。
        kw = dict(ts="TS", proof_sha256="aa" * 32)
        a = cert.build_payload("p", "1", _spec(), "public", {"passed": True}, "vk",
                               proof_mode="core", **kw)
        b = cert.build_payload("p", "1", _spec(), "public", {"passed": True}, "vk",
                               proof_mode="compressed", **kw)
        self.assertNotEqual(cert.cert_digest(a), cert.cert_digest(b))

    def test_hiding_table(self):
        # 隐藏程度：core/compressed 的 STARK 不隐藏见证；groth16/plonk 只在
        # 包装层隐藏（内层 STARK 是 gnark 电路的私有见证，未审计）。
        self.assertEqual(cert.proof_hiding("core"), "none")
        self.assertEqual(cert.proof_hiding("compressed"), "none")
        self.assertEqual(cert.proof_hiding("groth16"), "wrapper-only")
        self.assertEqual(cert.proof_hiding("plonk"), "wrapper-only")
        self.assertEqual(cert.proof_hiding(cert.PROOF_MODE_UNPROVEN), "n/a")

    def test_unknown_mode_is_not_guessed(self):
        # 关键：遇到不认识的模式**不得**退回某个看似合理的档位 ——
        # 猜错就是把「未知」说成了「已知」，正是这张标注要防的事。
        for mode in (None, "", "stark-recursive", "CORE"):
            with self.subTest(mode=mode):
                self.assertEqual(cert.proof_hiding(mode), "unknown")


class TestKeyringLoading(unittest.TestCase):
    """验证方拿公钥的入口（``keys.load_keyring``）——只吃公开信息。

    验签的第一步是「公钥从哪来」。这条路径要**严格**：路径拼错必须当场报错，
    而不是把路径当成公钥文本去解析（那会得到「不是合法十六进制」这种与真因
    无关的提示）；同时保留「探测式回退」（``Path`` 不存在 → 空 ring），
    因为 ``verify_*.py`` 缺省会去试探同目录的 ``key.json``。
    """

    def test_missing_path_reports_the_real_reason(self):
        from policydsl import keys

        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "key.json"
            with self.assertRaises(FileNotFoundError) as ctx:
                keys.load_keyring(str(missing))
            self.assertIn("找不到公钥文件", str(ctx.exception))
            # 报错要**指名道姓**：只说「不是合法十六进制」会让人去查公钥内容，
            # 而真因是路径拼错。这里锁住「路径出现在提示里」。
            self.assertIn("key.json", str(ctx.exception))

    def test_probe_style_path_still_returns_empty(self):
        # 探测式回退保持不变：verify_*.py 会直接丢一个「可能存在」的 Path 进来
        from policydsl import keys

        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(keys.load_keyring(Path(tmp) / "key.json"), {})

    def test_hex_text_and_key_json_both_load(self):
        # 公钥文本（十六进制）与 key.json 记录两条路都要能用，且 keyid 一致
        from policydsl import keys

        signer = keys.ephemeral_signer()
        with tempfile.TemporaryDirectory() as tmp:
            kj = Path(tmp) / "key.json"
            kj.write_text(json.dumps(keys.public_record(signer.public_key)))
            from_file = keys.load_keyring(str(kj))
            from_text = keys.load_keyring(signer.public_hex)
            self.assertEqual(set(from_file), set(from_text))
            self.assertEqual(set(from_file), {signer.keyid})
            # 拿到的是**公钥**，据此能验签（私钥不出场）
            env = cert.sign_payload(_payload(), signer)
            self.assertTrue(cert.verify_envelope(env, from_text)[0])

    def test_record_claiming_a_wrong_keyid_is_rejected(self):
        # 记录里自称的 keyid 与公钥不符时，按 keyid 选密钥就失效了 → 必须拒绝
        from policydsl import keys

        signer = keys.ephemeral_signer()
        bad = dict(keys.public_record(signer.public_key))
        bad["keyid"] = "ed25519:" + "00" * 32
        with self.assertRaises(ValueError):
            keys.load_keyring(bad)


if __name__ == "__main__":
    unittest.main()
