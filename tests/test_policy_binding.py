"""策略绑定（P0-1）的回归测试 —— 把评估时实测复现的攻击永久锁死。

## 被锁死的攻击

修复前实测复现：证明者用**空策略**（``constraints: []``，恒通过）在 zkVM 里
判定一个实际违规的响应，拿到 ``passed=true`` 的证明；再在证书里把
``policy_hash`` 填成**真实策略**的哈希。彼时验证方的「策略绑定」只是一次
字符串比对（``payload["policy_hash"] == 重编译(pack).sha256``），而证明的
公开值里**根本不含**任何策略引用 —— 于是六项检查全绿，那张证书看起来
完全合规，却什么都没被证明。

根因：**被哈希的策略**与**参与判定的策略**是两份可分离的数据。

## 修复

策略以**规范 JSON 字节**（``spec_canonical``）传入电路，guest 从同一段字节
**同时**派生 ``policy_hash`` 与解析出的约束。二者不可分离 —— 想拿
``passed=true``，提交的哈希就必然是空策略的哈希，而不是真实策略的哈希。

## 本文件的三层锁

1. :class:`TestAttackIsDead`：Rust 侧实跑 ``pop-script --check``。「恒通过」与
   「真实策略哈希」**永远不会同时出现**。
2. :class:`TestFailsClosed`：策略解析不了时必须**产不出证明**，而不是静默跳过。
3. :class:`TestThreeWayBinding` / :class:`TestVerifierEndToEnd`：验证方的
   三方比对（含反空洞断言），以及一张**签名有效**的伪造证书必须被判 FAIL。

更慢的一层（真跑 SP1 证明验证）默认跳过，用 ``POP_TEST_PROOF=1`` 打开。
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl import anchor, cert, keys, verifier  # noqa: E402  (keys: P0-3 公钥分发)
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
from policydsl.serialize import spec_canonical_text  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"

#: 真实策略：响应里出现 "secret" 即违规。
REAL = Policy("real", "1.0.0", rules=[
    Rule("keyword_block", "no-secret", {"keywords": ["secret"]}),
])
#: 攻击用的空策略：没有任何约束 ⇒ 对任何输入恒通过。
EMPTY = Policy("empty", "1.0.0", rules=[])

#: 会违反真实策略的响应（攻击者想让它拿到「合规」的证明）。
VIOLATING = "here is the secret you asked for"


def _hash(policy: Policy) -> str:
    return compile_policy(policy)["sha256"]


class TestAttackIsDead(unittest.TestCase):
    """Rust 侧实跑：``passed=true`` 与「真实策略哈希」不可兼得。"""

    @classmethod
    def setUpClass(cls):
        if not POP_SCRIPT.exists():
            raise unittest.SkipTest("pop-script not built")

    def _check(self, spec_text: str, response: str) -> dict:
        """跑一次真实电路逻辑（宿主检查模式，不生成证明）。"""
        vectors = {"vectors": [{"name": "t", "response": response,
                                "spec_canonical": spec_text}]}
        with tempfile.TemporaryDirectory() as tmp:
            vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
            vp.write_text(json.dumps(vectors))
            proc = subprocess.run(
                [str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                cwd=str(REPO), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(op.read_text())[0]

    def test_real_policy_rejects_violating_response(self):
        # 反向对照（防止本文件在「什么都没跑」的情况下空过）：
        # 真策略 + 违规响应 ⇒ 必须判违规，且哈希就是真策略的哈希。
        out = self._check(spec_canonical_text(compile_policy(REAL)), VIOLATING)
        self.assertFalse(out["passed"])
        self.assertEqual(out["policy_hash"], _hash(REAL))
        self.assertEqual(out["violations"][0]["rule"], "no-secret")

    def test_empty_policy_commits_empty_hash_not_real(self):
        # 攻击的第一半：空策略确实能拿到 passed=true……
        out = self._check(spec_canonical_text(compile_policy(EMPTY)), VIOLATING)
        self.assertTrue(out["passed"])
        # ……但第二半做不到：电路承诺的哈希是**空策略**的哈希。
        self.assertEqual(out["policy_hash"], _hash(EMPTY))
        self.assertNotEqual(out["policy_hash"], _hash(REAL))

    def test_passed_true_never_cooccurs_with_real_hash(self):
        # 不变量（攻击者要而拿不到的那个组合）：对**真策略会拒绝**的响应，
        # 不存在任何策略能让证明既 passed=true 又承诺真策略的哈希。
        #
        # 注意前提必须逐例实测，不能假设：只有当真策略确实拒绝该响应时，
        # 「passed=true + 真哈希」才是攻击；否则那是一次正常的合规判定。
        real_hash = _hash(REAL)
        real_text = spec_canonical_text(compile_policy(REAL))
        empty_text = spec_canonical_text(compile_policy(EMPTY))
        for response in (VIOLATING, "SECRET", "a secret plan", "SeCrEt"):
            real_out = self._check(real_text, response)
            assert not real_out["passed"], f"前提不成立：真策略未拒绝 {response!r}"
            for text in (real_text, empty_text):
                with self.subTest(response=response, spec_hash=text[:40]):
                    out = self._check(text, response)
                    self.assertFalse(out["passed"] and out["policy_hash"] == real_hash,
                                     "攻击组合出现了：恒通过的判定 + 真策略哈希")


class TestFailsClosed(unittest.TestCase):
    """契约解析不了时必须产不出证明 —— 不能退化成「跳过这条规则」。"""

    @classmethod
    def setUpClass(cls):
        if not POP_SCRIPT.exists():
            raise unittest.SkipTest("pop-script not built")

    def test_unknown_kind_cannot_prove(self):
        # 未知 kind 会让 guest 的 serde 解析失败。因为 guest 用 expect() 而不是
        # 忽略错误，进程会非零退出 —— 「解不出来」因此等价于「证明不了」，
        # 而不是「这条约束被静默跳过」（后者会让攻击者只要塞个不认识的 kind
        # 就能绕过策略）。
        bogus = {"spec_version": "v1", "policy_id": "x", "policy_version": "1",
                 "semantic": "and", "constraints": [{"kind": "made_up", "name": "x"}]}
        with tempfile.TemporaryDirectory() as tmp:
            vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
            vp.write_text(json.dumps({"vectors": [
                {"name": "t", "response": "anything",
                 "spec_canonical": spec_canonical_text(bogus)}]}))
            proc = subprocess.run(
                [str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                cwd=str(REPO), capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0,
                                "未知约束类型竟然被接受了：策略可以被绕过")

    def test_unimplemented_semantic_cannot_prove(self):
        # 同类脱钩的另一面：`semantic` 进了哈希，却没被判定使用。
        # 若放行 "or"，契约里就有一个「被承诺、对结果毫无影响」的字段。
        # 电路只实现 "and"，其它取值必须同样 fail-closed。
        for semantic in ("or", "PER_RULE", ""):
            with self.subTest(semantic=semantic):
                spec = {"spec_version": "v1", "policy_id": "x", "policy_version": "1",
                        "semantic": semantic, "constraints": [
                            {"kind": "keyword_block", "name": "n", "keywords": ["secret"]}]}
                with tempfile.TemporaryDirectory() as tmp:
                    vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
                    vp.write_text(json.dumps({"vectors": [
                        {"name": "t", "response": "hello",
                         "spec_canonical": spec_canonical_text(spec)}]}))
                    proc = subprocess.run(
                        [str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                        cwd=str(REPO), capture_output=True, text=True)
                    self.assertNotEqual(proc.returncode, 0,
                                        f"未实现的语义 {semantic!r} 竟被按 and 判定了")


class TestThreeWayBinding(unittest.TestCase):
    """验证方三方比对的判定逻辑（纯函数层）。"""

    def setUp(self):
        self.real = _hash(REAL)
        self.empty = _hash(EMPTY)

    def test_all_sources_agree(self):
        ok, detail = verifier.check_policy_binding(
            [("cert", self.real), ("recompiled", self.real), ("proof", self.real)])
        self.assertTrue(ok, detail)

    def test_mismatched_proof_hash_fails(self):
        # 攻击的形态：证书与重编译一致（都是真策略），但**证明承诺的是空策略**。
        # 旧验证方只看前两者，这一路完全看不见。
        ok, detail = verifier.check_policy_binding(
            [("cert", self.real), ("recompiled", self.real), ("proof", self.empty)])
        self.assertFalse(ok)
        self.assertIn("MISMATCH", detail)

    def test_cert_cannot_claim_a_different_pack(self):
        # 攻击的另一形态：证明与证书自洽（都是空策略），但策略包是真策略 ——
        # 证书根本没在证明「这个策略包」被满足。
        ok, _ = verifier.check_policy_binding(
            [("cert", self.empty), ("recompiled", self.real), ("proof", self.empty)])
        self.assertFalse(ok)

    def test_single_source_is_not_a_binding(self):
        # 反空洞断言：只有一个来源时「全部相等」是恒真的，必须判失败 ——
        # 否则「三方比对」会退化成一个永远通过的空操作。
        ok, detail = verifier.check_policy_binding([("cert", self.real)])
        self.assertFalse(ok)
        self.assertIn("uncheckable", detail)

    def test_missing_sources_are_reported(self):
        # 缺失的来源必须如实列出来，避免报告读起来像是做过完整比对。
        ok, detail = verifier.check_policy_binding(
            [("cert", self.real), ("recompiled", self.real), ("proof", None)])
        self.assertTrue(ok)
        self.assertIn("absent", detail)
        self.assertIn("proof", detail)

    def test_committed_policy_hash_extraction(self):
        # 从验证器输出里取 policy_hash；取不到必须是 None（缺失），
        # 绝不能返回一个看似合法的值。
        self.assertEqual(verifier.committed_policy_hash(
            {"outcome": {"policy_hash": self.real}}), self.real)
        self.assertIsNone(verifier.committed_policy_hash({"outcome": {}}))
        self.assertIsNone(verifier.committed_policy_hash({}))
        self.assertIsNone(verifier.committed_policy_hash({"outcome": {"policy_hash": 7}}))


class TestVerifierEndToEnd(unittest.TestCase):
    """端到端：对一张**签名有效**的伪造证书跑 verify_cert.py，必须 FAIL。

    注意这里刻意用 ``cert.sign_payload`` **正常签名**（P0-3 之后是 Ed25519，
    公钥随证书一起交给验证方）—— 被测的不是「签名能不能挡伪造」，而是
    「一张格式完备、签名**正确**的证书，只要 policy_hash 对不上证明/策略包，
    仍必须被策略绑定检查拦下」。这两层是正交的：签名保证「谁说的」，
    策略绑定保证「说的是不是这个策略」。
    """

    def _run(self, pack: Policy, claimed_hash: str, tmp: Path) -> subprocess.CompletedProcess:
        """用 ``claimed_hash`` 组装并签名一张证书，跑一次独立验证。"""
        spec = compile_policy(pack)
        outcome = {"policy_hash": claimed_hash, "passed": True, "violations": []}
        # vkey_hash 用 unproven 而不是随手一个假哈希：这张证书没有证明工件，
        # 「宿主判定、无电路参与」才是它的诚实标注。用 `"deadbeef"` 会让它同时
        # 踩中 vkey_label 卡（见 TestVkeyLabelHonestyRejected），于是
        # `test_honest_certificate_passes` 这条**对照**就不再是诚实的了。
        payload = cert.build_payload(pack.id, pack.version, {"sha256": claimed_hash},
                                     "public", outcome,
                                     vkey_hash=cert.VKEY_HASH_UNPROVEN, ts="2026-01-01T00:00:00Z")
        # P0-3：用 Ed25519 正常签名，并把公钥写到证书旁边 —— 这样被测的是
        # 「格式完备、签名正确但策略绑定对不上」，而不是签名本身挡没挡住。
        signer = cert.Ed25519Signer.generate()
        env = cert.sign_payload(payload, signer)

        pack_file = tmp / "pack.json"
        pack_file.write_text(json.dumps({
            "id": pack.id, "version": pack.version,
            "rules": [{"kind": r.kind, "name": r.name, "params": r.params} for r in pack.rules],
        }))
        cert_file = tmp / "cert.json"
        cert_file.write_text(json.dumps(env))
        (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
        ledger = tmp / "ledger.jsonl"
        anchor.append_anchor(ledger, cert.cert_digest(payload))
        self.assertEqual(spec["sha256"] is not None, True)
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify_cert.py"),
             "--cert", str(cert_file), "--pack", str(pack_file), "--ledger", str(ledger)],
            cwd=str(REPO), capture_output=True, text=True)

    def test_honest_certificate_passes(self):
        # 对照：诚实的证书（声称的哈希 == 策略包的哈希）必须通过。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(REAL, _hash(REAL), Path(tmp))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] policy_hash", proc.stdout)

    def test_forged_certificate_is_rejected(self):
        # 攻击：证书声称的哈希是**另一个**策略（这里用空策略演示，方向可反），
        # 策略包却是真策略。签名完全有效，但绑定必须断。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(REAL, _hash(EMPTY), Path(tmp))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] policy_hash", proc.stdout)
        self.assertIn("RESULT: FAIL", proc.stdout)

    def test_cert_internal_inconsistency_is_rejected(self):
        # 证书**自己**两处声称的哈希（载荷顶层 vs outcome 内嵌）对不上 ——
        # 这种自相矛盾的证书同样必须被拦下。
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            pack_file = tmp / "pack.json"
            pack_file.write_text(json.dumps({
                "id": REAL.id, "version": REAL.version,
                "rules": [{"kind": r.kind, "name": r.name, "params": r.params}
                          for r in REAL.rules]}))
            payload = cert.build_payload(REAL.id, REAL.version, {"sha256": _hash(REAL)},
                                         "public",
                                         {"policy_hash": _hash(EMPTY), "passed": True,
                                          "violations": []},
                                         vkey_hash=cert.VKEY_HASH_UNPROVEN)
            signer = cert.Ed25519Signer.generate()
            (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
            cert_file = tmp / "cert.json"
            cert_file.write_text(json.dumps(cert.sign_payload(payload, signer)))
            ledger = tmp / "ledger.jsonl"
            anchor.append_anchor(ledger, cert.cert_digest(payload))
            proc = subprocess.run(
                [sys.executable, str(REPO / "scripts" / "verify_cert.py"),
                 "--cert", str(cert_file), "--pack", str(pack_file), "--ledger", str(ledger)],
                cwd=str(REPO), capture_output=True, text=True)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] policy_hash", proc.stdout)


class TestProofModeOverclaimRejected(unittest.TestCase):
    """证明模式标注的诚实性（P0-4）：**不得声称一档并不存在的证据**。

    一张没有任何证明工件的证书（``proof_sha256`` 为 ``null``）只有两种写法
    是诚实的：标 ``unproven``，或者（P0-4 之前签发的）干脆没有这个字段。
    若它自称 ``core`` —— 那等于告诉验证方「有零知识证明顶着」，而实测
    ``core`` 的 STARK **恰恰不是零知识**（``docs/sp1-zk-audit.md``），
    这种**过度声明**必须被 ``verify_cert.py`` 当场判 FAIL。
    """

    def _run(self, proof_mode, proof_sha, tmp: Path,
             drop: bool = False) -> subprocess.CompletedProcess:
        tmp = Path(tmp)
        pack_file = tmp / "pack.json"
        pack_file.write_text(json.dumps({
            "id": REAL.id, "version": REAL.version,
            "rules": [{"kind": r.kind, "name": r.name, "params": r.params} for r in REAL.rules]}))
        payload = cert.build_payload(REAL.id, REAL.version, compile_policy(REAL),
                                     "public", {"passed": True, "violations": []},
                                     vkey_hash=("deadbeef" if proof_sha else "unproven"),
                                     proof_sha256=proof_sha, ts="2026-01-01T00:00:00Z",
                                     proof_mode=proof_mode)
        if drop:
            # 模拟 P0-4 之前签发的证书：`build_payload` 现在总会写上这个字段，
            # 所以只能从载荷里手工抹掉 —— 那正是旧证书在验证方眼里的样子。
            payload["binding"].pop("proof_mode", None)
        signer = cert.Ed25519Signer.generate()
        (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
        cert_file = tmp / "cert.json"
        cert_file.write_text(json.dumps(cert.sign_payload(payload, signer)))
        ledger = tmp / "ledger.jsonl"
        anchor.append_anchor(ledger, cert.cert_digest(payload))
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify_cert.py"),
             "--cert", str(cert_file), "--pack", str(pack_file), "--ledger", str(ledger)],
            cwd=str(REPO), capture_output=True, text=True)

    def test_honest_unproven_certificate_passes(self):
        # 非恒真对照：诚实标 unproven 的证书必须通过（否则下面的 FAIL 不说明问题）。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(cert.PROOF_MODE_UNPROVEN, None, Path(tmp))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] proof_mode", proc.stdout)

    def test_overclaimed_mode_is_rejected(self):
        # 过度声明：自称 core，却没有任何证明工件。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run("core", None, Path(tmp))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] proof_mode", proc.stdout)
        self.assertIn("RESULT: FAIL", proc.stdout)

    def test_missing_field_is_skipped_not_failed(self):
        # P0-4 之前签发的证书没有这个字段：如实跳过，而不是倒过来判它失败
        # （那会让旧证书"因为缺字段"而失败，掩盖它真正的问题）。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(None, None, Path(tmp), drop=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] proof_mode", proc.stdout)
        self.assertIn("predate", proc.stdout)


class TestSessionProofModeOverclaim(unittest.TestCase):
    """会话级（`verify_session.py`）的证明模式核对（P0-4）。

    单张证书那一层由 :class:`TestProofModeOverclaimRejected` 覆盖；这里补的是
    **会话级**那条：它要求「标了某档模式」与「附了工件」互为充要条件
    （`(proof_mode != unproven) == (proof_sha256 is not None)`），并把缺字段的
    旧证书单独计数。没有这条，一张会话包里混进一张夸张的证书仍会全绿。
    """

    PACK = "policy_packs/eu_ai_act_v1.json"

    def _session(self, tmp: Path, proof_mode: str, proof_sha) -> Path:
        """造一个最小会话包：单张会话证书 + 账本 + 出证方公钥。"""
        sys.path.insert(0, str(REPO / "scripts"))
        from verify_session import load_policy  # 与验证脚本共用同一套加载逻辑

        pack = load_policy(REPO / self.PACK)
        payload = cert.build_payload(pack.id, pack.version, compile_policy(pack),
                                     "public", {"passed": True, "violations": []},
                                     "unproven", proof_sha, "2026-01-01T00:00:00Z",
                                     proof_mode=proof_mode)
        signer = cert.Ed25519Signer.generate()
        ledger = tmp / "ledger.jsonl"
        anchor.append_anchor(ledger, cert.cert_digest(payload))
        session = {
            "session_id": "t",
            "ledger": ledger.name,
            "packs": [self.PACK],
            "signers": [keys.public_record(signer.public_key)],
            "certificates": [{"kind": "llm", "policy_pack": self.PACK,
                              "envelope": cert.sign_payload(payload, signer)}],
            "summary": {},
        }
        path = tmp / "session.json"
        path.write_text(json.dumps(session))
        return path

    def _verify(self, path: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify_session.py"),
             "--session", str(path)],
            cwd=str(REPO), capture_output=True, text=True)

    def test_honest_session_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._verify(self._session(Path(tmp), cert.PROOF_MODE_UNPROVEN, None))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] certificates_proof_mode", proc.stdout)

    def test_overclaimed_certificate_fails_the_session(self):
        # 非恒真对照：同一份会话包，只把标注改成「有 core 证明」而工件仍是 None。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._verify(self._session(Path(tmp), "core", None))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] certificates_proof_mode", proc.stdout)
        self.assertIn("RESULT: FAIL", proc.stdout)

    def test_underclaimed_certificate_also_fails(self):
        # 反向也要拦：附了工件却标 unproven 是**低报**，同样让标注失去意义。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._verify(self._session(Path(tmp), cert.PROOF_MODE_UNPROVEN, "aa" * 32))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] certificates_proof_mode", proc.stdout)


class TestVkeyLabelHonestyRejected(unittest.TestCase):
    """``vkey_hash`` 标注的诚实性 —— 与 ``proof_mode`` **同构**的那条不变量。

    ``binding.vkey_hash`` 的语义是「**哪块电路**判定了它」：它指向
    ``pop-program`` / ``pop-infer`` / ``pop-session`` 三块 guest ELF 各自派生
    出的验证密钥。而宿主判定的三类证书（stream/llm/tool）**根本没有电路参与**
    —— 没有证明，就没有验证密钥可指，唯一诚实的取值就是 ``unproven``。

    这条不变量此前**一条都不存在**：验证方只比对「证书 vs 证明」
    （``vkey_hash`` / ``proof_vkey`` 两张卡），从不问这个值**本身**是否可能是
    真的。于是 ``scripts/demo_e2e.py`` 里写过的魔法值 ``"demo"`` 可以**全绿
    通过验证** —— 一个有内容、却没有任何东西能证伪的字段。修法就是这一组用例
    锁住的两条：**过度声明**（未附工件却声明 vkey）与**低报**（附了工件却标
    ``unproven``）都判 FAIL。
    """

    def _run(self, vkey, proof_sha, tmp: Path, drop: bool = False):
        tmp = Path(tmp)
        pack_file = tmp / "pack.json"
        pack_file.write_text(json.dumps({
            "id": REAL.id, "version": REAL.version,
            "rules": [{"kind": r.kind, "name": r.name, "params": r.params} for r in REAL.rules]}))
        payload = cert.build_payload(REAL.id, REAL.version, compile_policy(REAL),
                                     "public", {"passed": True, "violations": []},
                                     vkey_hash=vkey, proof_sha256=proof_sha,
                                     ts="2026-01-01T00:00:00Z")
        if drop:
            payload["binding"].pop("vkey_hash", None)
        signer = cert.Ed25519Signer.generate()
        (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
        cert_file = tmp / "cert.json"
        cert_file.write_text(json.dumps(cert.sign_payload(payload, signer)))
        ledger = tmp / "ledger.jsonl"
        anchor.append_anchor(ledger, cert.cert_digest(payload))
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify_cert.py"),
             "--cert", str(cert_file), "--pack", str(pack_file), "--ledger", str(ledger)],
            cwd=str(REPO), capture_output=True, text=True)

    def test_honest_unproven_vkey_passes(self):
        # 非恒真对照：诚实标 unproven 的证书必须通过（否则下面的 FAIL 不说明问题）。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(cert.VKEY_HASH_UNPROVEN, None, Path(tmp))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] vkey_label", proc.stdout)

    def test_placeholder_vkey_is_rejected(self):
        # **这就是原缺陷本身**：demo_e2e.py 写过的魔法值 "demo"。
        # 它没有任何证明工件，却往这个字段里写了一个看着有内容的值。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run("demo", None, Path(tmp))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] vkey_label", proc.stdout)
        self.assertIn("RESULT: FAIL", proc.stdout)

    def test_underclaimed_vkey_is_rejected(self):
        # 反向也要拦：附了工件却标 unproven 是**低报**，同样让这个字段失去意义
        # （与 proof_mode 的「低报也算失败」同一条理由）。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(cert.VKEY_HASH_UNPROVEN, "aa" * 32, Path(tmp))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] vkey_label", proc.stdout)

    def test_missing_field_is_skipped_not_failed(self):
        # 缺字段的证书如实跳过，而不是「因为缺字段」判失败 —— 与 2b 同款。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run(None, None, Path(tmp), drop=True)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] vkey_label", proc.stdout)
        self.assertIn("predate", proc.stdout)


class TestSessionVkeyLabelHonesty(unittest.TestCase):
    """会话级（``verify_session.py``）的 vkey 标注核对。

    单张证书那一层由 :class:`TestVkeyLabelHonestyRejected` 覆盖；这里补的是
    **会话级**那条：一张包里混进一张夸张的证书必须让整个会话 FAIL ——
    否则「逐张都查过了」在会话层并没有真的发生。
    """

    PACK = "policy_packs/eu_ai_act_v1.json"

    def _session(self, tmp: Path, vkey: str) -> Path:
        sys.path.insert(0, str(REPO / "scripts"))
        from verify_session import load_policy  # 与验证脚本共用同一套加载逻辑

        pack = load_policy(REPO / self.PACK)
        payload = cert.build_payload(pack.id, pack.version, compile_policy(pack),
                                     "public", {"passed": True, "violations": []},
                                     vkey, None, "2026-01-01T00:00:00Z")
        signer = cert.Ed25519Signer.generate()
        ledger = tmp / "ledger.jsonl"
        anchor.append_anchor(ledger, cert.cert_digest(payload))
        session = {
            "session_id": "t",
            "ledger": ledger.name,
            "packs": [self.PACK],
            "signers": [keys.public_record(signer.public_key)],
            "certificates": [{"kind": "llm", "policy_pack": self.PACK,
                              "envelope": cert.sign_payload(payload, signer)}],
            "summary": {},
        }
        path = tmp / "session.json"
        path.write_text(json.dumps(session))
        return path

    def _verify(self, path: Path):
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify_session.py"),
             "--session", str(path)],
            cwd=str(REPO), capture_output=True, text=True)

    def test_honest_session_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._verify(self._session(Path(tmp), cert.VKEY_HASH_UNPROVEN))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("[PASS] certificates_vkey_label", proc.stdout)

    def test_placeholder_vkey_fails_the_session(self):
        # 非恒真对照：同一份会话包，只把这个字段改成魔法值 "demo"。
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._verify(self._session(Path(tmp), "demo"))
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[FAIL] certificates_vkey_label", proc.stdout)
        self.assertIn("RESULT: FAIL", proc.stdout)


@unittest.skipUnless(os.environ.get("POP_TEST_PROOF") == "1",
                     "set POP_TEST_PROOF=1 to run the SP1 proof-level binding test")
class TestProofLevelBinding(unittest.TestCase):
    """最慢的一层：真跑 SP1 证明验证，核对公开值承诺的 policy_hash。

    需要 ``scripts/examples/out/cert_public/`` 下的工件与当前 guest ELF 匹配
    （P0-1 改了 ELF，旧工件需重新生成）。默认跳过，因为它要构造证明器状态
    （数十秒、约 10 GB RSS），不适合放进常规测试循环。
    """

    CERT_DIR = REPO / "scripts" / "examples" / "out" / "cert_public"

    PACK = REPO / "policy_packs" / "eu_ai_act_v1.json"

    def setUp(self):
        if not (self.CERT_DIR / "proof.bin").exists():
            self.skipTest("no proof artifact")

    def _verify(self, cert_file: Path, ledger: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO / "scripts" / "verify_cert.py"),
             "--cert", str(cert_file), "--pack", str(self.PACK),
             "--ledger", str(ledger), "--proof", str(self.CERT_DIR / "proof.bin")],
            cwd=str(REPO), capture_output=True, text=True,
            env=dict(os.environ, SP1_PROVER="cpu"))

    def test_proof_commits_the_certified_policy(self):
        proc = self._verify(self.CERT_DIR / "cert.json",
                            REPO / "scripts" / "examples" / "out" / "ledger.jsonl")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        # 必须出现「证明公开值」这一路来源，否则等于没做三方比对
        self.assertIn("[proof]", proc.stdout)
        self.assertIn("[PASS] policy_hash", proc.stdout)

    def test_forged_policy_hash_rejected_despite_valid_proof(self):
        """攻击的完整形态（真证明 + 假哈希）必须在证明层被拦下。

        取一张**真实有效**的证明，把证书里的 policy_hash 换成**另一个策略**的
        哈希并重新签名。证明本身依然密码学有效 —— 修复前，验证方只看
        「证书声称 vs 重编译」，而这两处都是伪造者写的，于是会全绿通过。
        现在第四路来源（证明公开值解出来的 outcome）把伪造戳穿。
        """
        pack = Policy("eu-ai-act-v1", "0.1.0", rules=[Rule("keyword_block", "x",
                                                          {"keywords": ["zzz"]})])
        env = json.loads((self.CERT_DIR / "cert.json").read_text())
        payload = cert.envelope_payload(env)
        forged = _hash(pack)
        self.assertNotEqual(forged, payload["policy_hash"])
        payload["policy_hash"] = forged
        payload["outcome"]["policy_hash"] = forged

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            signer = cert.Ed25519Signer.generate()
            (tmp / "key.json").write_text(json.dumps(keys.public_record(signer.public_key)))
            cert_file = tmp / "cert.json"
            cert_file.write_text(json.dumps(cert.sign_payload(payload, signer)))
            ledger = tmp / "ledger.jsonl"
            anchor.append_anchor(ledger, cert.cert_digest(payload))
            proc = self._verify(cert_file, ledger)

        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("[PASS] proof_verify", proc.stdout)   # 证明本身仍然有效
        self.assertIn("[FAIL] policy_hash", proc.stdout)    # 但绑定断了


if __name__ == "__main__":
    unittest.main()
