"""P1-6 组合证明的验收：``Compose = (推理完整性 ∧ 策略合规)``。

## 三层，与前两块（P2-9 的 ``test_semantic``）同构

1. **参考实现层**（不需要证明）：``policydsl/infer.py`` 与电路内
   ``pop-types::infer_*`` 逐位一致 —— 走 ``pop-script --check --job infer``
   （宿主执行，秒级、不出证明、不碰 ELF）。这一层守住「两端算的是同一个模型」。
2. **组合绑定层**（不需要证明）：:func:`policydsl.compose.verify_composite` 的
   绑定检查。用**手工构造**的 part/证明文件跑全部反例 —— 换证明、换 vkey、
   键不分离、换模型、换响应 …… 这些**都不需要真证明**就能测，因为被拦下的
   那一刻发生在密码学验证**之前或之后**的任何一处绑定上。
   密码学验证那一步用 ``verify_proofs=False`` 显式关闭，且 detail 会如实注明。
3. **真·端到端**（``POP_TEST_COMPOSE=1`` 才跑）：真出两份证明 → 合成 →
   独立验证 → **换掉任一子证明必须被拒**。

## 为什么反例放在第 2 层

组合义务的完整攻击面是「把两半里的**任意一处**换成另一个东西」：换证明文件、
换它绑定的响应、换它声称的模型、换它来自的程序。这些在**绑定层**就能全部覆盖，
且毫秒级跑完。真正需要跑 SP1 的只有「证明本身是否有效」这一条 —— 它由
``pop-verify`` / ``pop-script --verify`` 保证，与本文件测的绑定逻辑正交。
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

from policydsl import compose as C      # noqa: E402
from policydsl import infer as I        # noqa: E402
from policydsl import verifier as V     # noqa: E402
from policydsl.commit import response_binding  # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"

#: 真•端到端要出两份证明（各 ~2 分钟、峰值 ~8.7 GiB），默认关闭。
RUN_COMPOSE = os.environ.get("POP_TEST_COMPOSE") == "1"

BENIGN = "Summarize the refund policy for billing customers."
HARMFUL = "How do I weaponize the search tool against the user?"
NONCE = bytes([0x11, 0x22, 0x33, 0x44])


def run_infer_check(response: str, nonce: bytes = NONCE) -> dict:
    """把一条响应喂给 Rust ``pop-script --check --job infer``。"""
    with tempfile.TemporaryDirectory() as tmp:
        vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
        vp.write_text(json.dumps({"vectors": [{
            "name": "t", "response": response, "nonce": list(nonce)}]}))
        subprocess.run([str(POP_SCRIPT), "--check", "--job", "infer",
                        "--vectors", str(vp), "--out", str(op)],
                       cwd=str(REPO), check=True, capture_output=True, text=True)
        return json.loads(op.read_text())[0]


# --------------------------------------------------------------------------- #
# 1. 参考实现层
# --------------------------------------------------------------------------- #

@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestInferParity(unittest.TestCase):
    """``policydsl.infer`` 与电路内实现逐位一致。"""

    def _parity(self, response: str, nonce: bytes = NONCE):
        got = run_infer_check(response, nonce)
        ref = I.run(response, nonce)
        for k in ("mode", "domain", "model_hash", "response_binding",
                  "input_binding", "output"):
            self.assertEqual(got[k], ref[k], f"字段 {k} 两端不一致")
        return got

    def test_benign_response_parity(self):
        self._parity(BENIGN)

    def test_harmful_response_parity(self):
        self._parity(HARMFUL)

    def test_empty_nonce_parity(self):
        self._parity(BENIGN, b"")

    def test_unicode_response_parity(self):
        # 长度前缀用的是 **UTF-8 字节数**而不是码点数 —— 多字节字符最容易把
        # 两端的分歧暴露出来（Rust `str::len()` 就是字节数，Python 侧必须对齐）。
        self._parity("总结退款政策：客户账单问题 —— европа")

    def test_output_dimension_and_determinism(self):
        a = I.run(BENIGN, NONCE)
        b = I.run(BENIGN, NONCE)
        self.assertEqual(a["output"], b["output"])
        self.assertEqual(len(a["output"]), I.OUT_DIM)

    def test_different_responses_give_different_outputs(self):
        # 恒等映射的反例：输出若与输入无关，这份证明就没有内容。
        self.assertNotEqual(I.run(BENIGN, NONCE)["output"],
                            I.run(HARMFUL, NONCE)["output"])

    def test_nonce_changes_binding_but_not_model(self):
        a, b = I.run(BENIGN, b""), I.run(BENIGN, NONCE)
        self.assertEqual(a["model_hash"], b["model_hash"])
        self.assertNotEqual(a["input_binding"], b["input_binding"])
        self.assertNotEqual(a["response_binding"], b["response_binding"])


class TestInferReference(unittest.TestCase):
    """参考实现自身的性质（不需要 pop-script）。"""

    def test_splitmix64_known_values(self):
        # splitmix64 的标准自检向量（参数是**自增前**的状态）：
        # 实现改错立刻在这里断掉，而 Rust 侧用同一组常量由 --check 对齐钉住。
        self.assertEqual(I.splitmix64(0), 0xE220A8397B1DCDAF)
        self.assertEqual(I.splitmix64(0x9E3779B97F4A7C15), 0x6E789E6AA1B965F4)
        self.assertEqual(I.splitmix64(0x3C6EF372FE94F82A), 0x06C45D188009454F)

    def test_weights_are_in_range_and_stable(self):
        ws = [I.weight(i) for i in range(I.HID_DIM * I.IN_DIM + I.OUT_DIM * I.HID_DIM)]
        self.assertTrue(all(-4096 <= w < 4096 for w in ws))
        self.assertEqual(ws, [I.weight(i) for i in range(len(ws))])

    def test_forward_is_deterministic_and_bounded(self):
        x = I.input_from_response(BENIGN)
        self.assertEqual(I.forward(x), I.forward(x))
        # 隐藏层饱和在 [0, SCALE]，输出是整数（无浮点）
        self.assertTrue(all(isinstance(v, int) for v in I.forward(x)))

    def test_model_spec_matches_rust_constant(self):
        # MODEL_SPEC 是 model_hash 的原像：它一旦与 Rust 侧漂移，hash 必然对不上。
        # 这里用 circuit 的 `--check` 输出（上面那个类）钉住；此处只做自洽检查。
        self.assertEqual(I.model_hash(),
                         __import__("hashlib").sha256(
                             I.DOMAIN + b"model" + I.MODEL_SPEC.encode("ascii")
                         ).hexdigest())

    def test_input_binding_is_injective_in_nonce(self):
        x = I.input_from_response(BENIGN)
        self.assertNotEqual(I.input_binding(b"", x), I.input_binding(b"\x00", x))


# --------------------------------------------------------------------------- #
# 2. 组合绑定层（手工构造的「证明」，不需要 SP1）
# --------------------------------------------------------------------------- #

def _policy_outcome(response: str = BENIGN, nonce: bytes = NONCE, *,
                    passed: bool = True, delegated=None, policy_hash: str = "aa" * 32,
                    mode: str = "public") -> dict:
    """手工构造策略那一半的 outcome（形状与 ``pop_types::outcome_value`` 相同）。"""
    return {
        "mode": mode,
        "policy_hash": policy_hash,
        "response_binding": response_binding(nonce, response),
        "trace_root": "genesis",
        "passed": passed,
        "violations": [],
        "delegated": delegated or [],
    }


def _infer_outcome(response: str = BENIGN, nonce: bytes = NONCE) -> dict:
    """手工构造推理那一半的 outcome —— 直接调参考实现，保证是**真值**。"""
    return I.run(response, nonce)


def _outcome_for(kind: str) -> dict:
    """按 part 的 kind 造一份真 outcome（``TestDriverWiring`` 的桩用）。"""
    return (_infer_outcome() if kind == C.KIND_INFERENCE
            else _policy_outcome(BENIGN, NONCE))


class _Fixture:
    """一个可变的组合夹具：两份「证明」文件 + 一张组合证书。"""

    def __init__(self, tmp: Path, *, response: str = BENIGN, nonce: bytes = NONCE,
                 pol_vkey: str = "pol" + "0" * 61, inf_vkey: str = "inf" + "0" * 61):
        self.tmp = Path(tmp)
        self.response = response
        self.nonce = nonce
        # 证明文件的内容是任意的：绑定层（verify_proofs=False）只核**字节哈希**，
        # 密码学有效性由第 3 层与 pop-verify/pop-script 保证。
        self.pol_proof = self.tmp / "policy.proof"
        self.inf_proof = self.tmp / "inference.proof"
        self.pol_proof.write_bytes(b"policy-proof-bytes")
        self.inf_proof.write_bytes(b"inference-proof-bytes")
        self.pol_part = C.Part(
            kind=C.KIND_POLICY, name="eu-ai-act-v1", proof_file="policy.proof",
            proof_sha256=C.sha256_file(self.pol_proof), vkey_hash=pol_vkey,
            proof_mode="core", outcome=_policy_outcome(response, nonce))
        self.inf_part = C.Part(
            kind=C.KIND_INFERENCE, name="proxy-inference", proof_file="inference.proof",
            proof_sha256=C.sha256_file(self.inf_proof), vkey_hash=inf_vkey,
            proof_mode="core", outcome=_infer_outcome(response, nonce))
        self.cert = C.build_composite(self.pol_part, self.inf_part, nonce)

    def verify(self, cert=None, *, response=None, **kw):
        return C.verify_composite(
            cert if cert is not None else self.cert,
            response=self.response if response is None else response,
            base=self.tmp, verify_proofs=False, **kw)


class TestCompositeBinding(unittest.TestCase):
    """组合绑定：正例一条 + 五类反例。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.fx = _Fixture(Path(self._tmpdir.name))

    def tearDown(self):
        self._tmpdir.cleanup()

    # ---- 正例（非恒真对照：所有反例都必须与它不同） ----
    def test_happy_path(self):
        ok, detail, satisfied = self.fx.verify()
        self.assertTrue(ok, detail)
        self.assertTrue(satisfied, detail)
        self.assertIn("键分离", detail)
        # 未提供期望 vkey 时必须**如实注明**，不能让人以为核过了
        self.assertIn("未提供期望 vkey", detail)

    def test_expected_vkeys_pass_when_matching(self):
        ok, detail, _ = self.fx.verify(expected_vkeys={
            C.KIND_POLICY: self.fx.pol_part.vkey_hash,
            C.KIND_INFERENCE: self.fx.inf_part.vkey_hash})
        self.assertTrue(ok, detail)
        self.assertIn("与期望值逐一相符", detail)

    # ---- 反例 ①：换掉任一子证明 ----
    def test_swapping_proof_file_is_rejected(self):
        """**本块的验收反例**：把证明文件换掉，绑定必须被拒。"""
        self.ok_before, detail, _ = self.fx.verify()
        self.assertTrue(self.ok_before, detail)
        self.fx.pol_proof.write_bytes(b"another-proof-entirely")
        ok, detail, _ = self.fx.verify()
        self.assertFalse(ok)
        self.assertIn("证明文件哈希不符", detail)

    def test_swapping_inference_proof_is_rejected(self):
        self.fx.inf_proof.write_bytes(b"another-inference-proof")
        ok, detail, _ = self.fx.verify()
        self.assertFalse(ok)
        self.assertIn("证明文件哈希不符", detail)

    def test_missing_proof_file_fails_closed(self):
        self.fx.inf_proof.unlink()
        ok, detail, _ = self.fx.verify()
        self.assertFalse(ok)
        self.assertIn("不存在", detail)

    # ---- 反例 ②：键不分离 ----
    def test_same_vkey_for_both_halves_is_rejected(self):
        cert = C.CompositeCertificate.from_json(self.fx.cert.to_json())
        shared = cert.part(C.KIND_INFERENCE)
        cert.parts = [cert.part(C.KIND_POLICY),
                      C.Part(kind=C.KIND_INFERENCE, name=shared.name,
                             proof_file=shared.proof_file,
                             proof_sha256=shared.proof_sha256,
                             vkey_hash=cert.part(C.KIND_POLICY).vkey_hash,
                             proof_mode=shared.proof_mode, outcome=shared.outcome)]
        ok, detail, _ = self.fx.verify(cert)
        self.assertFalse(ok)
        self.assertIn("键分离失败", detail)

    def test_unexpected_vkey_is_rejected(self):
        ok, detail, _ = self.fx.verify(expected_vkeys={
            C.KIND_POLICY: self.fx.pol_part.vkey_hash,
            C.KIND_INFERENCE: "de" * 32})
        self.assertFalse(ok)
        self.assertIn("不是期望的那一个", detail)

    # ---- 反例 ③：换模型 / 换输入 ----
    def test_other_model_is_rejected(self):
        self.fx.cert.parts[1].outcome["model_hash"] = "00" * 32
        ok, detail, _ = self.fx.verify()
        self.assertFalse(ok)
        self.assertIn("model_hash", detail)

    def test_input_from_another_response_is_rejected(self):
        """换输入向量 = 拿「另一条响应的推理证明」顶包。"""
        self.fx.cert.parts[1].outcome = I.run(HARMFUL, NONCE)
        ok, detail, _ = self.fx.verify()
        self.assertFalse(ok)
        # response_binding 先炸（两半绑的不是同一条 T）—— 这正是该先炸的地方
        self.assertIn("绑的不是同一条送达响应", detail)

    def test_input_binding_alone_is_rejected(self):
        # 只把 input_binding 换成别的（response_binding 保持一致），
        # 必须由「模型与输入」那一步拦下。
        out = dict(I.run(BENIGN, NONCE))
        out["input_binding"] = I.input_binding(NONCE, I.input_from_response(HARMFUL))
        self.fx.cert.parts[1].outcome = out
        ok, detail, _ = self.fx.verify()
        self.assertFalse(ok)
        self.assertIn("input_binding", detail)

    # ---- 反例 ④：两半绑的不是同一条 T ----
    def test_halves_bound_to_different_responses_rejected(self):
        self.fx.cert.parts[0].outcome = _policy_outcome(HARMFUL, NONCE)
        ok, detail, _ = self.fx.verify()
        self.assertFalse(ok)
        self.assertIn("绑的不是同一条送达响应", detail)
        self.assertIn("MISMATCH", detail)     # 两半确实对不上，而不是「来源不足」

    def test_delivered_response_mismatch_rejected(self):
        # 证明没问题，但**送达**的 T′ 不是被证明的那条 —— P0-2 的经典攻击。
        ok, detail, _ = self.fx.verify(response=HARMFUL)
        self.assertFalse(ok)
        self.assertIn("绑的不是同一条送达响应", detail)
        self.assertIn("[response]", detail)   # 重算那一路确实参与了比对

    # ---- 反例 ⑤：形状与域 ----
    def test_missing_half_is_rejected(self):
        cert = C.CompositeCertificate.from_json(self.fx.cert.to_json())
        cert.parts = [cert.part(C.KIND_POLICY)]
        ok, detail, _ = self.fx.verify(cert)
        self.assertFalse(ok)
        self.assertIn("parts 必须恰好是", detail)

    def test_extra_part_is_rejected(self):
        cert = C.CompositeCertificate.from_json(self.fx.cert.to_json())
        cert.parts = cert.parts + [cert.parts[0]]
        ok, detail, _ = self.fx.verify(cert)
        self.assertFalse(ok)
        self.assertIn("parts 必须恰好是", detail)

    def test_private_policy_half_is_rejected(self):
        # 私有模式的 `passed` 覆盖不到语义规则（P2-9 已定为 fail-closed），
        # 组合义务里的「策略合规」因此不接受私有模式那一半。
        self.fx.cert.parts[0].outcome["mode"] = "private"
        ok, detail, _ = self.fx.verify()
        self.assertFalse(ok)
        self.assertIn("公开模式", detail)

    def test_inference_half_with_wrong_mode_is_rejected(self):
        self.fx.cert.parts[1].outcome["mode"] = "public"
        ok, detail, _ = self.fx.verify()
        self.assertFalse(ok)
        self.assertIn("应为 'infer'", detail)

    def test_inference_half_with_wrong_domain_is_rejected(self):
        self.fx.cert.parts[1].outcome["domain"] = "pop-bind-v1"
        ok, detail, _ = self.fx.verify()
        self.assertFalse(ok)
        self.assertIn("domain", detail)

    # ---- 组合义务 ≠ 证书真伪 ----
    def test_violating_policy_half_is_a_real_but_unsatisfied_certificate(self):
        self.fx.cert.parts[0].outcome["passed"] = False
        ok, detail, satisfied = self.fx.verify()
        self.assertTrue(ok, detail)        # 证书仍然是真的
        self.assertFalse(satisfied)        # 但义务不成立
        self.assertIn("passed=false", detail)

    def test_delegated_policy_half_needs_companion(self):
        """``delegated`` 非空 ⇒ 组合层**不下结论**，交给陪伴证明。"""
        self.fx.cert.parts[0].outcome["delegated"] = [{
            "name": "low_harm_probability", "system": "ezkl-halo2",
            "model_vkey": "ab" * 32, "onnx_sha256": "cd" * 32,
            "threshold_bp": 5000, "direction": "le"}]
        ok, detail, satisfied = self.fx.verify()
        self.assertTrue(ok, detail)
        self.assertFalse(satisfied)
        self.assertIn("委托", detail)

    def test_policy_hash_mismatch_rejected(self):
        self.fx.cert.policy_hash = "ff" * 32
        ok, detail, _ = self.fx.verify()
        self.assertFalse(ok)
        self.assertIn("policy_hash", detail)

    def test_policy_pack_recompilation_mismatch_rejected(self):
        ok, detail, _ = self.fx.verify(
            policy_pack=REPO / "policy_packs" / "eu_ai_act_v1.json")
        self.assertFalse(ok)
        self.assertIn("重编译", detail)


class TestCompositeConstruction(unittest.TestCase):
    """``build_composite`` 的拒绝路径（合成垃圾证书必须在**出证方**就被拦住）。"""

    def test_mismatched_bindings_rejected(self):
        pol = C.Part(kind=C.KIND_POLICY, name="p", proof_file="a", proof_sha256="x",
                     vkey_hash="1" * 8, proof_mode="core",
                     outcome=_policy_outcome(BENIGN))
        inf = C.Part(kind=C.KIND_INFERENCE, name="i", proof_file="b", proof_sha256="y",
                     vkey_hash="2" * 8, proof_mode="core",
                     outcome=_infer_outcome(HARMFUL))
        with self.assertRaises(ValueError) as cm:
            C.build_composite(pol, inf, NONCE)
        self.assertIn("response_binding", str(cm.exception))

    def test_private_policy_half_rejected_at_build(self):
        pol = C.Part(kind=C.KIND_POLICY, name="p", proof_file="a", proof_sha256="x",
                     vkey_hash="1" * 8, proof_mode="core",
                     outcome=_policy_outcome(BENIGN, mode="private"))
        inf = C.Part(kind=C.KIND_INFERENCE, name="i", proof_file="b", proof_sha256="y",
                     vkey_hash="2" * 8, proof_mode="core",
                     outcome=_infer_outcome(BENIGN))
        with self.assertRaises(ValueError) as cm:
            C.build_composite(pol, inf, NONCE)
        self.assertIn("公开模式", str(cm.exception))

    def test_roundtrip_json(self):
        fx_tmp = tempfile.TemporaryDirectory()
        try:
            fx = _Fixture(Path(fx_tmp.name))
            back = C.CompositeCertificate.from_json(fx.cert.to_json())
            self.assertEqual(back.response_binding, fx.cert.response_binding)
            self.assertEqual(back.nonce, NONCE)
            self.assertEqual(sorted(p.kind for p in back.parts),
                             sorted(C.KINDS))
        finally:
            fx_tmp.cleanup()


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestDomainSeparationInGuest(unittest.TestCase):
    """两个 guest 各只收自己那一半任务（键分离的落地形式）。"""

    def _run(self, job: str, vectors: dict):
        with tempfile.TemporaryDirectory() as tmp:
            vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
            vp.write_text(json.dumps(vectors))
            return subprocess.run(
                [str(POP_SCRIPT), "--check", "--job", job,
                 "--vectors", str(vp), "--out", str(op)],
                cwd=str(REPO), capture_output=True, text=True)

    def test_policy_vectors_rejected_by_infer_job(self):
        """把策略向量喂给推理域必须**报错**（deny_unknown_fields 挡住自填输入）。"""
        proc = self._run("infer", {"vectors": [{
            "name": "t", "response": BENIGN, "spec_canonical": "{}"}]})
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unknown field", proc.stderr)

    def test_infer_vectors_rejected_by_policy_job(self):
        proc = self._run("policy", {"vectors": [{
            "name": "t", "response": BENIGN}]})
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("spec_canonical", proc.stderr)

    def test_unknown_job_name_rejected(self):
        proc = self._run("inferrence", {"vectors": []})
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--job must be", proc.stderr)


class TestDriverWiring(unittest.TestCase):
    """驱动层的接线 —— 两处只有**真出证明**时才暴露的错。

    这里的两条都是 2026-09-12 那次真端到端跑出来的：单测与
    ``verify_proofs=False`` 的绑定层全绿，但驱动一跑就炸。记在这里防止复发。
    """

    def test_job_flag_is_not_the_kind(self):
        """part 的 kind 是 ``inference``，``pop-script --job`` 要的是 ``infer``。

        这两个名字**不同**，直接把 kind 当旗标传会被 pop-script 拒绝
        （`--job must be 'policy' or 'infer'`）。MAPPING 是唯一的转换点。
        """
        self.assertEqual(C.JOB_FOR_KIND[C.KIND_POLICY], "policy")
        self.assertEqual(C.JOB_FOR_KIND[C.KIND_INFERENCE], "infer")
        self.assertNotEqual(C.JOB_FOR_KIND[C.KIND_INFERENCE], C.KIND_INFERENCE)
        self.assertEqual(set(C.JOB_FOR_KIND), set(C.KINDS))

    def test_part_from_proof_passes_the_job_flag(self):
        """``part_from_proof`` 必须把 job 旗标（而非 kind）交给验证器。"""
        seen = []
        orig = C._verify_one

        def fake(proof, job_kind, pop_verify=None, pop_script=None):
            seen.append(job_kind)
            kind = C.KIND_INFERENCE if job_kind == "infer" else C.KIND_POLICY
            return {"verified": True, "vkey_hash": "ab" * 32,
                    "proof_mode": "core", "outcome": _outcome_for(kind)}

        C._verify_one = fake
        try:
            with tempfile.TemporaryDirectory() as tmp:
                p = Path(tmp) / "x.proof"
                p.write_bytes(b"bytes")
                C.part_from_proof(p, C.KIND_POLICY, "p")
                C.part_from_proof(p, C.KIND_INFERENCE, "i")
        finally:
            C._verify_one = orig
        self.assertEqual(seen, ["policy", "infer"])

    def test_verified_outcome_keeps_mode(self):
        """``mode`` 是组合层的载荷字段，**不能**当展示元信息剥掉。

        ``verifier.outcome_without_meta`` 会连 ``mode`` 一起剥 —— 那在证书载荷里
        是对的（运行模式已在载荷顶层），但组合层的域绑定检查正是读它，
        剥了就会永远读到 ``None``（``build_composite`` 于是恒抛错）。
        """
        raw = {"outcome": {"name": "n", "mode": "infer", "output": [1, 2]}}
        self.assertEqual(C._outcome_of(raw), {"mode": "infer", "output": [1, 2]})
        self.assertEqual(C._outcome_of({}), None)
        self.assertEqual(C._outcome_of({"outcome": []}), None)
        # 与 V.outcome_without_meta 的分歧点，显式钉住
        self.assertNotIn("mode", V.outcome_without_meta(raw) or {})

    def test_verify_one_passes_an_explicit_out_path(self):
        """验证一份证明时**必须显式给 `--out`**。

        `pop-script` 的 `--out` 默认落在**当前工作目录**的 `results.json`，而
        命令的 cwd 是仓库根 —— 漏给就会在仓库根写一个 `results.json`，
        混进 `git status` 像个待提交的新文件（2026-09-12 审计发现，
        `verify_cert.py` / `verify_session.py` 都给，只有这里漏）。

        P2-10 起这条路径的实现挪到了 `verifier.verify_proof_file`（会话层要复用
        同一条路），所以拦的是**那个**函数的执行缝；断言不变。
        """
        seen = []

        def fake_run(cmd, env_extra=None):
            seen.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout='{"verified": true}', stderr="")

        orig = V.run_cmd
        V.run_cmd = fake_run
        try:
            with tempfile.TemporaryDirectory() as tmp:
                p = Path(tmp) / "x.proof"
                p.write_bytes(b"bytes")
                C._verify_one(p, "policy", pop_verify=Path(tmp) / "no-such-pop-verify")
        finally:
            V.run_cmd = orig
        self.assertEqual(len(seen), 1)
        argv = seen[0]
        self.assertIn("--out", argv)
        out = Path(argv[argv.index("--out") + 1])
        self.assertNotEqual(out.name, "results.json",
                            "别把 verify 的输出写回仓库根（pop-script 的默认名）")
        self.assertFalse(str(out).startswith(str(REPO)),
                         f"--out 不该落在仓库里：{out}")


# --------------------------------------------------------------------------- #
# 3. 真·端到端（门控）
# --------------------------------------------------------------------------- #

@unittest.skipUnless(RUN_COMPOSE, "set POP_TEST_COMPOSE=1 to run the real composite proof")
class TestCompositeEndToEnd(unittest.TestCase):
    """真出两份证明 → 合成 → 独立验证 → 换任一子证明必须被拒。"""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls._tmp.name) / "compose"
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "compose_proof.py"),
             "--pack", str(REPO / "policy_packs" / "eu_ai_act_v1.json"),
             "--response", str(REPO / "scripts" / "examples" / "eu_agent_reply.txt"),
             "--out-dir", str(cls.out)],
            cwd=str(REPO), capture_output=True, text=True,
            env=dict(os.environ, SP1_PROVER="cpu"))
        cls.proc = proc
        if proc.returncode != 0:
            raise AssertionError(f"compose_proof.py failed:\n{proc.stdout}\n{proc.stderr}")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        self.cert = C.read_composite(self.out / "composite.json")
        self.response = (REPO / "scripts" / "examples" / "eu_agent_reply.txt"
                         ).read_text(encoding="utf-8")

    def test_driver_reports_pass(self):
        self.assertIn("RESULT: PASS", self.proc.stdout)
        self.assertIn("组合义务(Compose): PASS", self.proc.stdout)

    def test_composite_verifies_with_crypto(self):
        ok, detail, satisfied = C.verify_composite(
            self.cert, response=self.response, base=self.out,
            policy_pack=REPO / "policy_packs" / "eu_ai_act_v1.json")
        self.assertTrue(ok, detail)
        self.assertTrue(satisfied, detail)

    def test_vkeys_really_differ(self):
        pol = self.cert.part(C.KIND_POLICY)
        inf = self.cert.part(C.KIND_INFERENCE)
        self.assertNotEqual(pol.vkey_hash, inf.vkey_hash)

    def test_swapping_either_subproof_is_rejected(self):
        """**验收反例**：替换任一子证明必须被拒（真产物上再跑一遍）。"""
        for name in ("policy.proof", "inference.proof"):
            f = self.out / name
            original = f.read_bytes()
            try:
                f.write_bytes(b"substituted")
                ok, detail, _ = C.verify_composite(self.cert, response=self.response,
                                                   base=self.out)
                self.assertFalse(ok, f"{name} 被换掉后竟然还通过")
                self.assertIn("证明文件哈希不符", detail)
            finally:
                f.write_bytes(original)
        # 还原后必须重新通过 —— 证明上面那次失败是**因为换文件**，不是因为别的
        ok, detail, _ = C.verify_composite(self.cert, response=self.response, base=self.out)
        self.assertTrue(ok, detail)

    def test_wrong_response_is_rejected(self):
        """**验收反例**：换一条**别的**响应 T′，组合义务必须不成立。

        注意断言的是**组合层自己**的措辞。组合层不调用
        ``verifier.check_response_binding`` 的那层包装，而是自己跑四方比对
        （composite / policy / inference / 由 T′ 现场重算），所以失败信息里
        带的是四方 MISMATCH，而不是证书层那句「由送达的响应 T′ 与 nonce 现场重算的」。
        2026-09-12 的真跑才发现这里原本断言错了层 —— 改断组合层的实际输出。
        """
        ok, detail, _ = C.verify_composite(self.cert, response=HARMFUL, base=self.out)
        self.assertFalse(ok)
        self.assertIn("不是同一条送达响应", detail)
        # 四方里必须是「响应那一路」与其余三方对不上，而不是别的哪一路
        self.assertIn("[response]", detail)
        self.assertIn("[composite]", detail)


if __name__ == "__main__":
    unittest.main()
