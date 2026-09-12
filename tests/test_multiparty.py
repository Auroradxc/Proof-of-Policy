"""P2-11 多证明者的验收：三个角色各证一段，缺谁都不成立。

## 三层（与 ``test_compose`` / ``test_session`` 同构）

1. **切片划分层**（不需要证明）：``shard`` 把整条策略按规则类切成三个角色的切片，
   互斥且并集为整条策略；未知规则类、重名规则一律 fail closed。
2. **绑定/签名层**（手工构造的「证明」）：``verify_multiparty`` 对着**伪造的**
   证明文件跑全部反例 —— 缺角色签名、两角色共用一把键、某一段切片被换、
   换证明文件、换一条 T、三段绑不同的轨迹。这些都不需要真证明就能测：被拦下的
   那一刻发生在「签名载荷比对」「切片现场重算」「response_binding 比对」这几步。
3. **真·端到端**（``POP_TEST_MULTIPARTY=1`` 才跑）：真出两份切片证明（模型方 +
   工具网关，各约 2 分钟）→ 独立验证 → 换掉网关那份证明必须被拒。

## 验收判据（计划 §P2-11）

「缺任一角色签名 → 拒绝；单角色策略切片被换 → 拒绝」。两条都在第 2 层，且第二条
有**三条互相独立**的拦截线：

* 切片被换 ⇒ part 自述的 ``rules``/``slice_sha256`` 与 ``plan`` 对不上；
* 换完还想自圆其说就得改 ``plan`` ⇒ 其余两个角色的签名载荷（含 ``plan_digest``）
  立刻不符 —— 这正是「多证明者」三个字买到的性质；
* 三个角色**串通**一起改（各自用真键重签）⇒ 出证侧与验证侧的「现场重算」拦不住，
  只有**策略包重编译**拦得住。``test_colluding_roles_rewritten_plan_needs_the_pack``
  是这一层最该存在的用例：它把「不给策略包就只能核自洽」这句话钉成事实。
"""

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
import sys  # noqa: E402
sys.path.insert(0, str(REPO))

from policydsl import cert as C  # noqa: E402
from policydsl import keys  # noqa: E402
from policydsl import multiparty as M  # noqa: E402
from policydsl.commit import response_binding  # noqa: E402
from policydsl.compile import compile_policy, compile_slice_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402

#: 真·端到端要真出证（两份切片证明，各约 2 分钟、峰值 ~10 GB），默认关闭。
RUN_E2E = os.environ.get("POP_TEST_MULTIPARTY") == "1"

NONCE = bytes.fromhex("00112233445566778899aabbccddeeff")
RESPONSE = "Sure, here is the summary you asked for."

#: 伪造证明的 vkey（第 2 层不核密码学，只核声明与边车自报的一致性）。
VKEY = "c0ffee" + "0" * 58

#: 主策略：模型方两段（关键词 + 长度）、网关两段（工具参数 + 预算）、部署方空。
POLICY = Policy("eu-ai-act-mp", "0.1.0", "多证明者 demo",
                rules=[Rule("keyword_block", "no_bad_topics",
                            {"keywords": ["weaponize", "doxxing"]}),
                       Rule("length_bound", "bounded_reply", {"min": 1, "max": 2000}),
                       Rule("tool_arg_guard", "no_secret_args",
                            {"forbidden_fields": ["api_key"]}),
                       Rule("budget_bound", "call_budget",
                            {"budget": 3, "unit": "calls"})])

#: 含语义规则的策略：部署方那段不空（``delegated`` 非空的那条路径）。
SEM_POLICY = Policy("semantic-demo-v1", "0.1.0",
                    rules=[Rule("keyword_block", "no_bad_topics",
                                {"keywords": ["weaponize"]}),
                           Rule("length_bound", "bounded_reply", {"min": 1, "max": 64}),
                           Rule("semantic_bound", "low_harm_probability",
                                {"threshold_bp": 5000, "direction": "le"})])


def _outcome(slice_sha: str, nonce: bytes, response: str, *,
             passed: bool = True, delegated=(), trace_root: str = "genesis",
             mode: str = "public") -> dict:
    """手工构造一份切片证明的公开值（形状与 ``pop_types::outcome_value`` 相同）。"""
    return {
        "mode": mode,
        "policy_hash": slice_sha,
        "response_binding": response_binding(nonce, response),
        "trace_root": trace_root,
        "passed": passed,
        "violations": [],
        "delegated": list(delegated),
    }


class _Fixture:
    """一张可改的多证明者证书：三份伪造证明文件 + 三个角色的键。"""

    def __init__(self, tmp: Path, *, policy: Policy = POLICY,
                 response: str = RESPONSE, nonce: bytes = NONCE,
                 vkey: str = VKEY) -> None:
        self.tmp = Path(tmp)
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.policy = policy
        self.response = response
        self.nonce = nonce
        self.vkey = vkey
        self.specs = M.slice_specs(policy)
        # 部署方那段的公开值里带着「被委托出去」的约束（形状与
        # pop_types::DelegatedConstraint 相同）。绑定层不核这些字段的内容 ——
        # 那是 ezkl 陪伴证明的事（见 policydsl/semantic.py 的 verify_companion），
        # 这里只核「非空 ⇒ 不替它下合规结论」这条口径。
        self._delegated = [
            {"name": r.name, "system": "ezkl-halo2", "model_vkey": "v" * 64,
             "onnx_sha256": "o" * 64, "threshold_bp": int(r.params["threshold_bp"]),
             "direction": r.params["direction"]}
            for r in policy.rules if r.kind == "semantic_bound"]
        self.signers = {r: keys.ephemeral_signer() for r in M.ROLES}
        self.keyring = C.keyring(*(s.public_key for s in self.signers.values()))

        parts = []
        for role in M.ROLES:
            spec = self.specs[role]
            if not M.slice_rules(spec):
                parts.append(M.empty_part(role, spec))
                continue
            proof = self.tmp / f"{role}.proof"
            proof.write_bytes(f"proof-bytes-for-{role}".encode())
            # 边车：verify_proofs=False 时只读它自报的 vkey（不是密码学绑定）
            Path(f"{proof}.meta.json").write_text(
                json.dumps({"vkey_hash": vkey}), encoding="utf-8")
            parts.append(M.SlicePart(
                role=role, rules=M.slice_rules(spec), slice_sha256=spec["sha256"],
                proof_file=proof.name, proof_sha256=M.sha256_file(proof),
                vkey_hash=vkey, proof_mode="core",
                outcome=_outcome(spec["sha256"], nonce, response,
                                 delegated=self._delegated if role == M.ROLE_DEPLOYER
                                 else ())))
        self.cert = M.assemble(policy, parts, signers=self.signers, nonce=nonce)

    # ---- 反例构造的小工具（都在第 2 层，不需要真证明） ----
    def part(self, role: str):
        return next(p for p in self.cert.parts if p.role == role)

    def resign(self, part, signer=None):
        """用该角色的**真键**重新签一份被改过的 part（模拟「角色自己耍赖」）。

        共同上下文（整条策略哈希 / 那条 T / plan 摘要）沿用原证书的：这正是
        最有利的攻击者视角 —— 他有权改自己那一段，但没有别的角色的键。
        """
        honest = self.part(part.role)
        part.policy_hash = honest.policy_hash
        part.response_binding = honest.response_binding
        part.plan_digest = honest.plan_digest
        return M.sign_part(part, signer or self.signers[part.role])

    def cert_with(self, *parts):
        """换掉若干 part 后的证书副本（其余照旧）。"""
        cert = copy.deepcopy(self.cert)
        by_role = {p.role: p for p in parts}
        cert.parts = [by_role.get(p.role, p) for p in cert.parts]
        return cert

    def verify(self, cert=None, *, response=None, keyring=..., policy=..., **kw):
        return M.verify_multiparty(
            cert if cert is not None else self.cert,
            response=self.response if response is None else response,
            base=self.tmp,
            keyring=self.keyring if keyring is ... else keyring,
            policy=self.policy if policy is ... else policy,
            verify_proofs=False, **kw)

    def failure(self, cert=None, **kw):
        """断言验证失败并返回诊断串（反例用例的统一写法）。

        夹具不是 TestCase，所以这里用裸 assert —— 反例失败时必须**响亮**
        （断言消息里带上诊断串，否则「本该被拒却通过了」只能靠猜）。
        """
        ok, detail, satisfied = self.verify(cert, **kw)
        assert not ok, f"本该被拒，却通过了：{detail}"
        return detail


# --------------------------------------------------------------------------- #
# 1. 切片划分层（不需要证明）
# --------------------------------------------------------------------------- #

class TestSlicePartition(unittest.TestCase):
    """切片怎么分：互斥、并集为整条策略、未知类不猜。"""

    def test_all_eight_kinds_have_exactly_one_owner(self):
        self.assertEqual(len(M.KIND_OWNER), 8, "规则类总数（7 入电路 + 1 委托）")
        flat = [k for role in M.ROLES for k in M.KINDS_BY_ROLE[role]]
        self.assertEqual(sorted(flat), sorted(M.KIND_OWNER),
                         "每个规则类必须恰有一个归属角色（既不漏也不重）")

    def test_slices_are_disjoint_and_cover_the_whole_policy(self):
        names = [r.name for r in POLICY.rules]
        got = [n for role in M.ROLES for n in M.plan_of(POLICY)[role]["rules"]]
        self.assertEqual(sorted(got), sorted(names))
        self.assertEqual(len(got), len(set(got)), "切片必须互斥")

    def test_role_assignment_is_by_evidence_holder(self):
        plan = M.plan_of(POLICY)
        self.assertEqual(plan[M.ROLE_MODEL]["rules"], ["no_bad_topics", "bounded_reply"])
        self.assertEqual(plan[M.ROLE_GATEWAY]["rules"], ["no_secret_args", "call_budget"])
        self.assertEqual(plan[M.ROLE_DEPLOYER]["rules"], [], "本策略没有语义规则")

    def test_all_three_roles_always_exist(self):
        """没有自己那类规则的角色的切片是**空切片**，但角色本身必须在。"""
        self.assertEqual(sorted(M.plan_of(POLICY)), sorted(M.ROLES))
        self.assertEqual(sorted(M.shard(POLICY)), sorted(M.ROLES))

    def test_semantic_rule_goes_to_the_deployer(self):
        plan = M.plan_of(SEM_POLICY)
        self.assertEqual(plan[M.ROLE_DEPLOYER]["rules"], ["low_harm_probability"])
        self.assertEqual(plan[M.ROLE_GATEWAY]["rules"], [])

    def test_unknown_rule_kind_is_rejected(self):
        """未知规则类不猜归属：静默落到「没人证」的位置正是本层要消灭的形态。

        两层防护：``Rule.validate`` 先拒一次（拼错的类名进不了任何地方），
        ``role_of_kind`` 再拒一次 —— 后者挡的是**另一件事**：有人往
        ``model.py``/``compile.py`` 里加了一类规则、却忘了在这里指定归属。
        那时 ``validate`` 会放行，只有 ``role_of_kind`` 拦得住。
        """
        with self.assertRaises(M.MultipartyError) as cm:
            M.role_of_kind("brand_new_kind")
        self.assertIn("未知规则类", str(cm.exception))
        with self.assertRaises(Exception):        # model.Rule.validate
            M.plan_of(Policy("p", "1", rules=[Rule("brand_new_kind", "x", {})]))

    def test_duplicate_rule_names_are_rejected(self):
        """plan 用规则名标识「谁证了哪一段」，重名会让这句话产生歧义。"""
        p = Policy("p", "1", rules=[Rule("keyword_block", "same", {"keywords": ["a"]}),
                                    Rule("budget_bound", "same", {"budget": 1})])
        with self.assertRaises(M.MultipartyError) as cm:
            M.shard(p)
        self.assertIn("唯一", str(cm.exception))

    def test_covering_length_bound_is_checked_on_the_whole_policy(self):
        """定长前提在**整条策略**上检查：切片本身不重复检查（否则语义策略无法分片）。"""
        bad = Policy("p", "1", rules=[Rule("semantic_bound", "sem",
                                           {"threshold_bp": 5000, "direction": "le"})])
        with self.assertRaises(Exception) as cm:
            M.shard(bad)
        self.assertIn("length_bound", str(cm.exception))
        # 同一批规则**加上** length_bound 就可以分片了：定长前提由模型方那段提供，
        # 部署方那段只有语义规则，编译它**不会**因为缺 length_bound 而失败。
        ok = Policy("p", "1", rules=[Rule("length_bound", "len", {"min": 1, "max": 64}),
                                     Rule("semantic_bound", "sem",
                                          {"threshold_bp": 5000, "direction": "le"})])
        plan = M.plan_of(ok)
        self.assertEqual(plan[M.ROLE_DEPLOYER]["rules"], ["sem"])

    def test_slices_are_compiled_by_the_same_compiler(self):
        """切片编译与整条策略编译走**同一份**规则映射（不存在第二份编译器）。"""
        sub = M.shard(POLICY)[M.ROLE_GATEWAY]
        self.assertEqual(compile_slice_policy(sub), compile_policy(sub),
                         "不涉及语义规则时，两条路必须逐字节相同")

    def test_plan_is_deterministic_and_content_addressed(self):
        self.assertEqual(M.plan_of(POLICY), M.plan_of(POLICY))
        self.assertEqual(M.plan_digest(M.plan_of(POLICY)),
                         M.plan_digest(M.plan_of(POLICY)))
        changed = Policy(POLICY.id, POLICY.version, POLICY.description,
                         [Rule("keyword_block", "no_bad_topics", {"keywords": ["other"]})]
                         + POLICY.rules[1:], POLICY.semantic)
        plan, other = M.plan_of(POLICY), M.plan_of(changed)
        self.assertNotEqual(plan[M.ROLE_MODEL]["slice_sha256"],
                            other[M.ROLE_MODEL]["slice_sha256"])
        self.assertNotEqual(M.plan_digest(plan), M.plan_digest(other))
        # 网关那段没变，哈希就不该变（切片是内容寻址的，不是整条策略的投影）
        self.assertEqual(plan[M.ROLE_GATEWAY]["slice_sha256"],
                         other[M.ROLE_GATEWAY]["slice_sha256"])


# --------------------------------------------------------------------------- #
# 2. 绑定/签名层（手工构造的「证明」）
# --------------------------------------------------------------------------- #

class TestMultipartyBinding(unittest.TestCase):
    """正例一条 + 各类反例；全部不需要真证明。"""

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
        self.assertIn("三份签名均通过验证", detail)
        self.assertIn("现场重编译相符", detail)

    def test_proofs_marked_unverified_when_skipped(self):
        """跳过密码学验证时必须**如实注明**，不能让报告读起来像跑全了。"""
        ok, detail, _ = self.fx.verify()
        self.assertTrue(ok, detail)
        self.assertIn("证明有效性未核", detail)

    def test_missing_policy_pack_is_noted(self):
        """不给策略包：仍可核自洽，但必须注明「不能核整条策略就是你手上那个包」。"""
        ok, detail, _ = self.fx.verify(policy=None)
        self.assertTrue(ok, detail)
        self.assertIn("未提供策略包", detail)

    def test_semantic_slice_is_real_but_needs_companion(self):
        """部署方那段把 semantic_bound 委托出去：证书为真，但**不构成合规**。"""
        fx = _Fixture(Path(self._tmpdir.name) / "sem", policy=SEM_POLICY)
        ok, detail, satisfied = fx.verify()
        self.assertTrue(ok, detail)
        self.assertFalse(satisfied, "delegated 非空时不能替陪伴证明下结论")
        self.assertIn("委托", detail)

    def test_roundtrip_json(self):
        back = M.MultipartyCertificate.from_json(
            json.loads(json.dumps(self.fx.cert.to_json(), ensure_ascii=False)))
        ok, detail, satisfied = self.fx.verify(back)
        self.assertTrue(ok, detail)
        self.assertTrue(satisfied, detail)

    def test_plan_digest_is_bound_into_every_signature(self):
        for p in self.fx.cert.parts:
            self.assertEqual(p.plan_digest, self.fx.cert.to_json()["plan_digest"])
            self.assertIn("plan_digest", p.claim())

    # ---- 验收判据 ①：缺任一角色签名 → 拒绝 ----
    def test_missing_role_signature_is_rejected(self):
        for role in M.ROLES:
            with self.subTest(role=role):
                cert = copy.deepcopy(self.fx.cert)
                next(p for p in cert.parts if p.role == role).envelope = {}
                detail = self.fx.failure(cert)
                self.assertIn("没有签名", detail)

    def test_empty_signature_list_is_rejected(self):
        cert = copy.deepcopy(self.fx.cert)
        self.fx.part("gateway").role  # 仅确认角色名
        next(p for p in cert.parts if p.role == "gateway").envelope = {
            "payloadType": "application/vnd.pop+json", "payload": "e30=",
            "signatures": []}
        self.assertIn("没有签名", self.fx.failure(cert))

    def test_missing_role_part_is_rejected(self):
        cert = copy.deepcopy(self.fx.cert)
        cert.parts = [p for p in cert.parts if p.role != M.ROLE_GATEWAY]
        detail = self.fx.failure(cert)
        self.assertIn("三个角色各一份", detail)

    def test_duplicated_role_part_is_rejected(self):
        cert = copy.deepcopy(self.fx.cert)
        cert.parts.append(copy.deepcopy(self.fx.part(M.ROLE_MODEL)))
        self.assertIn("三个角色各一份", self.fx.failure(cert))

    def test_two_roles_sharing_one_key_is_rejected(self):
        """同一个键签两个角色：签名本身在 keyring 里**验得过**，靠键分离单独拦住。

        这一条刻意做到「除了键分离，别的检查都会过」—— 否则测的就不是键分离。
        网关那一段的内容照旧，只是改用**模型方那把键**来签：两个角色的 keyid
        因此相同，而「谁证的」无从判断。
        """
        gw = copy.deepcopy(self.fx.part("gateway"))
        gw.envelope = C.sign_payload(gw.claim(), self.fx.signers["model"])
        detail = self.fx.failure(self.fx.cert_with(gw))
        self.assertIn("键分离", detail)

    # ---- 验收判据 ②：单角色策略切片被换 → 拒绝 ----
    def test_swapped_slice_without_rekeying_is_rejected(self):
        """无钥攻击者改了某一段（rules/哈希），签名当场不符。"""
        cert = copy.deepcopy(self.fx.cert)
        p = next(p for p in cert.parts if p.role == "model")
        p.rules = ["no_secret_args", "call_budget"]
        p.slice_sha256 = self.fx.specs["gateway"]["sha256"]
        self.assertIn("签名覆盖的载荷与 part 的字段", self.fx.failure(cert))

    def test_swapped_slice_by_the_role_itself_is_rejected(self):
        """角色用**自己的真键**把自己那一段换成另一段 —— 三条拦截线里至少中一条。"""
        spec = self.fx.specs["gateway"]
        cheat = M.SlicePart(role="model", rules=M.slice_rules(spec),
                            slice_sha256=spec["sha256"], proof_file="gateway.proof",
                            proof_sha256=self.fx.part("gateway").proof_sha256,
                            vkey_hash=self.fx.vkey, proof_mode="core",
                            outcome=_outcome(spec["sha256"], NONCE, RESPONSE))
        self.fx.resign(cheat)
        detail = self.fx.failure(self.fx.cert_with(cheat))
        self.assertTrue("现场重算" in detail or "plan 不一致" in detail, detail)

    def test_role_declaring_its_slice_empty_is_rejected(self):
        """角色声称「我没有要证的规则」—— plan 里那段明明有规则。"""
        cheat = M.empty_part("model", self.fx.specs["model"])
        self.fx.resign(cheat)
        self.assertIn("plan 不一致", self.fx.failure(self.fx.cert_with(cheat)))

    def test_rewriting_the_plan_alone_breaks_the_other_signatures(self):
        """改了 plan 就得让另外两个角色也重签 —— 一方的键改不动三方的签名。"""
        cert = copy.deepcopy(self.fx.cert)
        cert.plan["model"] = {"rules": [], "slice_sha256": self.fx.specs["model"]["sha256"]}
        detail = self.fx.failure(cert)
        # 改动一方拦不住另两方的签名：part 自述与 plan 当场对不上（三方都重签才
        # 能自洽，而那需要三把键 —— 见下一条「串通」用例）。
        self.assertIn("plan 不一致", detail)

    def test_tampered_plan_digest_is_rejected(self):
        """改 plan 摘要但不动 plan：两头对不上（摘要字段本身也是被签名的）。"""
        cert = copy.deepcopy(self.fx.cert)
        cert.plan_digest = "ab" * 32
        detail = self.fx.failure(cert)
        self.assertIn("plan 摘要", detail)

    def test_colluding_roles_rewritten_plan_needs_the_pack(self):
        """**三个角色串通**各自重签一份改过的划分：只有策略包重编译拦得住。

        这是本层最该存在的用例 —— 它把「不给策略包就只能核自洽」钉成事实：
        串通后的证书**自洽得完美**（摘要、签名、切片哈希全都对得上），
        现场重算用的是验证方自己的切分，所以只有 `policy=` / `policy_pack=`
        这一条路能拆穿它。
        """
        cert = copy.deepcopy(self.fx.cert)
        # 串通：把模型方那段的规则整体藏起来（声称它那一段是空的 —— 而「空切片」
        # 的规范哈希是公开可算的，所以这个声明自洽得挑不出毛病）
        empty_spec = M.slice_specs(POLICY)[M.ROLE_DEPLOYER]
        cert.plan["model"] = {"rules": [], "slice_sha256": empty_spec["sha256"]}
        cert.plan_digest = M.plan_digest(cert.plan)
        for p in cert.parts:
            p.plan_digest = cert.plan_digest
            if p.role == "model":
                p.rules, p.slice_sha256 = [], empty_spec["sha256"]
                p.proof_file, p.proof_sha256, p.outcome = None, None, {}
            M.sign_part(p, self.fx.signers[p.role])
        # 不给策略包：自洽 ⇒ 通过（**这是本模块如实标注的能力边界**）
        ok, detail, _ = self.fx.verify(cert, policy=None)
        self.assertTrue(ok, f"串通后的自洽证书在无策略包时应当通过：{detail}")
        self.assertIn("未提供策略包", detail)
        # 给了策略包：现场重算立刻拆穿
        ok, detail, _ = self.fx.verify(cert, policy=POLICY)
        self.assertFalse(ok)
        self.assertIn("现场重算不符", detail)

    # ---- 其余反例 ----
    def test_swapping_a_proof_file_is_rejected(self):
        cert = copy.deepcopy(self.fx.cert)
        Path(self.fx.tmp / "gateway.proof").write_bytes(b"another-proof-entirely")
        detail = self.fx.failure(cert)
        self.assertIn("哈希不符", detail)

    def test_proof_from_another_slice_is_rejected(self):
        """证明承诺的 policy_hash 必须是**这一段**的（拿别段的证明来冒充）。"""
        p = copy.deepcopy(self.fx.part("model"))
        p.outcome = dict(p.outcome, policy_hash=self.fx.specs["gateway"]["sha256"])
        self.fx.resign(p)
        detail = self.fx.failure(self.fx.cert_with(p))
        self.assertIn("不是这一段切片", detail)

    def test_empty_slice_carrying_a_proof_is_rejected(self):
        cert = copy.deepcopy(self.fx.cert)
        p = next(p for p in cert.parts if p.role == "deployer")
        p.proof_file = "model.proof"
        p.proof_sha256 = self.fx.part("model").proof_sha256
        p.outcome = dict(self.fx.part("model").outcome)
        detail = self.fx.failure(cert)
        self.assertTrue("空切片" in detail or "签名覆盖" in detail, detail)

    def test_nonempty_slice_without_a_proof_is_rejected(self):
        p = copy.deepcopy(self.fx.part("gateway"))
        p.proof_file, p.proof_sha256, p.outcome = None, None, {}
        self.fx.resign(p)
        self.assertIn("没有证明文件", self.fx.failure(self.fx.cert_with(p)))

    def test_non_public_mode_is_rejected(self):
        p = copy.deepcopy(self.fx.part("model"))
        p.outcome = dict(p.outcome, mode="private")
        self.fx.resign(p)
        self.assertIn("'public'", self.fx.failure(self.fx.cert_with(p)))

    def test_mixed_vkeys_are_rejected(self):
        """三段必须由**同一个**程序判定，否则「切片」只是名字上的。"""
        p = copy.deepcopy(self.fx.part("gateway"))
        p.vkey_hash = "beef" + "0" * 60
        Path(f"{self.fx.tmp / 'gateway.proof'}.meta.json").write_text(
            json.dumps({"vkey_hash": p.vkey_hash}), encoding="utf-8")
        self.fx.resign(p)
        detail = self.fx.failure(self.fx.cert_with(p))
        self.assertIn("同一个程序", detail)

    def test_unexpected_vkey_is_rejected(self):
        ok, detail, _ = self.fx.verify(expected_vkey="beef" + "0" * 60)
        self.assertFalse(ok)
        self.assertIn("不是期望的那一个", detail)
        ok, detail, _ = self.fx.verify(expected_vkey=VKEY)
        self.assertTrue(ok, detail)

    def test_delivering_another_response_is_rejected(self):
        detail = self.fx.failure(response="A completely different reply.")
        self.assertIn("同一条送达响应", detail)

    def test_slices_bound_to_different_responses_are_rejected(self):
        p = copy.deepcopy(self.fx.part("gateway"))
        p.outcome = _outcome(p.slice_sha256, NONCE, "another reply")
        self.fx.resign(p)
        cert = self.fx.cert_with(p)
        cert.response_binding = self.fx.part("model").response_binding
        detail = self.fx.failure(cert)
        self.assertIn("不是同一条送达响应", detail)

    def test_different_trace_roots_are_rejected(self):
        p = copy.deepcopy(self.fx.part("gateway"))
        p.outcome = dict(p.outcome, trace_root="deadbeef")
        self.fx.resign(p)
        self.assertIn("同一条轨迹", self.fx.failure(self.fx.cert_with(p)))

    def test_violating_slice_is_a_real_but_unsatisfied_certificate(self):
        """如实记录违规的证书同样是**真**证书：ok 与 satisfied 必须分开读。"""
        p = copy.deepcopy(self.fx.part("model"))
        p.outcome = dict(p.outcome, passed=False)
        self.fx.resign(p)
        ok, detail, satisfied = self.fx.verify(self.fx.cert_with(p))
        self.assertTrue(ok, detail)
        self.assertFalse(satisfied)
        self.assertIn("passed=false", detail)


class TestMultipartyConstruction(unittest.TestCase):
    """出证侧的 fail-closed（`assemble` / `build_multiparty`）。"""

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.fx = _Fixture(self.tmp)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_missing_role_key_is_rejected(self):
        signers = {r: s for r, s in self.fx.signers.items() if r != M.ROLE_DEPLOYER}
        with self.assertRaises(M.MultipartyError) as cm:
            M.assemble(POLICY, copy.deepcopy(self.fx.cert.parts),
                       signers=signers, nonce=NONCE)
        self.assertIn("缺角色的键", str(cm.exception))

    def test_one_key_for_two_roles_is_rejected(self):
        signers = dict(self.fx.signers)
        signers["gateway"] = signers["model"]
        with self.assertRaises(M.MultipartyError) as cm:
            M.assemble(POLICY, copy.deepcopy(self.fx.cert.parts),
                       signers=signers, nonce=NONCE)
        self.assertIn("键分离失败", str(cm.exception))

    def test_empty_policy_cannot_certify(self):
        """空策略（没有任何规则）恒通过 —— 正是 P0-1 的形态，不给出证。"""
        empty = Policy("empty", "1", rules=[])
        parts = [M.empty_part(r, s) for r, s in M.slice_specs(empty).items()]
        with self.assertRaises(M.MultipartyError) as cm:
            M.assemble(empty, parts, signers=self.fx.signers, nonce=NONCE)
        self.assertIn("没有证明任何东西", str(cm.exception))

    def test_missing_proof_is_rejected_at_build(self):
        with self.assertRaises(M.MultipartyError) as cm:
            M.build_multiparty(POLICY, RESPONSE, signers=self.fx.signers, nonce=NONCE)
        self.assertIn("没有证明文件", str(cm.exception))

    def test_part_not_matching_the_policy_is_rejected_at_build(self):
        parts = copy.deepcopy(self.fx.cert.parts)
        next(p for p in parts if p.role == "model").rules = []
        with self.assertRaises(M.MultipartyError) as cm:
            M.assemble(POLICY, parts, signers=self.fx.signers, nonce=NONCE)
        self.assertIn("与现场切分不符", str(cm.exception))


# --------------------------------------------------------------------------- #
# 3. 真·端到端（默认关闭；POP_TEST_MULTIPARTY=1 才跑）
# --------------------------------------------------------------------------- #

@unittest.skipUnless(RUN_E2E, "设 POP_TEST_MULTIPARTY=1 才跑真证明（两份，各约 2 分钟）")
class TestMultipartyEndToEnd(unittest.TestCase):
    """真出两份切片证明（模型方 + 工具网关）→ 独立验证 → 换证明必须被拒。"""

    def test_real_slice_proofs_verify_and_swapping_is_rejected(self):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        tmp = Path(tmpdir.name)
        signers = {r: keys.ephemeral_signer() for r in M.ROLES}
        keyring = C.keyring(*(s.public_key for s in signers.values()))

        cert = M.build_multiparty(POLICY, RESPONSE, signers=signers, nonce=NONCE,
                                  prove=True, proof_dir=tmp, relative_to=tmp)
        out = M.write_multiparty(cert, tmp / "multiparty.json")
        back = M.read_multiparty(out)

        ok, detail, satisfied = M.verify_multiparty(
            back, response=RESPONSE, base=tmp, keyring=keyring, policy=POLICY,
            expected_vkey=None)
        self.assertTrue(ok, detail)
        self.assertTrue(satisfied, detail)
        self.assertIn("切片证明通过密码学验证", detail)

        # 反向：把网关那份证明换成模型那份（**真**证明，只是段不对）
        swapper = copy.deepcopy(back)
        gw = next(p for p in swapper.parts if p.role == M.ROLE_GATEWAY)
        gw.proof_file = "model.proof"
        gw.proof_sha256 = M.sha256_file(tmp / "model.proof")
        gw.outcome = dict(next(p for p in back.parts
                               if p.role == M.ROLE_MODEL).outcome)
        M.sign_part(gw, signers[M.ROLE_GATEWAY])
        ok, detail, _ = M.verify_multiparty(swapper, response=RESPONSE, base=tmp,
                                            keyring=keyring, policy=POLICY)
        self.assertFalse(ok, detail)


if __name__ == "__main__":
    unittest.main()
