"""P2-10 跨证书一致性的验收：把**一组证书**聚合成一次证明。

## 三层，与前两块（P1-6 的 ``test_compose``）同构

1. **参考实现层**（不出证明）：``policydsl/session.py::run_session``（Python）
   与电路内 ``pop-types::run_session``（Rust）在 ``pop-script --check --job session``
   下**逐字段一致**。链长取 1/2/3/5/8 是有意的：Merkle 的**奇数末位提升**只在
   n 不是 2 的幂时才被走到。
2. **聚合绑定层**（不出证明）：``verify_session_proof`` 对着**手工构造**的证书集
   跑全部反例 —— 混策略、挖中间、**挖尾**、换一张、改根、改链尾承诺。这些都不
   需要真证明就能测：被拦下的那一刻发生在「由交付的证书重算根」这一步。
3. **真·端到端**（``POP_TEST_SESSION=1`` 才跑）：真出一次聚合证明 → 独立验证 →
   **换成另一组证书必须被拒**。

## 验收判据（计划 §P2-10）

「混入一张异策略证书 → 失败；**挖掉一张 → 失败**」。两条都在第 2 层，且第二条
是**只有 Merkle 根拦得住**的那一条：

* 挖掉**中间**一张 → 电路内 ``chain.index``/``prev`` 就断了（出不了证明）；
* 挖掉**链尾**一张 → ``chain.index = 0..k`` 截断后**依然是「连续」的**，电路
  自己不拦（这正是 P1-5b 的截尾问题在会话层的形态）。拦住它的是根：交付 3 张、
  证明只承诺 2 张 ⟹ 现场重算的根不一样。

所以 ``test_dropping_a_tail_certificate_is_rejected`` 是这一块**最该存在**的用例，
它同时钉住了「只靠 verify_chain 式的检查是不够的」这个事实。
"""

import base64
import json
import os
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
import sys  # noqa: E402
sys.path.insert(0, str(REPO))

from policydsl import cert, keys, session as S, trace  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402

POP_SCRIPT = S.POP_SCRIPT

#: 真·端到端要出一次证明（~2 分钟、峰值 ~10 GB），默认关闭。
RUN_SESSION = os.environ.get("POP_TEST_SESSION") == "1"

#: 固定 ts → 载荷确定性（便于断言「同一组证书 ⇒ 同一个根」）。
TS = "2026-09-12T00:00:00Z"

POLICY = Policy("demo", "0.1.0",
                rules=[Rule("keyword_block", "no_bad", {"keywords": ["weapon"]})])
SPEC = compile_policy(POLICY)
POLICY_HASH = SPEC["sha256"]

SIGNER = keys.ephemeral_signer()


def make_envelope(index: int, prev: str, seal, *, passed: bool = True,
                  policy_hash: str = POLICY_HASH, spec=SPEC, signer=SIGNER,
                  with_chain: bool = True, with_seal: bool = True) -> dict:
    """构造一张流式证书信封（形状与 ``AgentMonitor.on_generate`` 产出的一致）。

    刻意把 ``streaming.chain`` / ``trace_seal`` 做成可关的开关：反例要的正是
    「缺了某一项」的证书，而真实签发路径永远不会产出那种东西 —— 反例只能在
    测试里手工造。
    """
    outcome = {"trace_root": seal.trace_root if seal is not None else "genesis",
               "passed": passed, "violations": []}
    extra = {}
    if with_chain:
        extra["streaming"] = {"partial": False, "tokens": index,
                              "chain": {"index": index, "prev": prev}}
    payload = cert.build_payload(
        "demo", "0.1.0", spec, "public", outcome, "unproven", TS,
        extra=extra or None,
        trace_seal=trace.seal_to_json(seal) if with_seal else None)
    payload["policy_hash"] = policy_hash     # 反例要的就是「异策略」
    return cert.sign_payload(payload, signer)


def make_chain(n: int, *, gateway=None, passed=None, policy_hash=POLICY_HASH,
               signer=SIGNER) -> tuple:
    """造一条 n 张的流式链；返回 ``(证书列表, 网关)``。

    ``gateway`` 不给就新建一个（每张证书都带上**同一个**网关的 seal —— 真实路径
    就是这样的）。
    """
    gw = gateway if gateway is not None else trace.ToolGateway(ts=TS)
    if not gw.receipts:
        gw.issue("search_kb", {"query": "refund"}, result="ok")
    seal = gw.seal()
    envs, prev = [], S.GENESIS
    for i in range(n):
        ok = True if passed is None else passed[i]
        env = make_envelope(i, prev, seal, passed=ok, policy_hash=policy_hash,
                            signer=signer)
        envs.append(env)
        prev = S.cert_leaf(env)
    return envs, gw


def texts(envs) -> list:
    return [S.cert_text(e) for e in envs]


# --------------------------------------------------------------------------- #
# 1. Merkle（纯算术层）
# --------------------------------------------------------------------------- #

class TestMerkle(unittest.TestCase):
    """Merkle 的构造必须与 Rust 逐字节一致，且**不能有别名**。"""

    def _leaf(self, i: int) -> str:
        return f"{i:064x}"

    def test_single_leaf_root_is_the_leaf_itself(self):
        self.assertEqual(S.merkle_root([self._leaf(1)]), self._leaf(1))

    def test_two_leaves_are_domain_separated_nodes(self):
        import hashlib
        want = hashlib.sha256(S.MERKLE_NODE_DOMAIN
                              + bytes.fromhex(self._leaf(1))
                              + bytes.fromhex(self._leaf(2))).hexdigest()
        self.assertEqual(S.merkle_root([self._leaf(1), self._leaf(2)]), want)

    def test_odd_tail_is_promoted_not_duplicated(self):
        """☆ **本条是「挖掉一张尾证书」防线的前提**。

        末位若**复制**，``[a,b,c]`` 与 ``[a,b,c,c]`` 会得到同一个根 —— 于是
        「把链尾复制一份」或「挖掉一张再补一张同样的」都能绕过根比对。提升
        （promote）则让两者的根必然不同。
        """
        a, b, c = self._leaf(1), self._leaf(2), self._leaf(3)
        self.assertNotEqual(S.merkle_root([a, b, c]), S.merkle_root([a, b, c, c]))
        # 同理：尾部的任意增删都改变根
        self.assertNotEqual(S.merkle_root([a, b, c]), S.merkle_root([a, b]))

    def test_root_changes_when_any_leaf_changes(self):
        leaves = [self._leaf(i) for i in range(1, 6)]
        base = S.merkle_root(leaves)
        for i in range(len(leaves)):
            mutated = list(leaves)
            mutated[i] = self._leaf(99)
            self.assertNotEqual(S.merkle_root(mutated), base, f"第 {i} 片叶子没进根")

    def test_inclusion_proofs_round_trip_for_all_sizes(self):
        for n in range(1, 10):
            leaves = [self._leaf(i) for i in range(1, n + 1)]
            root = S.merkle_root(leaves)
            for i in range(n):
                proof = S.merkle_proof(leaves, i)
                self.assertTrue(S.verify_merkle_proof(leaves[i], proof, root),
                                f"n={n} 第 {i} 片的包含证明不通过")

    def test_inclusion_proof_rejects_a_tampered_leaf(self):
        leaves = [self._leaf(i) for i in range(1, 6)]
        root = S.merkle_root(leaves)
        proof = S.merkle_proof(leaves, 3)
        self.assertFalse(S.verify_merkle_proof(self._leaf(99), proof, root))
        # 换掉证明里的一个兄弟节点也必须失败
        bad = [("left", self._leaf(99)) if side == "left" else (side, sib)
               for side, sib in proof]
        self.assertFalse(S.verify_merkle_proof(leaves[3], bad, root))

    def test_shape_errors_are_fail_closed(self):
        with self.assertRaises(S.SessionError):
            S.merkle_root([])                       # 空集：恒真的「一致性」
        with self.assertRaises(S.SessionError):
            S.merkle_root(["zz"])                   # 非十六进制
        with self.assertRaises(S.SessionError):
            S.merkle_root(["abcd"])                 # 不是 32 字节
        with self.assertRaises(S.SessionError):
            S.merkle_proof([self._leaf(1)], 5)      # 下标越界


# --------------------------------------------------------------------------- #
# 2. 参考实现层：Python ↔ Rust 逐字段一致（不出证明）
# --------------------------------------------------------------------------- #

@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestSessionParity(unittest.TestCase):
    """``run_session``（Python）与 ``pop-types::run_session``（Rust）对拍。"""

    def _parity(self, envs, nonce=b"", label=""):
        py = S.run_session(texts(envs), nonce)
        ru = S.pop_check(envs, nonce)
        ru.pop("name", None)
        self.assertEqual(py, ru, f"{label}: Python 与电路实现的会话结论不一致")

    def test_parity_across_chain_lengths(self):
        """链长 1/2/3/5/8 —— 奇数链才会走到 Merkle 的末位提升。"""
        for n in (1, 2, 3, 5, 8):
            with self.subTest(n=n):
                envs, _ = make_chain(n)
                self._parity(envs, label=f"n={n}")

    def test_merkle_root_matches_between_layers(self):
        """两端的 Merkle 根逐字节相同（Python 算一遍、Rust 算一遍）。"""
        envs, _ = make_chain(5)
        py = S.run_session(texts(envs))
        self.assertEqual(py["merkle_root"],
                         S.merkle_root([S.cert_leaf(e) for e in envs]))
        self.assertEqual(S.pop_check(envs)["merkle_root"], py["merkle_root"])

    def test_session_binding_follows_the_nonce(self):
        """挑战值不同 ⟹ 绑定不同；相同 ⟹ 绑定相同（会话证明因此不可整体重放）。"""
        envs, _ = make_chain(3)
        a = S.run_session(texts(envs), bytes([1, 2, 3]))
        b = S.run_session(texts(envs), bytes([1, 2, 3]))
        c = S.run_session(texts(envs), bytes([9]))
        self.assertEqual(a["session_binding"], b["session_binding"])
        self.assertNotEqual(a["session_binding"], c["session_binding"])
        # 绑定的是根：换了证书集，同一个 nonce 也得到不同的绑定
        envs2, _ = make_chain(2)
        d = S.run_session(texts(envs2), bytes([1, 2, 3]))
        self.assertNotEqual(a["session_binding"], d["session_binding"])

    def test_outcome_shape(self):
        envs, gw = make_chain(3)
        out = S.run_session(texts(envs), b"")
        self.assertEqual(out["mode"], "session")
        self.assertEqual(out["domain"], "session")
        self.assertEqual(out["policy_hash"], POLICY_HASH)
        self.assertEqual(out["cert_count"], 3)
        self.assertEqual(out["seal_keyid"], gw.seal().keyid)
        self.assertEqual(out["sealed_count"], len(gw.receipts))
        self.assertEqual(out["trace_root"], gw.trace_root)


# --------------------------------------------------------------------------- #
# 3. 三条义务的反例（两层都必须拒）
# --------------------------------------------------------------------------- #

class TestSessionObligations(unittest.TestCase):
    """三条义务各自的反例。**两层都跑**：Python 参考实现与（可能存在的）Rust。"""

    def _both_reject(self, envs, label, nonce=b""):
        with self.assertRaises(S.SessionError, msg=f"Python 没拦住：{label}"):
            S.run_session(texts(envs), nonce)
        if POP_SCRIPT.exists():
            with self.assertRaises(S.SessionError, msg=f"Rust 没拦住：{label}"):
                S.pop_check(envs, nonce)

    def test_a_foreign_policy_certificate_is_rejected(self):
        """★ 验收判据之一：混入一张异策略证书 → 失败。"""
        envs, gw = make_chain(3)
        foreign = make_envelope(2, S.cert_leaf(envs[1]), gw.seal(),
                                policy_hash="ff" * 32)
        self._both_reject([envs[0], envs[1], foreign], "混入异策略证书")

    def test_a_missing_middle_certificate_is_rejected(self):
        """挖掉中间一张 → 电路内的 index/prev 就断了。"""
        envs, _ = make_chain(3)
        self._both_reject([envs[0], envs[2]], "挖掉中间那张")

    def test_reordering_is_rejected(self):
        envs, _ = make_chain(3)
        self._both_reject([envs[1], envs[0], envs[2]], "重排")

    def test_certificate_without_chain_is_rejected(self):
        envs, gw = make_chain(2)
        naked = make_envelope(1, S.GENESIS, gw.seal(), with_chain=False)
        self._both_reject([envs[0], naked], "缺 streaming.chain")

    def test_certificate_without_seal_is_rejected(self):
        """★ 缺 seal 的证书必须被拒 —— 否则「链尾被删」无从排除（P1-5b 同口径）。"""
        envs, gw = make_chain(2)
        noseal = make_envelope(1, S.cert_leaf(envs[0]), gw.seal(), with_seal=False)
        self._both_reject([envs[0], noseal], "缺 trace_seal")

    def test_seals_from_two_different_gateways_are_rejected(self):
        """两条网关的证书不能拼成一条会话（keyid 不同即拒）。

        攻击形态：会话前半段在网关 A 下、后半段换到网关 B（或把 B 的证书混进来）
        —— 各自的 seal 都是真的，但「这一整条轨迹被**谁**承诺」就没有答案了。
        """
        first, _ = make_chain(1)
        other_gateway = trace.ToolGateway(ts=TS)     # 另一把临时钥 ⇒ 另一个 keyid
        crossed = make_envelope(1, S.cert_leaf(first[0]), other_gateway.seal())
        self._both_reject([first[0], crossed], "两条网关的 seal 混用")

    def test_empty_set_is_rejected(self):
        """空集的「一致性/无缺口/全覆盖」都是恒真的 —— 必须拒。"""
        with self.assertRaises(S.SessionError):
            S.run_session([])
        if POP_SCRIPT.exists():
            with self.assertRaises(S.SessionError):
                S.pop_check([])


# --------------------------------------------------------------------------- #
# 4. 聚合绑定层：验证方对着交付的证书集核（不出证明）
# --------------------------------------------------------------------------- #

class TestVerifySessionProof(unittest.TestCase):
    """``verify_session_proof`` 的绑定检查（``proof=None``，如实注明密码学未核）。"""

    def _ok_outcome(self, envs, nonce=b"") -> dict:
        return S.run_session(texts(envs), nonce)

    def test_happy_path(self):
        envs, _ = make_chain(3)
        ok, detail, satisfied = S.verify_session_proof(self._ok_outcome(envs), envelopes=envs)
        self.assertTrue(ok, detail)
        self.assertTrue(satisfied, detail)
        self.assertIn("证明有效性未核", detail)     # 没给 proof 就必须这么说

    def test_foreign_policy_certificate_fails(self):
        """★ 验收：混入一张异策略证书 → 失败。

        拦住它的是义务①（对**交付的这批证书**现场重算时就发现 policy_hash 不同），
        比根比对**更早** —— 两条防线都指向同一个结论，这里是先到的那条。
        """
        envs, gw = make_chain(3)
        outcome = self._ok_outcome(envs)
        foreign = make_envelope(2, S.cert_leaf(envs[1]), gw.seal(),
                                policy_hash="ff" * 32)
        ok, detail, _ = S.verify_session_proof(outcome,
                                               envelopes=[envs[0], envs[1], foreign])
        self.assertFalse(ok)
        self.assertIn("策略哈希", detail)

    def test_dropping_a_tail_certificate_is_rejected(self):
        """★ 验收：**挖掉一张 → 失败**，而且这里挖的是**链尾**那张。

        这是本文件最重要的一条用例：链尾被挖掉之后，剩下的 `index = 0..k`
        **依然是连续的**，三条义务全部满足（下面①就断言了这一点），拦住它的
        只有②「由交付的证书重算 Merkle 根」。若哪天有人把根比对删掉，这条会红
        —— 而别的反例（混策略、挖中间、重排）都拦不住漏掉根比对的后果。
        """
        envs, _ = make_chain(4)
        trimmed = envs[:3]
        # ① 先确认这组证书**确实**满足所有义务（否则「只有根拦得住」是句空话）
        S.run_session(texts(trimmed))          # 不抛错：截断后的链仍然自洽
        # ② 但拿「4 张的结论」去核「3 张的交付」必须失败
        ok, detail, _ = S.verify_session_proof(self._ok_outcome(envs), envelopes=trimmed)
        self.assertFalse(ok)
        self.assertIn("Merkle", detail)

    def test_a_consistent_but_replaced_tail_is_rejected(self):
        """★ 链尾**整张换掉**（index/prev/策略/seal 全都对）—— 仍然必须失败。

        这是比「挖掉链尾」更刁的形态：攻击者保留链的形状，只把链尾那张的**内容**
        换掉 —— 把一次违规从会话末尾抹掉。三条义务它**全部满足**（下面①），
        拦住它的仍然只有根。

        反例必须让内容**真的不同**：拿「同参数重建一张」当反例是恒真的（它逐
        字节就是原来那张），这一点值得显式断言一下。
        """
        envs, gw = make_chain(3, passed=[True, True, False])   # 链尾那张记录了一次违规
        clean = make_envelope(2, S.cert_leaf(envs[1]), gw.seal(), passed=True)
        self.assertNotEqual(S.cert_leaf(clean), S.cert_leaf(envs[2]),
                            "反例必须与原证书**不同**，否则这条用例是恒真的")
        # ① 义务全过：换进来的是一张「合规」且链接得严丝合缝的证书
        S.run_session(texts([envs[0], envs[1], clean]))
        outcome = self._ok_outcome(envs)
        # ② 拿原来那组（含违规链尾）出的结论，去核换过链尾的交付 ⟹ 根对不上
        ok, detail, _ = S.verify_session_proof(
            outcome, envelopes=[envs[0], envs[1], clean])
        self.assertFalse(ok)
        self.assertIn("Merkle", detail)
        # ③ 正对照：交付**原封不动**那组时，证明为真、但轨迹不合规（ok≠satisfied）
        ok, detail, satisfied = S.verify_session_proof(outcome, envelopes=envs)
        self.assertTrue(ok, detail)
        self.assertFalse(satisfied)

    def test_dropping_a_middle_certificate_is_rejected(self):
        envs, _ = make_chain(4)
        trimmed = [envs[0], envs[1], envs[3]]
        ok, detail, _ = S.verify_session_proof(self._ok_outcome(envs), envelopes=trimmed)
        self.assertFalse(ok)

    def test_swapping_one_certificate_for_another_fails(self):
        """同策略、同链位、不同内容的一张证书：内容变了，链与根都得变。

        换进来的那张 `prev` 仍指向第 0 张（所以义务②先抓到它）—— 即便攻击者
        把 `prev`/`index` 也一起改对，下面的根比对仍会拦（那是
        ``test_dropping_a_tail_certificate_is_rejected`` 覆盖的落点）。
        """
        envs, gw = make_chain(3)
        swapped = make_envelope(1, S.cert_leaf(envs[0]), gw.seal(), passed=False)
        ok, detail, _ = S.verify_session_proof(self._ok_outcome(envs),
                                               envelopes=[envs[0], swapped, envs[2]])
        self.assertFalse(ok)
        self.assertIn("chain.prev", detail)

    def test_a_forged_root_is_rejected(self):
        envs, _ = make_chain(3)
        forged = self._ok_outcome(envs)
        forged["merkle_root"] = "00" * 32
        ok, detail, _ = S.verify_session_proof(forged, envelopes=envs)
        self.assertFalse(ok)
        self.assertIn("Merkle", detail)

    def test_a_forged_trace_root_is_rejected(self):
        """链尾承诺被改 → 与交付的证书重算出来的不符。"""
        envs, _ = make_chain(3)
        forged = self._ok_outcome(envs)
        forged["trace_root"] = "deadbeef"
        ok, detail, _ = S.verify_session_proof(forged, envelopes=envs)
        self.assertFalse(ok)
        self.assertIn("trace_root", detail)

    def test_a_forged_policy_hash_is_rejected(self):
        envs, _ = make_chain(3)
        forged = self._ok_outcome(envs)
        forged["policy_hash"] = "ab" * 32
        ok, detail, _ = S.verify_session_proof(forged, envelopes=envs)
        self.assertFalse(ok)

    def test_wrong_domain_is_rejected(self):
        envs, _ = make_chain(2)
        forged = self._ok_outcome(envs)
        forged["domain"] = "policy"
        ok, detail, _ = S.verify_session_proof(forged, envelopes=envs)
        self.assertFalse(ok)
        self.assertIn("domain", detail)

    def test_policy_pack_is_recompiled_on_site(self):
        """给了策略包就核「承诺的 policy_hash == 现场重编译」——换策略包即拒。"""
        import tempfile
        envs, _ = make_chain(2)
        other = Policy("other", "0.1.0",
                       rules=[Rule("keyword_block", "no_bad", {"keywords": ["different"]})])
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "other.json"
            p.write_text(json.dumps({"id": other.id, "version": other.version,
                                     "rules": [{"kind": r.kind, "name": r.name,
                                                "params": r.params} for r in other.rules]}))
            ok, detail, _ = S.verify_session_proof(self._ok_outcome(envs), envelopes=envs,
                                                   policy_pack=p)
            self.assertFalse(ok)
            self.assertIn("重编译", detail)
        # 正对照：给**正确**的策略对象则通过
        ok, detail, _ = S.verify_session_proof(self._ok_outcome(envs), envelopes=envs,
                                               policy=POLICY)
        self.assertTrue(ok, detail)

    def test_seal_signature_is_checked_when_a_keyring_is_given(self):
        """★ ③ 的另一半：给了网关公钥就真验签；给了**别人**的公钥就必须失败。"""
        envs, gw = make_chain(2)
        outcome = self._ok_outcome(envs)
        ok, detail, _ = S.verify_session_proof(outcome, envelopes=envs,
                                               keyring={gw.seal().keyid: gw.public_key})
        self.assertTrue(ok, detail)
        self.assertIn("已由", detail)              # 「seal 已由 … 签出」

        other = trace.ToolGateway(ts=TS)
        ok, detail, _ = S.verify_session_proof(outcome, envelopes=envs,
                                               keyring={gw.seal().keyid: other.public_key})
        self.assertFalse(ok)
        self.assertIn("签名", detail)

    def test_seal_is_checked_against_the_real_receipts(self):
        """给了真回执链就核 count/trace_root —— 截尾的链会对不上。"""
        envs, gw = make_chain(2)
        outcome = self._ok_outcome(envs)
        ok, detail, _ = S.verify_session_proof(outcome, envelopes=envs,
                                               receipts=gw.receipts)
        self.assertTrue(ok, detail)
        ok, detail, _ = S.verify_session_proof(outcome, envelopes=envs,
                                               receipts=[])          # 链被截尾
        self.assertFalse(ok)
        self.assertIn("count", detail)

    def test_unproven_proof_is_reported_honestly(self):
        """没给 proof 时**不能**让调用方以为密码学那一步跑过了。"""
        envs, _ = make_chain(2)
        ok, detail, _ = S.verify_session_proof(self._ok_outcome(envs), envelopes=envs)
        self.assertTrue(ok)
        self.assertIn("未核", detail)

    def test_a_violating_trajectory_is_true_but_not_satisfied(self):
        """★ 与 compose/cert 同一条口径：一张如实记录违规的聚合证明**同样是真**的。

        ``ok`` 与 ``satisfied`` 必须分开返回 —— 混成一个布尔值，验证方就没法
        区分「证明是假的」与「策略真的被违反了」。
        """
        envs, _ = make_chain(3, passed=[True, False, True])
        ok, detail, satisfied = S.verify_session_proof(self._ok_outcome(envs), envelopes=envs)
        self.assertTrue(ok, detail)
        self.assertFalse(satisfied)
        self.assertIn("不合规", detail)

    def test_empty_delivery_is_rejected(self):
        envs, _ = make_chain(2)
        ok, detail, _ = S.verify_session_proof(self._ok_outcome(envs), envelopes=[])
        self.assertFalse(ok)


# --------------------------------------------------------------------------- #
# 5. 多 run 切分
# --------------------------------------------------------------------------- #

class TestRunsOf(unittest.TestCase):

    def test_two_runs_are_split_at_index_zero(self):
        """一个 session 里两条互不相干的流式链 —— 每次 index 归零就切开。"""
        a, _ = make_chain(2)
        b, _ = make_chain(3)
        runs = S.runs_of(a + b)
        self.assertEqual([len(r) for r in runs], [2, 3])

    def test_a_single_run_stays_whole(self):
        envs, _ = make_chain(4)
        self.assertEqual(len(S.runs_of(envs)), 1)

    def test_off_chain_certificates_are_not_swept_into_a_run(self):
        """不在链上的证书（如 ``on_llm_end`` 那张权威证书）不属于任何 run。

        真实会话包里它没有 ``streaming`` 块 —— 若被扫进 run，义务②会当场失败，
        而它本来也不该被算作链的一环。
        """
        envs, gw = make_chain(3)
        authoritative = make_envelope(3, S.GENESIS, gw.seal(), with_chain=False)
        runs = S.runs_of([envs[0], envs[1], authoritative, envs[2]])
        self.assertEqual([len(r) for r in runs], [3])
        self.assertNotIn(authoritative, runs[0])


# --------------------------------------------------------------------------- #
# 6. 真·端到端（门控）
# --------------------------------------------------------------------------- #

@unittest.skipUnless(RUN_SESSION, "set POP_TEST_SESSION=1 to run the real session proof")
class TestSessionEndToEnd(unittest.TestCase):
    """真出一次聚合证明 → 独立验证 → 换/挖证书必须被拒。"""

    def test_real_proof_verifies_and_binds(self):
        import tempfile
        envs, gw = make_chain(3)
        nonce = bytes([0x51, 0x52, 0x53])
        with tempfile.TemporaryDirectory() as tmp:
            proof = Path(tmp) / "session.proof"
            res = S.prove_session(envs, nonce=nonce, proof_out=proof)
            outcome = res["outcome"]
            self.assertEqual(outcome["mode"], "session")
            self.assertEqual(outcome["cert_count"], 3)

            # 正向：带证明核，通过
            ok, detail, satisfied = S.verify_session_proof(
                outcome, envelopes=envs, nonce=nonce, proof=proof,
                keyring={gw.seal().keyid: gw.public_key}, receipts=gw.receipts)
            self.assertTrue(ok, detail)
            self.assertTrue(satisfied, detail)
            self.assertIn("密码学验证", detail)

            # 反向：换一组证书 → 根对不上
            other, _ = make_chain(3)
            ok, detail, _ = S.verify_session_proof(outcome, envelopes=other,
                                                   nonce=nonce, proof=proof)
            self.assertFalse(ok)
            self.assertIn("Merkle", detail)

            # 反向：挖掉链尾一张 → 根对不上
            ok, detail, _ = S.verify_session_proof(outcome, envelopes=envs[:2],
                                                   nonce=nonce, proof=proof)
            self.assertFalse(ok)
            self.assertIn("Merkle", detail)

            # 反向：混入一张异策略证书（计划 §P2-10 的第一条验收判据，对着**真证明**跑）
            # 异策略证书的叶子摘要必然不同于原证书 ⟹ 根也对不上；这里钉住的是
            # 「在重算三条义务那一步就被拦下」，比根比对更早、诊断也更具体。
            foreign, _ = make_chain(1, policy_hash="0" * 64)
            mixed = [envs[0], foreign[0], envs[2]]
            self.assertNotEqual(S.cert_leaf(mixed[1]), S.cert_leaf(envs[1]))  # 非空洞
            ok, detail, _ = S.verify_session_proof(outcome, envelopes=mixed,
                                                   nonce=nonce, proof=proof)
            self.assertFalse(ok)
            self.assertIn("策略哈希", detail)

            # 反向：换个 nonce → 绑定对不上
            ok, detail, _ = S.verify_session_proof(outcome, envelopes=envs,
                                                   nonce=b"", proof=proof)
            self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
