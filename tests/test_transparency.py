"""透明日志原型（``policydsl.evidence.transparency``）的单元测试。

覆盖任务要求的五类：追加、根变化、包含证明、篡改、重放。另加三类**边界**，
因为它们是把「只追加」与「可验证」分开的地方：

* 空日志没有根（不返回假值）；
* 叶子绑定（F-3）—— 默认只绑证书，给了 ``binding`` 才绑被交付工件；
* 树头签名（F-L 的雏形）—— 未签名头不得被当作日志承诺。

新增（A10）：**一致性证明 / gossip**（F-2 的密码学内核）——

* 旧树是新树前缀时，RFC 6962 风格的证明必须通过（含空树、同尺寸、跨多次追加）；
* 回滚、改写前缀、分叉（split-view）必须被拒；
* 包含证明与一致性证明可以组合使用；
* gossip 消息能把「审计者见过的旧树头 → 当前树头」连同证明一起转发。

所有用例只碰内存对象，不跑 SP1、不写文件。
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl.evidence import cert  # noqa: E402
from policydsl.evidence import transparency as T  # noqa: E402


def digest(i: int) -> str:
    """确定性的 32 字节摘要（测试用；不依赖随机数）。"""
    return cert.sha256_hex(f"cert-{i}".encode())


def binding(i: int) -> str:
    return cert.sha256_hex(f"delivery-{i}".encode())


def log_with(values) -> T.TransparencyLog:
    """按给定摘要序列建一棵日志（测试用）。"""
    log = T.TransparencyLog()
    for value in values:
        log.append(value)
    return log


def checkpoints(n: int):
    """追加 ``n`` 条，返回 ``[(size, root)]``（下标即 size）；空树根为 ``None``。"""
    log = T.TransparencyLog()
    cps = [(0, None)]
    for i in range(n):
        log.append(digest(i))
        cps.append((log.size, log.root()))
    return log, cps


class TestAppendAndRoot(unittest.TestCase):
    """追加只增长；根随内容变化；空日志没有根。"""

    def test_empty_log_has_no_root(self):
        log = T.TransparencyLog()
        self.assertEqual(log.size, 0)
        with self.assertRaises(T.TransparencyError):
            log.root()
        with self.assertRaises(T.TransparencyError):
            log.checkpoint()

    def test_append_grows_and_changes_root(self):
        log = T.TransparencyLog()
        roots = []
        for i in range(5):
            idx = log.append(digest(i))
            self.assertEqual(idx, i)
            roots.append(log.root())
            self.assertEqual(log.size, i + 1)
        self.assertEqual(len(set(roots)), len(roots), "每次追加后根都必须变化")
        self.assertEqual(log.checkpoint().root, log.root())

    def test_append_does_not_mutate_previous_entries(self):
        log = T.TransparencyLog()
        log.append(digest(0))
        before = log.entry(0)
        log.append(digest(1))
        self.assertEqual(log.entry(0), before, "追加不得改写历史条目")

    def test_duplicate_append_is_two_events(self):
        # 日志是事件序列，不是集合：同一个证书摘要可以出现两次。
        log = T.TransparencyLog()
        a = log.append(digest(0))
        b = log.append(digest(0))
        self.assertEqual((a, b), (0, 1))
        self.assertEqual(log.size, 2)
        # 两次事件的叶子相同（第二原像抗性下，同一证书摘要就是同一叶子）；
        # 证明里的 index 是**这次事件**的下标，元数据不同。
        pa, pb = log.prove(a), log.prove(b)
        self.assertEqual(pa["leaf"], pb["leaf"])
        self.assertEqual(pa["index"], 0)
        self.assertEqual(pb["index"], 1)
        # 两条证明都能验证同一摘要 —— 对**相同事件**这是对的行为，不是重放漏洞。
        self.assertTrue(T.verify_inclusion(digest(0), pa))
        self.assertTrue(T.verify_inclusion(digest(0), pb))


class TestInclusion(unittest.TestCase):
    """包含证明对每个下标都成立，且能通过检查点核对。"""

    def test_inclusion_for_every_index(self):
        log = T.TransparencyLog()
        for i in range(17):        # 含奇数叶子（末位提升）与多层
            log.append(digest(i))
        cp = log.checkpoint()
        for i in range(log.size):
            proof = log.prove(i)
            self.assertTrue(
                T.verify_inclusion(digest(i), proof,
                                   expected_root=cp.root, expected_size=cp.size),
                f"第 {i} 片叶子的包含证明应通过")
        self.assertGreater(len(log.prove(0)["path"]), 0)

    def test_single_leaf_has_empty_path(self):
        log = T.TransparencyLog()
        log.append(digest(0))
        proof = log.prove(0)
        self.assertEqual(proof["path"], [])
        self.assertTrue(T.verify_inclusion(digest(0), proof))

    def test_unknown_digest_fails(self):
        log = T.TransparencyLog()
        for i in range(4):
            log.append(digest(i))
        proof = log.prove(0)
        self.assertFalse(T.verify_inclusion(digest(99), proof))

    def test_bad_proof_shape_returns_false(self):
        log = T.TransparencyLog()
        log.append(digest(0))
        proof = log.prove(0)
        for bad in (None, {}, {**proof, "path": "nope"},
                    {**proof, "index": -1}, {**proof, "size": 0},
                    {**proof, "path": [["up", "00" * 32]]}):
            self.assertFalse(T.verify_inclusion(digest(0), bad))


class TestTamper(unittest.TestCase):
    """改动叶子、路径、绑定或根，都必须失败。"""

    def setUp(self):
        self.log = T.TransparencyLog()
        for i in range(8):
            self.log.append(digest(i))
        self.proof = self.log.prove(3)

    def test_tampered_leaf_fails(self):
        bad = {**self.proof, "leaf": digest(4)}
        self.assertFalse(T.verify_inclusion(digest(3), bad))

    def test_tampered_path_fails(self):
        path = [list(p) for p in self.proof["path"]]
        side, sib = path[0]
        path[0] = [side, digest(123)]
        self.assertFalse(T.verify_inclusion(digest(3), {**self.proof, "path": path}))

    def test_tampered_root_fails(self):
        bad = {**self.proof, "root": digest(124)}
        self.assertFalse(T.verify_inclusion(digest(3), bad))

    def test_expected_root_mismatch_fails(self):
        # 即使证明自身自洽，调用方拿到的检查点不同也必须拒绝。
        self.assertFalse(
            T.verify_inclusion(digest(3), self.proof, expected_root=digest(125)))
        self.assertFalse(
            T.verify_inclusion(digest(3), self.proof, expected_size=self.log.size + 1))

    def test_binding_tamper_fails(self):
        log = T.TransparencyLog()
        idx = log.append(digest(0), binding=binding(0))
        proof = log.prove(idx)
        self.assertTrue(T.verify_inclusion(digest(0), proof, binding=binding(0)))
        self.assertFalse(T.verify_inclusion(digest(0), proof, binding=binding(1)))
        self.assertFalse(T.verify_inclusion(digest(0), proof))   # 漏传绑定


class TestReplay(unittest.TestCase):
    """重放：旧证明、他人的证明、同一证书的另一事件，都不能冒充。"""

    def test_old_proof_does_not_verify_against_new_root(self):
        log = T.TransparencyLog()
        for i in range(4):
            log.append(digest(i))
        old = log.prove(1)
        old_cp = log.checkpoint()
        log.append(digest(4))
        new_cp = log.checkpoint()
        self.assertNotEqual(old_cp.root, new_cp.root)
        # 证明仍对旧视图成立……
        self.assertTrue(T.verify_inclusion(digest(1), old, expected_root=old_cp.root))
        # ……但拿新检查点核对必须失败（防止把旧视图当现状）。
        self.assertFalse(T.verify_inclusion(digest(1), old, expected_root=new_cp.root,
                                            expected_size=new_cp.size))

    def test_proof_for_one_digest_cannot_be_replayed_for_another(self):
        log = T.TransparencyLog()
        for i in range(6):
            log.append(digest(i))
        proof = log.prove(2)
        self.assertTrue(T.verify_inclusion(digest(2), proof))
        self.assertFalse(T.verify_inclusion(digest(5), proof))

    def test_duplicate_event_proofs_are_indistinguishable(self):
        # 同一摘要的两次事件，叶子相同；证明可以互相验证 —— 这不是漏洞，
        # 因为两片叶子承诺的是同一个值。要防的是**不同摘要**之间的重放，
        # 见 test_proof_for_one_digest_cannot_be_replayed_for_another。
        log = T.TransparencyLog()
        log.append(digest(0))
        log.append(digest(0))
        p0, p1 = log.prove(0), log.prove(1)
        self.assertEqual(p0["leaf"], p1["leaf"])
        self.assertTrue(T.verify_inclusion(digest(0), {**p1, "index": 0}))


class TestBindingAndHead(unittest.TestCase):
    """F-3 的绑定语义与 F-L 的树头签名雏形。"""

    def test_default_leaf_equals_cert_digest(self):
        # 与定理 F2 的 d = H(canonical(cert)) 对齐。
        self.assertEqual(T.entry_hash(digest(0)), digest(0))

    def test_binding_changes_leaf(self):
        self.assertNotEqual(T.entry_hash(digest(0), binding(0)), digest(0))
        self.assertNotEqual(T.entry_hash(digest(0), binding(0)),
                            T.entry_hash(digest(0), binding(1)))

    def test_head_signed_and_verified(self):
        log = T.TransparencyLog()
        log.append(digest(0))
        signer = cert.Ed25519Signer.generate()
        head = log.head(signer, ts="2026-11-01T00:00:00Z")
        ok, body = T.verify_head(head, {signer.keyid: signer.public_key})
        self.assertTrue(ok)
        self.assertEqual(body["root"], log.root())
        self.assertEqual(body["size"], log.size)

    def test_unsigned_head_is_not_a_commitment(self):
        log = T.TransparencyLog()
        log.append(digest(0))
        ok, body = T.verify_head(log.head(), {})
        self.assertFalse(ok)
        self.assertIsNone(body)

    def test_tampered_head_fails(self):
        log = T.TransparencyLog()
        log.append(digest(0))
        signer = cert.Ed25519Signer.generate()
        head = log.head(signer)
        bad = {**head, "root": digest(9)}
        ok, _ = T.verify_head(bad, {signer.keyid: signer.public_key})
        self.assertFalse(ok)


class TestConsistencyPositive(unittest.TestCase):
    """旧树是新树的前缀 → 一致性证明必须通过（RFC 6962）。"""

    def test_every_prefix_pair_verifies(self):
        # 覆盖奇偶叶子、末位提升、跨 2 的幂边界；n 取到 17 已有多层。
        log, cps = checkpoints(17)
        for n in (1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17):
            for m in range(0, n + 1):
                proof = log.consistency_proof(m, n)
                self.assertTrue(
                    T.verify_consistency(cps[m][1], m, cps[n][1], n, proof),
                    f"{m} → {n} 的一致性证明应通过")
                # 裸 path 列表也必须能验（便于线上只传数组）。
                self.assertTrue(
                    T.verify_consistency(cps[m][1], m, cps[n][1], n, proof["path"]),
                    f"{m} → {n} 的裸 path 应通过")

    def test_proof_binds_both_roots_and_sizes(self):
        log, cps = checkpoints(9)
        proof = log.consistency_proof(3, 9)
        self.assertEqual(proof["old_size"], 3)
        self.assertEqual(proof["new_size"], 9)
        self.assertEqual(proof["old_root"], cps[3][1])
        self.assertEqual(proof["new_root"], cps[9][1])
        self.assertTrue(proof["path"], "非平凡前缀必须有非空路径")
        # 路径只含 32 字节摘要。
        for item in proof["path"]:
            self.assertEqual(len(bytes.fromhex(item)), 32)

    def test_empty_tree_to_nonempty(self):
        log = log_with([digest(i) for i in range(5)])
        proof = log.consistency_proof(0, 5)
        self.assertIsNone(proof["old_root"], "空树没有根")
        self.assertEqual(proof["path"], [])
        self.assertEqual(proof["new_root"], log.root())
        self.assertTrue(T.verify_consistency(None, 0, log.root(), 5, proof))
        # 声称空树有一个具体根 → 拒绝。
        self.assertFalse(T.verify_consistency(digest(0), 0, log.root(), 5, proof))

    def test_same_size_requires_equal_roots(self):
        log, cps = checkpoints(6)
        proof = log.consistency_proof(6, 6)
        self.assertEqual(proof["path"], [])
        self.assertTrue(T.verify_consistency(cps[6][1], 6, cps[6][1], 6, proof))
        self.assertFalse(T.verify_consistency(cps[5][1], 6, cps[6][1], 6, proof))
        # 同尺寸却给了非空路径 → 拒绝。
        self.assertFalse(T.verify_consistency(
            cps[6][1], 6, cps[6][1], 6, [digest(0)]))

    def test_zero_to_zero(self):
        log = T.TransparencyLog()
        proof = log.consistency_proof(0, 0)
        self.assertIsNone(proof["old_root"])
        self.assertIsNone(proof["new_root"])
        self.assertEqual(proof["path"], [])
        self.assertTrue(T.verify_consistency(None, 0, None, 0, proof))

    def test_multiple_appends_between_checkpoints(self):
        log = T.TransparencyLog()
        for i in range(3):
            log.append(digest(i))
        old = log.checkpoint()
        for i in range(3, 17):
            log.append(digest(i))
        new = log.checkpoint()
        proof = log.consistency_proof(old.size, new.size)
        self.assertGreater(len(proof["path"]), 1)
        self.assertTrue(T.verify_consistency(old.root, old.size,
                                             new.root, new.size, proof))

    def test_chain_of_checkpoints(self):
        log, cps = checkpoints(20)
        for a, b in ((0, 1), (1, 2), (2, 4), (4, 8), (8, 16), (3, 20), (0, 20)):
            proof = log.consistency_proof(a, b)
            self.assertTrue(T.verify_consistency(cps[a][1], a, cps[b][1], b, proof),
                            f"检查点链 {a} → {b} 应通过")

    def test_invalid_sizes_raise_at_proof_time(self):
        log, _ = checkpoints(5)
        with self.assertRaises(T.TransparencyError):
            log.consistency_proof(5, 4)          # 回滚不是只追加
        with self.assertRaises(T.TransparencyError):
            log.consistency_proof(0, 6)          # 超过当前大小
        with self.assertRaises(T.TransparencyError):
            log.consistency_proof(-1, 5)
        with self.assertRaises(T.TransparencyError):
            log.consistency_proof(1.0, 5)        # 必须是整数


class TestConsistencyNegative(unittest.TestCase):
    """回滚、改写、分叉、篡改路径 → 一律拒绝。"""

    def test_rollback_is_rejected(self):
        log, cps = checkpoints(8)
        # 「新树」比「旧树」小：连证明都生成不出来。
        with self.assertRaises(T.TransparencyError):
            log.consistency_proof(8, 5)
        # 即使把大小对调着喂给验证函数，也必须 False。
        proof = log.consistency_proof(5, 8)
        self.assertFalse(T.verify_consistency(cps[8][1], 8, cps[5][1], 5, proof))

    def test_rewritten_prefix_is_rejected(self):
        # 分叉：前 5 片里第 3 片被改写，其余相同。
        original, cps = checkpoints(8)
        fork = log_with([digest(0), digest(1), digest(2), digest(99),
                         digest(4), digest(5), digest(6), digest(7)])
        self.assertEqual(fork.size, original.size)
        proof = fork.consistency_proof(5, 8)
        self.assertNotEqual(proof["old_root"], cps[5][1])
        # 分叉自己能证明自己（证明自洽）……
        self.assertTrue(T.verify_consistency(proof["old_root"], 5,
                                             fork.root(), 8, proof))
        # ……但拿原树第 5 片时的树头去核对，必须失败。
        self.assertFalse(T.verify_consistency(cps[5][1], 5,
                                              fork.root(), 8, proof))

    def test_split_view_two_extensions_rejected(self):
        # 同一前缀（前 4 片）之后分成两条互不相同的延伸。
        prefix = [digest(i) for i in range(4)]
        branch_a = log_with(prefix + [digest(i) for i in range(4, 8)])
        branch_b = log_with(prefix + [digest(i) for i in range(104, 108)])
        old_root = branch_a.consistency_proof(4, 8)["old_root"]
        self.assertEqual(old_root, branch_b.consistency_proof(4, 8)["old_root"])
        self.assertNotEqual(branch_a.root(), branch_b.root())
        proof_a = branch_a.consistency_proof(4, 8)
        self.assertTrue(T.verify_consistency(old_root, 4, branch_a.root(), 8, proof_a))
        # A 的证明不能被用来把 B 的树头「洗白」。
        self.assertFalse(T.verify_consistency(old_root, 4, branch_b.root(), 8, proof_a))
        proof_b = branch_b.consistency_proof(4, 8)
        self.assertFalse(T.verify_consistency(old_root, 4, branch_a.root(), 8, proof_b))

    def test_each_tampered_path_element_fails(self):
        log, cps = checkpoints(11)
        proof = log.consistency_proof(4, 11)
        self.assertTrue(proof["path"])
        for i in range(len(proof["path"])):
            bad = {**proof, "path": list(proof["path"])}
            bad["path"][i] = digest(200 + i)
            self.assertFalse(
                T.verify_consistency(cps[4][1], 4, cps[11][1], 11, bad),
                f"篡改第 {i} 个路径元素应失败")

    def test_wrong_roots_and_sizes_fail(self):
        log, cps = checkpoints(9)
        proof = log.consistency_proof(4, 9)
        self.assertFalse(T.verify_consistency(cps[3][1], 4, cps[9][1], 9, proof))
        self.assertFalse(T.verify_consistency(cps[4][1], 4, cps[8][1], 9, proof))
        self.assertFalse(T.verify_consistency(cps[4][1], 3, cps[9][1], 9, proof))
        self.assertFalse(T.verify_consistency(cps[4][1], 4, cps[9][1], 8, proof))

    def test_proof_from_another_size_pair_is_rejected(self):
        log, cps = checkpoints(9)
        proof_3_9 = log.consistency_proof(3, 9)
        # 内嵌的 old_size/new_size 与调用方参数不一致 → 形状层就拒绝，
        # 即使把 roots 换成这一对「碰巧」对得上的值。
        self.assertFalse(T.verify_consistency(cps[4][1], 4, cps[9][1], 9, proof_3_9))
        self.assertFalse(T.verify_consistency(cps[3][1], 3, cps[9][1], 8, proof_3_9))

    def test_truncated_or_extended_proof_fails(self):
        log, cps = checkpoints(13)
        proof = log.consistency_proof(5, 13)
        short = {**proof, "path": list(proof["path"][:-1])}
        extra = {**proof, "path": list(proof["path"]) + [digest(300)]}
        self.assertFalse(T.verify_consistency(cps[5][1], 5, cps[13][1], 13, short))
        self.assertFalse(T.verify_consistency(cps[5][1], 5, cps[13][1], 13, extra))
        self.assertFalse(T.verify_consistency(cps[5][1], 5, cps[13][1], 13, []))

    def test_malformed_inputs_return_false(self):
        log, cps = checkpoints(5)
        proof = log.consistency_proof(2, 5)
        good = (cps[2][1], 2, cps[5][1], 5)
        bad_proofs = [
            None, {}, "nope", 42,
            {"path": "nope"},
            {"path": [["left", digest(0)]]},
            {"path": [digest(0), "zz" * 32]},
            {"path": [digest(0), None]},
        ]
        for bad in bad_proofs:
            self.assertFalse(T.verify_consistency(*good, bad), repr(bad))
        self.assertFalse(T.verify_consistency(cps[2][1], 2, cps[5][1], 5,
                                              {**proof, "old_size": 3}))
        self.assertFalse(T.verify_consistency(cps[2][1], 2, cps[5][1], 5,
                                              {**proof, "new_root": digest(9)}))
        self.assertFalse(T.verify_consistency(None, 2, cps[5][1], 5, proof))
        self.assertFalse(T.verify_consistency(cps[2][1], 2, None, 5, proof))
        self.assertFalse(T.verify_consistency(cps[2][1], -1, cps[5][1], 5, proof))
        self.assertFalse(T.verify_consistency(cps[2][1], True, cps[5][1], 5, proof))

    def test_empty_tree_with_nonempty_proof_fails(self):
        log, cps = checkpoints(5)
        self.assertFalse(T.verify_consistency(None, 0, cps[5][1], 5, [digest(0)]))


class TestInclusionAndConsistencyTogether(unittest.TestCase):
    """包含证明 + 一致性证明：旧视图的叶子在新视图里仍然是同一片叶子。"""

    def test_old_inclusion_survives_append_and_consistency(self):
        log = T.TransparencyLog()
        for i in range(5):
            log.append(digest(i))
        old = log.checkpoint()
        old_proof = log.prove(2)
        for i in range(5, 9):
            log.append(digest(i))
        new = log.checkpoint()

        consistency = log.consistency_proof(old.size, new.size)
        self.assertTrue(T.verify_consistency(old.root, old.size,
                                             new.root, new.size, consistency))
        # 旧包含证明仍对旧检查点成立……
        self.assertTrue(T.verify_inclusion(digest(2), old_proof,
                                           expected_root=old.root,
                                           expected_size=old.size))
        # ……但它不能冒充新视图（根/尺寸都变了）。
        self.assertFalse(T.verify_inclusion(digest(2), old_proof,
                                            expected_root=new.root,
                                            expected_size=new.size))
        # 同一片叶子在新树里的包含证明，与一致性证明一起用。
        new_proof = log.prove(2)
        self.assertTrue(T.verify_inclusion(digest(2), new_proof,
                                           expected_root=new.root,
                                           expected_size=new.size))
        self.assertEqual(old_proof["leaf"], new_proof["leaf"])

    def test_consistency_and_binding_leaves(self):
        # F-3 的绑定叶与 F-2 的一致性证明互不干扰。
        log = T.TransparencyLog()
        log.append(digest(0), binding=binding(0))
        log.append(digest(1), binding=binding(1))
        old = log.checkpoint()
        log.append(digest(2), binding=binding(2))
        new = log.checkpoint()
        proof = log.consistency_proof(old.size, new.size)
        self.assertTrue(T.verify_consistency(old.root, old.size,
                                             new.root, new.size, proof))
        inc = log.prove(1)
        self.assertTrue(T.verify_inclusion(digest(1), inc, binding=binding(1),
                                           expected_root=new.root,
                                           expected_size=new.size))
        self.assertFalse(T.verify_inclusion(digest(1), inc, binding=binding(9),
                                            expected_root=new.root,
                                            expected_size=new.size))


class TestGossip(unittest.TestCase):
    """最小 gossip：审计者把「我见过的旧树头 → 当前树头」连同证明转发。"""

    def setUp(self):
        self.signer = cert.Ed25519Signer.generate()
        self.keyring = {self.signer.keyid: self.signer.public_key}
        self.log = T.TransparencyLog()
        for i in range(4):
            self.log.append(digest(i))
        self.old_head = self.log.head(self.signer, ts="2026-11-01T00:00:00Z")
        for i in range(4, 9):
            self.log.append(digest(i))

    def test_signed_gossip_verifies_with_keyring(self):
        msg = self.log.gossip_message(self.old_head, signer=self.signer,
                                      ts="2026-11-02T00:00:00Z")
        self.assertEqual(msg["domain"], T.GOSSIP_DOMAIN)
        self.assertEqual(msg["older"]["size"], 4)
        self.assertEqual(msg["newer"]["size"], 9)
        ok, detail = T.verify_gossip(msg, self.keyring)
        self.assertTrue(ok)
        self.assertTrue(detail["signatures_checked"])
        self.assertEqual(detail["newer"]["root"], self.log.root())

    def test_unsigned_gossip_is_flagged_as_unverified(self):
        msg = self.log.gossip_message(self.old_head)     # 未签名新树头
        ok, detail = T.verify_gossip(msg)
        self.assertTrue(ok, "不给 keyring 时只验一致性")
        self.assertFalse(detail["signatures_checked"])
        # 给了 keyring 就必须两个树头都有签名 —— 无签名不得冒充日志承诺。
        ok, _ = T.verify_gossip(msg, self.keyring)
        self.assertFalse(ok)

    def test_tampered_newer_root_is_rejected(self):
        msg = self.log.gossip_message(self.old_head, signer=self.signer)
        bad = {**msg, "newer": {**msg["newer"], "root": digest(77)}}
        self.assertFalse(T.verify_gossip(bad, self.keyring)[0])

    def test_tampered_proof_is_rejected(self):
        msg = self.log.gossip_message(self.old_head, signer=self.signer)
        bad = {**msg, "consistency": {**msg["consistency"],
                                      "path": [digest(88)]}}
        self.assertFalse(T.verify_gossip(bad, self.keyring)[0])

    def test_same_prefix_fork_needs_head_comparison(self):
        # 两条延伸共享前 4 片：各自都能给出**合法**的一致性证明。单条证明
        # 分辨不出谁对谁错 —— split-view 的检出要求审计者**同时持有**两个
        # 同尺寸、不同根的树头（这正是 gossip 通道的外部义务，见设计文档）。
        prefix = [digest(i) for i in range(4)]
        other = log_with(prefix + [digest(i) for i in range(204, 209)])
        msg_a = self.log.gossip_message(self.old_head, signer=self.signer)
        msg_b = T.gossip_message(self.old_head, other.head(self.signer),
                                 other.consistency_proof(4, 9))
        self.assertTrue(T.verify_gossip(msg_a, self.keyring)[0])
        self.assertTrue(T.verify_gossip(msg_b, self.keyring)[0])
        self.assertEqual(msg_a["newer"]["size"], msg_b["newer"]["size"])
        self.assertNotEqual(msg_a["newer"]["root"], msg_b["newer"]["root"],
                            "同尺寸不同根 = 可检出的分叉（要靠比较，不靠单条证明）")
        # 把 A 的证明配到 B 的树头上必须失败：一致性证明只对**自己那条**新根成立。
        mixed = {**msg_a, "newer": msg_b["newer"]}
        self.assertFalse(T.verify_gossip(mixed, self.keyring)[0])

    def test_forged_proof_against_another_head_is_rejected(self):
        other = log_with([digest(i) for i in range(4, 9)])   # 前缀不同
        msg = T.gossip_message(self.old_head, self.log.head(self.signer),
                               other.consistency_proof(0, 5))
        self.assertFalse(T.verify_gossip(msg)[0])

    def test_previous_head_from_another_log_raises(self):
        fork = log_with([digest(100 + i) for i in range(4)])
        with self.assertRaises(T.TransparencyError):
            self.log.gossip_message(fork.head())

    def test_previous_head_larger_than_log_raises(self):
        with self.assertRaises(T.TransparencyError):
            self.log.gossip_message({"size": 99, "root": digest(1)})

    def test_empty_previous_head(self):
        empty = T.TransparencyLog()
        empty.append(digest(0))
        msg = empty.gossip_message({"size": 0, "root": None})
        self.assertIsNone(msg["older"]["root"])
        self.assertTrue(T.verify_gossip(msg)[0])

    def test_wrong_domain_is_rejected(self):
        msg = self.log.gossip_message(self.old_head, signer=self.signer)
        self.assertFalse(T.verify_gossip({**msg, "domain": "other"}, self.keyring)[0])
        self.assertFalse(T.verify_gossip(None)[0])
        self.assertFalse(T.verify_gossip({})[0])


if __name__ == "__main__":
    unittest.main()
