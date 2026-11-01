"""透明日志原型（``policydsl.evidence.transparency``）的单元测试。

覆盖任务要求的五类：追加、根变化、包含证明、篡改、重放。另加三类**边界**，
因为它们是把「只追加」与「可验证」分开的地方：

* 空日志没有根（不返回假值）；
* 叶子绑定（F-3）—— 默认只绑证书，给了 ``binding`` 才绑被交付工件；
* 树头签名（F-L 的雏形）—— 未签名头不得被当作日志承诺。

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


if __name__ == "__main__":
    unittest.main()
