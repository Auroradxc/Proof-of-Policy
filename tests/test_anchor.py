"""锚定账本（policydsl.anchor）的单元测试。

聚焦默认的**文件账本**后端：每条记录链接上一条记录的哈希（``prev``），
``verify_ledger`` 重算整条链。这里验证链接正确、可按下标查找、以及「改动
历史记录必被发现」——这是证书「仅追加、防篡改」承诺的底线。
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import anchor  # noqa: E402


class TestAnchorLedger(unittest.TestCase):
    """文件账本的追加、链接、查找与防篡改。"""

    def setUp(self):
        # 每个用例用独立临时目录，避免账本互相污染
        self.tmp = tempfile.TemporaryDirectory()
        self.ledger = Path(self.tmp.name) / "ledger.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    # 哈希链的关键不变量：首条 prev=genesis，之后 prev=上一条 hash，seq 递增。
    def test_append_and_verify_chain(self):
        e1 = anchor.append_anchor(self.ledger, "d1", {"policy": "p"}, "t1")
        e2 = anchor.append_anchor(self.ledger, "d2", ts="t2")
        e3 = anchor.append_anchor(self.ledger, "d3", ts="t3")
        self.assertEqual(e1["prev"], anchor.GENESIS)
        self.assertEqual(e2["prev"], e1["hash"])
        self.assertEqual(e3["seq"], 2)
        ok, reason = anchor.verify_ledger(self.ledger)
        self.assertTrue(ok, reason)
        self.assertEqual(len(anchor.read_ledger(self.ledger)), 3)

    # 按 digest 查档：命中返回记录，未登记返回 None（上层据此判断是否已锚定）。
    def test_find_anchor(self):
        anchor.append_anchor(self.ledger, "d1")
        anchor.append_anchor(self.ledger, "d2")
        self.assertIsNotNone(anchor.find_anchor(self.ledger, "d2"))
        self.assertIsNone(anchor.find_anchor(self.ledger, "nope"))

    # 防篡改核心用例：直接改写历史条目内容（prev/hash 未同步更新）必须被识别。
    def test_tamper_detected(self):
        anchor.append_anchor(self.ledger, "d1")
        anchor.append_anchor(self.ledger, "d2")
        raw = self.ledger.read_text(encoding="utf-8").splitlines()
        raw[0] = raw[0].replace('"d1"', '"dX"')  # 篡改历史记录
        self.ledger.write_text("\n".join(raw) + "\n", encoding="utf-8")
        ok, reason = anchor.verify_ledger(self.ledger)
        self.assertFalse(ok)
        self.assertIn("tampered", reason)

    # 未配置 RPC/合约时的便捷入口必须显式报错，避免调用方误以为已完成链上锚定。
    #
    # 抛的必须是 `AnchorError` 而非 `NotImplementedError`：全仓库所有锚定错误的
    # 消费点都按 `AnchorError` 捕获（verify_cert / verify_session / proof_service /
    # deploy_anchor / service.failure_reason），照文档写的调用方接不住后者。
    # 一致性本身由 `TestUnconfiguredTypeConsistency` 钉住 —— 这条只钉「会报错」。
    def test_on_chain_unconfigured_raises(self):
        old = dict(os.environ)
        for k in (anchor.ENV_RPC, anchor.ENV_CONTRACT):
            os.environ.pop(k, None)
        try:
            with self.assertRaises(anchor.AnchorError):
                anchor.anchor_on_chain("digest")
        finally:
            os.environ.clear()
            os.environ.update(old)


class TestUnconfiguredTypeConsistency(unittest.TestCase):
    """「要上链但没配」这一个条件，两个入口必须给**同一种**异常。

    这是 c6 修的东西。原先 ``backend_from_env(require=True)`` 抛 ``AnchorError``、
    ``anchor_on_chain`` 抛 ``NotImplementedError`` —— 同一条件两种类型，而全仓库
    所有锚定错误的消费点只捕 ``AnchorError``。下面两条断言分别钉住「类型相同」
    与「消息相同」，任一处再分叉都会红。
    """

    def _unconfigured(self):
        """在 rpc/contract 都清空的环境里跑；返回两个入口各抛出的异常。"""
        old = dict(os.environ)
        for k in (anchor.ENV_RPC, anchor.ENV_CONTRACT):
            os.environ.pop(k, None)
        try:
            with self.assertRaises(anchor.AnchorError) as a:
                anchor.backend_from_env(require=True)
            with self.assertRaises(anchor.AnchorError) as b:
                anchor.anchor_on_chain("ab" * 32)
        finally:
            os.environ.clear()
            os.environ.update(old)
        return a.exception, b.exception

    # 两者抛出的类型必须完全一致（而不是「都继承自 RuntimeError」这种弱断言）。
    def test_same_type(self):
        e1, e2 = self._unconfigured()
        self.assertIs(type(e1), type(e2))
        self.assertIs(type(e1), anchor.AnchorError)

    # 消息也必须一字不差：各写各的就还有分叉的余地。
    def test_same_message(self):
        e1, e2 = self._unconfigured()
        self.assertEqual(str(e1), str(e2))

    # 这条是**反例对照**：证明上面两条断言不是恒真的 —— `NotImplementedError`
    # 确实不是 `AnchorError`，所以「改成 AnchorError」是**真的改了行为**，
    # 而不是把一个已经成立的性质又断言了一遍。
    def test_not_implemented_error_would_not_be_caught(self):
        self.assertFalse(issubclass(NotImplementedError, anchor.AnchorError))
        try:
            raise NotImplementedError("on-chain anchoring backend not configured")
        except anchor.AnchorError:
            self.fail("`except anchor.AnchorError` 竟然接住了 NotImplementedError")
        except NotImplementedError:
            pass  # 这就是修之前的样子：写了文档里那个 except 的调用方接不住。


if __name__ == "__main__":
    unittest.main()
