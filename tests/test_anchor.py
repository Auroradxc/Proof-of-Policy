"""锚定账本（policydsl.anchor）的单元测试。

聚焦默认的**文件账本**后端：每条记录链接上一条记录的哈希（``prev``），
``verify_ledger`` 重算整条链。这里验证链接正确、可按下标查找、以及「改动
历史记录必被发现」——这是证书「仅追加、防篡改」承诺的底线。
"""

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
    def test_on_chain_stub_raises(self):
        with self.assertRaises(NotImplementedError):
            anchor.anchor_on_chain("digest")


if __name__ == "__main__":
    unittest.main()
