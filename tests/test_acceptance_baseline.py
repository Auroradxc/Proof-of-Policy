"""等效性基线：每一次 push 都验「可观察行为没变」。

这是 ``scripts/verify/acceptance.py`` 的**常驻消费者**。脚本本身只是采集器
（``--snapshot`` / ``--verify``），照仓库的惯例，光有脚本等于没人跑它 ——
``docs/development.md`` §4.3 记的四种「不响的失败」里就有这一类：脚本在，
但要靠谁想起来。所以基线放进单测，跟着 ``unittest discover`` 走。

判据是**逐路径一致**，而不是「大致相同」。基线里钉住的是七面（见脚本 docstring）：
跨层契约（含 ``policy_hash``）、两条判定路径的完整结论、畸形输入的**异常类型与
文案**、流式证书序列、两个 CLI 子命令、门面导入面。

**变红了怎么办。** 先分清两类：

* **不该变的变了** —— 那是回归，改代码。这也是这个文件存在的全部理由。
* **有意变更** —— 比如谁改了策略包（``policy_hash`` 必然变）、改了报错文案。
  此时人工确认后重新采集，把快照 diff 连同代码一起提交::

      python3 scripts/verify/acceptance.py --snapshot tests/acceptance_baseline.json
      python3 scripts/verify/acceptance.py --verify   tests/acceptance_baseline.json

  快照**不判断该不该变**，它只保证变了一定有人看见 —— 这份「看见」正是
  「等效替代被证明」与「变更被承认」之间的那条分界线。
"""

import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(REPO / "scripts"))
from _bootstrap import bootstrap  # noqa: E402

bootstrap()  # 把 5 个脚本组装进 sys.path（与脚本自身走同一条引导）

import acceptance  # noqa: E402

BASELINE = Path(__file__).resolve().parent / "acceptance_baseline.json"

#: 差异最多列这么多条 —— 差异成千上万时，报告的可读性比完整性更重要。
_MAX_REPORTED = 30


class TestAcceptanceBaseline(unittest.TestCase):
    """现算七面，逐路径比对入库的基线。"""

    @classmethod
    def setUpClass(cls):
        cls.golden = json.loads(BASELINE.read_text(encoding="utf-8"))
        cls.fresh = acceptance.collect()

    def test_baseline_covers_every_face(self):
        """基线必须覆盖 :data:`acceptance.FACES` 的每一面 —— 空集合上全绿没有意义。

        这一条防的是「基线被换成了只剩一面的小文件」：那样下面的比对测试
        照样会通过，而它其实什么都没验。
        """
        self.assertEqual(sorted(self.golden), sorted(acceptance.FACES))
        self.assertEqual(sorted(self.fresh), sorted(acceptance.FACES))

    def test_observable_surfaces_are_unchanged(self):
        """七面逐路径一致；不一致就列出差异路径。"""
        diffs = acceptance._diff(self.golden, self.fresh, limit=_MAX_REPORTED)
        if diffs:
            shown = "\n".join(f"  {d}" for d in diffs)
            self.fail(
                f"可观察行为与 {BASELINE.name} 有 {len(diffs)} 处差异"
                f"（最多显示 {_MAX_REPORTED} 条）：\n{shown}\n"
                "不该变的 → 改代码；有意变的 → 人工确认后重新采集快照：\n"
                "  python3 scripts/verify/acceptance.py --snapshot "
                "tests/acceptance_baseline.json")

    def test_policy_hash_pins_every_pack(self):
        """每包的 ``policy_hash`` 都非空且与基线一致 —— 单独成一条，便于定位。

        它值得单独一条：``policy_hash`` 一变，所有已入库的证明工件集体失效，
        而上面那条「七面一致」只会告诉你「某某路径不同」。
        """
        for name in acceptance.PACKS:
            with self.subTest(pack=name):
                got = self.fresh["1_contract"][name]["sha256"]
                want = self.golden["1_contract"][name]["sha256"]
                self.assertEqual(got, want, f"{name} 的 policy_hash 变了")
                self.assertEqual(len(got), 64, f"{name} 的 policy_hash 不像 SHA-256")


if __name__ == "__main__":
    unittest.main()
