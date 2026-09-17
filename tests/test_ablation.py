"""匹配器消融实验（Pike VM vs 朴素 O(n²)）跨层开关的测试。

背景：``pattern_block`` 的模式在 Python 参考层和 Rust 电路层各有一份解释器，
Rust 侧还提供两种匹配算法——默认的 Pike VM（每步只推进一次、线性时间、不做
回溯）与朴素的 NFA 子集模拟（逐位置尝试、O(n²)，作为消融基线）。消融实验只有
在**两者吃同一份 NFA 且判定完全一致**时才有意义：因此这里既逐点比对两种匹配器
对同一语料的结果，也验证 ``match_mode`` 开关从 DSL 校验一路传导到 Rust 约束，
并且非法的 mode 会被快速拒绝（避免消融旋钮被误用成正式语义）。"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "bench"))     # bench_*.py 平铺在同一目录下

from policydsl.core import nfa, pii  # noqa: E402
from policydsl.core.compile import compile_policy  # noqa: E402
from policydsl.core.model import Policy, PolicyError, Rule  # noqa: E402
from policydsl.core.serialize import spec_canonical_text  # noqa: E402
from policydsl.paths import POP_SCRIPT  # noqa: E402

import bench_ablation as ba  # noqa: E402
import bench_cycles as bc  # noqa: E402

# 语料刻意覆盖真实 PII 模式与边界语法：量词（a+ / {2,4}）、分支、通配，
# 以及空串和无命中文本（验证「不命中」这条路径两实现也一致）。
PATTERNS = [
    r"[\w.+-]+@[\w-]+\.[\w.]+",
    r"sk-[A-Za-z0-9]{16,}",
    r"\+\d[\d\s-]{6,}",
    r"a+", r"(cat|dog)s?", r"b{2,4}", r"\d{2,4}-\d{2,4}", r"a.*b",
]
TEXTS = [
    "contact a@b.com now", "plain text", "sk-abcdefghijklmnopqrstuvwxyz",
    "colours", "a cat and 3 dogs", "123-45 xy", "aaab", "", "no match here at all",
]


class TestBenchCorpusParsers(unittest.TestCase):
    """基准脚本的命令行采样点解析：**只有一个定义，且是逗号分隔的**。

    这一条守的是一个真发生过的 bug：``bench_ablation.py`` 曾自带一份
    ``parse_ints`` 副本，把 ``replace(",", " ")`` 写成了 ``replace(";", " ")``
    —— 它自己的 docstring 举的例子 ``--ns 100,200,400,800`` 因此跑不过。
    两份副本放在两个文件里，谁也不会去对，而**没有测试**覆盖这两个函数，
    所以漂移一直没被发现。

    两条断言各管一半：

    * ``test_comma_separated_works`` —— 行为对（docstring 里的写法真能跑）；
    * ``test_single_definition`` —— 结构对（不可能再出现第二份）。只断言行为
      的话，将来某人在任一侧抄回一份**恰好对**的副本仍会静默通过；而只断言
      结构的话，「共用的那一个本身写错了」又没人管。
    """

    def test_comma_separated_works(self):
        """逗号、空格、混合三种写法都要能跑（文档里用的是逗号）。"""
        for spec, want in (("100,200,400,800", [100, 200, 400, 800]),
                           ("100 200", [100, 200]),
                           ("100, 200,300", [100, 200, 300]),
                           ("7", [7])):
            with self.subTest(spec=spec):
                self.assertEqual(bc.parse_ints(spec), want)
                self.assertEqual(bc.parse_ints(spec), ba.parse_ints(spec))

    def test_single_definition(self):
        """两个脚本引用的是**同一个**函数对象 —— 再抄一份出来就会红。"""
        self.assertIs(ba.parse_ints, bc.parse_ints,
                      "parse_ints 又出现第二份定义了；两处各写一遍就是漂移的温床"
                      "（见 docs/refactor-proposal.md §2.4.2 ③）")


class TestMatcherParity(unittest.TestCase):
    """消融前提：同一 NFA 上 Pike VM 与朴素匹配器的判定必须逐点相等。"""

    # 穷举 模式×文本 的组合；一旦出现分歧，说明其中一侧语义（而非性能）有 bug，
    # 消融数据也就不再可比。
    def test_pike_equals_naive(self):
        for pat in PATTERNS:
            spec = nfa.compile_pattern(pat)
            for t in TEXTS:
                with self.subTest(pattern=pat, text=t):
                    self.assertEqual(nfa.match_search(spec, t),
                                     nfa.match_search_naive(spec, t))


class TestModeWiring(unittest.TestCase):
    """``match_mode`` 从 DSL 到 Rust 约束的传导与校验（消融旋钮的接线）。"""

    # 默认必须是 pike（生产语义）。契约字节里**不出现** "mode"：Rust 侧
    # `SpecConstraint::PatternBlock` 对 mode 标了 #[serde(default)]，缺省即 pike。
    # 断言直接落在电路将要解析的那段字节上，而非某个中间映射。
    def test_default_is_pike(self):
        spec = compile_policy(Policy("p", "1", rules=[
            Rule("pattern_block", "pb", {"patterns": [pii.PII_PATTERNS["email"]]})]))
        self.assertNotIn("mode", spec["constraints"][0])
        self.assertNotIn('"mode"', spec_canonical_text(spec))

    # 显式指定 naive 时必须如实出现在契约字节里，否则电路仍会跑 pike，
    # 消融就测不到朴素路径。
    def test_naive_mode_propagates(self):
        spec = compile_policy(Policy("p", "1", rules=[
            Rule("pattern_block", "pb", {"patterns": [pii.PII_PATTERNS["email"]],
                                         "match_mode": "naive"})]))
        self.assertEqual(spec["constraints"][0]["mode"], "naive")
        self.assertIn('"mode":"naive"', spec_canonical_text(spec))

    # 未知 mode（如 "dfa"）要快速失败：避免旋钮拼错后静默回落到默认匹配器，
    # 让消融结果被错误归因。
    def test_bad_mode_rejected(self):
        with self.assertRaises(PolicyError):
            Policy("p", "1", rules=[Rule("pattern_block", "pb", {
                "patterns": ["a"], "match_mode": "dfa"})]).validate()


@unittest.skipUnless(POP_SCRIPT.exists(), "pop-script not built")
class TestRustNaivePath(unittest.TestCase):
    """zkVM 内的朴素匹配器必须与 pike 判定一致（宿主机侧检查，快）。

    用 ``pop-script --check`` 直接跑 Rust 实现（不生成证明），这样能在单元测试
    里以秒级成本覆盖真实的电路逻辑；二进制未构建时整体跳过。
    """

    # 同一文本分别以 pike / naive 跑一次 Rust 检查，返回检查结果。
    def _run_check(self, mode: str, text: str) -> dict:
        spec = compile_policy(Policy("p", "1", rules=[
            Rule("pattern_block", "pb", {"patterns": [pii.PII_PATTERNS["email"]],
                                         "match_mode": mode})]))
        vectors = {"vectors": [{"name": f"{mode}", "response": text,
                                "spec_canonical": spec_canonical_text(spec)}]}
        with tempfile.TemporaryDirectory() as tmp:
            vp, op = Path(tmp) / "v.json", Path(tmp) / "r.json"
            vp.write_text(json.dumps(vectors))
            subprocess.run([str(POP_SCRIPT), "--check", "--vectors", str(vp), "--out", str(op)],
                           cwd=str(REPO), check=True, capture_output=True, text=True)
            return json.loads(op.read_text())[0]

    # 命中（含邮箱）与未命中（含空串）两类输入都要一致：只比 passed 不够，
    # 还要比触发的规则名，防止「都判违规但归因不同」的假一致。
    def test_naive_matches_pike_on_hit_and_clean(self):
        for text in ["reach me at a@b.com", "no address here", ""]:
            pike = self._run_check("pike", text)
            naive = self._run_check("naive", text)
            self.assertEqual(pike["passed"], naive["passed"], text)
            self.assertEqual([v["rule"] for v in pike["violations"]],
                             [v["rule"] for v in naive["violations"]], text)


if __name__ == "__main__":
    unittest.main()
