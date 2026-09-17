"""``match_search`` 的转移表（R10）：**逐输入对拍**，不是「跑一遍看着对」。

为什么要有这一组用例。``match_search`` 是参考层判定 ``pattern_block`` 的那条路径，
而 ``pattern_block`` 的判定要**与电路侧逐条一致** —— 这里错一个字符，链下与链上就
分叉，而分叉的表现是「证明验不过」，不是「这里报错」。R10 把它的最内层从
「每条边调一次 Python 写的二分（``_point_in_ranges``）」换成「预解包的
``bisect_right``」，理由是实测 ``pii_redaction_v1`` 的流式路径上
``_point_in_ranges`` 独占总耗时的 **42%**（504 万次调用 / 1.56 s）。

换法本身是等价变形，但「等价」这两个字必须被**证明**，不能靠读代码点头。这里用
两把独立的尺子：

1. ``_match_search_pre_r10`` —— R10 **之前**那段实现的逐字副本（就地放在本文件里，
   这样「旧行为」有一个长得像代码的记录，而不是一段描述）。它对**任何** spec 都
   成立，包括畸形的手工 spec。
2. ``nfa.match_search_naive`` —— 仓库已有的、**算法不同**的参考匹配器
   （每个起点做锚定尝试，O(n²)）。它与转移表共用「语义应当相同」这个前提，但
   实现路径完全不同，所以能抓住「旧实现本来就错」这一类。

> **为什么要两把**：单比第 1 把只能证明「没改坏」；单比第 2 把则会把
> 「旧实现与新实现同错」读成通过。两把一起，才既管住「改动」也管住「底子」。

还有一条同样要紧：**转移表得真的被走到**。若哪天 pattern 的区间变成「未排序」或
「同边内相交」，所有边都会退回 ``starts is None`` 那条慢分支 —— 那时上面那些对拍
**依然全绿**（因为退回的分支与旧实现逐字相同），而 R10 的收益已经悄悄归零。
所以这里另有一条断言：仓库里 6 条去重 pattern 的每一行都必须是快分支
（去重前是 8 处 ``pattern_block`` 约束 —— ``sk-[A-Za-z0-9]{16,}`` 在
``agent_content_v1`` 与 ``eu_ai_act_v1`` 各出现一次，是同一个串；去重掉的是
重复的输入，不是覆盖面）。

**这一组用例是被变异测试验过的**，不是写完看着绿就算数：把快分支里的
``bisect_right`` 换成 ``bisect_left``（一个只会让「精确落在区间端点上」的码点
分叉的改动），15,816 次比较里有 **11 处**立刻不等价。所以上面的「0 处不等价」
是一条会红的断言，不是恒真式。
"""

import json
import random
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl.core import nfa  # noqa: E402

PACKS_DIR = REPO / "policy_packs"


def pack_patterns() -> list:
    """7 个策略包里全部 ``pattern_block`` 的 pattern（去重、保序）。

    从包文件读，而不是抄一份常量：包改了，用例跟着改，不会留下一个
    「测的是上一版 pattern」的缺口。
    """
    seen, out = set(), []
    for path in sorted(PACKS_DIR.glob("*.json")):
        pack = json.loads(path.read_text(encoding="utf-8"))
        for rule in pack.get("rules", []):
            if rule.get("kind") != "pattern_block":
                continue
            pats = rule.get("patterns") or (rule.get("params") or {}).get("patterns") or []
            for p in pats:
                if p not in seen:
                    seen.add(p)
                    out.append(p)
    return out


def _match_search_pre_r10(spec: dict, text: str) -> bool:
    """R10 之前 ``match_search`` 的逐字副本（含它自己那次 ``cur & accept``）。

    只读地放这里当「旧行为」的锚：新实现必须与它在**每一次**输入上给出同一个
    布尔值。-- 它调的是 ``_point_in_ranges``，那条路 R10 没有删（``_anchored_end``
    还在用），所以这份副本至今是活的、不是一段死引用。
    """
    closure = nfa._closure_table(spec)
    states = spec["states"]
    accept = frozenset(spec["accept"])

    cur = set(closure[spec["start"]])
    if cur & accept:
        return True
    for ch in text:
        cp = ord(ch)
        nxt = set()
        for s in cur:
            for e in states[s]["edges"]:
                if nfa._point_in_ranges(cp, e["ranges"]):
                    nxt.update(closure[e["to"]])
        nxt.update(closure[spec["start"]])
        cur = nxt
        if cur & accept:
            return True
    return False


def fresh_compile(pattern: str) -> dict:
    """绕开缓存编译一次 —— 用作「没被任何人碰过」的对照。

    与 ``tests/test_nfa_cache.py`` 里同名函数同形：**「刚编译出来不该有记忆表」
    是对代码的断言，不是对用例执行顺序的断言**，所以必须真拿一份新鲜的，
    而不是赌自己先跑。
    """
    nfa.compile_pattern.cache_clear()
    try:
        return nfa.compile_pattern(pattern)
    finally:
        nfa.compile_pattern.cache_clear()   # 不留一个「只有本条用例碰过」的状态


def corpus(alphabet: str, max_len: int) -> list:
    """``alphabet`` 上长度 0..max_len 的**全枚举**（这是「穷举语料」的字面意思）。"""
    out = [""]
    frontier = [""]
    for _ in range(max_len):
        frontier = [s + c for s in frontier for c in alphabet]
        out.extend(frontier)
    return out


class TestTransitionTableIsEquivalent(unittest.TestCase):
    """新实现 ≡ 旧实现 ≡ 朴素参考器，逐输入。"""

    def setUp(self):
        self.patterns = pack_patterns()
        self.specs = [(p, nfa.compile_pattern(p)) for p in self.patterns]
        rng = random.Random(20260917)
        wide = "abzAZ09@. -_+/\\[]{}()*?^$|\t\n"
        # 语料三块：小字母表全枚举（短串，穷举「边界形状」）+ 宽字母表随机
        # （中长串，覆盖真实文本的混杂）+ 逐条 pattern 的「几乎命中」串。
        texts = corpus("a@.", 4)
        texts += ["".join(rng.choice(wide) for _ in range(rng.randint(0, 32)))
                  for _ in range(2500)]
        texts += ["sk-" + "A" * k for k in (1, 15, 16, 17, 40)]
        texts += ["Bearer " + "x" * k for k in (1, 15, 16, 17, 40)]
        texts += ["+1 (555) 123-4567", "a@b.co", "zzz", "z" * 120, "é中\U0001f600"]
        self.texts = texts

    def test_the_corpus_is_not_a_no_op(self):
        """下界，不是等式：语料或包被人为缩没了，上面那条对拍会「全绿」得毫无意义。

        这是本仓反复栽过的那个坑（「空集合上全绿」）。包**加** pattern 不该让这条红，
        所以只写下界。
        """
        self.assertGreaterEqual(len(self.specs), 6, "读到的 pattern 变少了")
        self.assertGreaterEqual(len(self.texts), 2000, "语料变少了")
        self.assertGreaterEqual(
            len(self.specs) * len(self.texts), 10000,
            "逐输入比较的**规模**掉下来了 —— 覆盖率不是靠「跑过了」说的")

    def test_matches_the_pre_r10_implementation(self):
        """**逐输入**等于 R10 之前那段实现 —— 差异必须是 0，不是「少」。"""
        self.assertTrue(self.specs, "一个 pattern 都没读到，这一条会退化成空断言")
        bad = []
        for pat, spec in self.specs:
            for t in self.texts:
                if nfa.match_search(spec, t) != _match_search_pre_r10(spec, t):
                    bad.append((pat, t))
        self.assertEqual(bad[:5], [], f"{len(bad)} 处与 R10 之前不等价（前 5 条如上）")

    def test_matches_the_naive_reference_matcher(self):
        """同时等于**算法不同**的 ``match_search_naive``（它不会跟着转移表一起错）。

        O(n²)，所以只喂短语料 —— 覆盖的是「每个起点都要试」的边界，不是长度。
        """
        short = [t for t in self.texts if len(t) <= 24]
        for _, spec in self.specs:
            for t in short:
                self.assertEqual(nfa.match_search(spec, t),
                                 nfa.match_search_naive(spec, t),
                                 f"与朴素参考器不一致：{t!r}")

    def test_plain_dict_spec_takes_the_same_path(self):
        """手工构造的普通 dict spec（走的是「每次现算转移表」那条路）同样等价。"""
        for _, spec in self.specs:
            plain = json.loads(json.dumps(spec))
            self.assertIs(type(plain), dict)
            for t in self.texts[:400]:
                self.assertEqual(nfa.match_search(plain, t),
                                 _match_search_pre_r10(plain, t),
                                 f"普通 dict spec 上与旧实现不一致：{t!r}")


class TestTheFastPathIsActuallyTaken(unittest.TestCase):
    """**不变量得真的成立**，否则上面那些对拍只是一条恒真断言。"""

    def test_every_edge_of_every_pack_pattern_uses_the_fast_branch(self):
        """仓库里每条 pattern 的每一行都必须走 ``bisect_right`` 那支。"""
        slow, total = [], 0
        for pat in pack_patterns():
            for i, rows in enumerate(nfa._transition_table(nfa.compile_pattern(pat))):
                for j, (starts, _ends, _cl) in enumerate(rows):
                    total += 1
                    if starts is None:
                        slow.append((pat, i, j))
        # 下界同上：真到了「零条边」的地步，这条会先于 slow 断言红。
        self.assertGreaterEqual(total, 100, "建出来的转移表几乎是空的")
        self.assertEqual(slow, [],
                         "有边退回了 _point_in_ranges 慢分支 —— 对拍依然会全绿，"
                         "但 R10 的收益已经归零。见本文件模块 docstring。")

    def test_unsorted_ranges_fall_back_but_stay_equivalent(self):
        """一条**故意做错**的 spec 会被判成慢分支 —— 这条证明上面那条不是恒真。

        用一个「区间未排序」的手工 spec：这类输入在旧实现下本来就是未定义行为
        （``_point_in_ranges`` 的 docstring 要求「已排序」），R10 也不去替它
        「顺手修好」—— 新旧必须**错得一样**。
        """
        built = {"start": 0, "accept": [1],
                 "states": [{"eps": [], "edges": [
                     {"to": 1, "ranges": [[200, 300], [10, 20]]}]},
                     {"eps": [], "edges": []}]}
        rows = nfa._transition_table(built)
        self.assertIsNone(rows[0][0][0], "未排序的区间没有被判成慢分支")
        for t in ["a", "", "zzz", "\x14", "\xc8"]:
            self.assertEqual(nfa.match_search(built, t),
                             _match_search_pre_r10(built, t),
                             f"慢分支上与旧实现不一致：{t!r}")

    def test_overlapping_ranges_within_one_edge_fall_back(self):
        """同一条边内**区间相交**也要退回 —— 那种输入下 ``bisect`` 会给出**不同**答案。

        例：``ranges=[[10, 300], [15, 16]]``、``cp=100``。逐条二分在第一条就命中；
        而 ``bisect_right(starts, 100)-1`` 落在第二条上、``100 <= 16`` 不成立，
        于是判决相反。所以这一条不是防御性代码，是**真的会分叉**的那一类。
        """
        built = {"start": 0, "accept": [1],
                 "states": [{"eps": [], "edges": [
                     {"to": 1, "ranges": [[10, 300], [15, 16]]}]},
                     {"eps": [], "edges": []}]}
        rows = nfa._transition_table(built)
        self.assertIsNone(rows[0][0][0], "相交的区间没有被判成慢分支")
        for cp in (10, 15, 100, 300, 301, 9):
            t = chr(cp)
            self.assertEqual(nfa.match_search(built, t),
                             _match_search_pre_r10(built, t), f"cp={cp}")


class TestTransitionTableMemo(unittest.TestCase):
    """转移表的记忆化：与 ``closure_memo`` 同款（挂在 slot 上，不进 dict 内容）。"""

    def test_memo_is_populated_and_reused(self):
        spec = fresh_compile(pack_patterns()[0])
        self.assertIsNone(spec.trans_memo, "刚编译出来的 spec 不该已经有转移表")
        first = nfa._transition_table(spec)
        self.assertIsNotNone(spec.trans_memo, "转移表没有挂到 spec 上，缓存没生效")
        self.assertIs(first, nfa._transition_table(spec))

    def test_plain_dict_spec_is_not_memoized(self):
        """手工构造的普通 dict **不**被缓存 —— 不为了性能改动对外行为面。"""
        plain = json.loads(json.dumps(nfa.compile_pattern(pack_patterns()[0])))
        nfa._transition_table(plain)
        self.assertFalse(hasattr(plain, "trans_memo"),
                         "普通 dict 上不该出现 trans_memo")

    def test_consumers_do_not_mutate_the_shared_transition_table(self):
        """共享的表被谁就地改一下就是「静默判错」，所以比一次内容。

        转移表里装的是**列表**（``starts`` / ``ends``）—— 比 ``closure_memo`` 的
        frozenset 更容易被就地改，所以这条不是照抄。
        """
        pat = pack_patterns()[0]
        spec = nfa.compile_pattern(pat)
        table = nfa._transition_table(spec)
        snapshot = [[(None if s is None else list(s), list(e), sorted(c))
                     for s, e, c in rows] for rows in table]
        for t in ["a@b.co", "", "z" * 40, "sk-" + "A" * 20]:
            nfa.match_search(spec, t)
        after = [[(None if s is None else list(s), list(e), sorted(c))
                  for s, e, c in rows] for rows in nfa._transition_table(spec)]
        self.assertEqual(snapshot, after, "有消费者就地改动了共享的转移表")


if __name__ == "__main__":
    unittest.main()
