"""``compile_pattern`` / ``_closure_table`` 的缓存（R3）：**共享一个对象是安全的**。

为什么要有这一组用例。改之前，每次调用 ``compile_pattern`` 都返回一个**全新的**
可变 dict；改完之后，同一个 pattern 永远返回**同一个对象**。这是本项目里第一次
出现「编译产物被多个调用方共享」——而它必须成立的前提是**谁都不改它**。

这个前提今天成立，但它是**隐式**的：四个消费者（``match_search`` / ``find_spans`` /
``anchored_full_match`` / ``mask_indices``）以及规范序列化都只读，读代码看得出来，
但将来任何人往里写一行「顺手规整一下 states」都不会报错 —— 只会让**别人**手里
那份悄悄变了。所以这里把它变成一条会红的断言，而不是一条注释。

第二条要钉的是**序列化**：缓存对象是个 dict 子类（为了挂 ``closure_memo``，
见 ``nfa._CompiledPattern`` 的说明）。子类若不慎改变了 ``json.dumps`` 的输出，
**跨层契约的规范字节就变了**，``policy_hash`` 跟着变 —— 那会让所有已入库的证明
与工件集体失效，而且是全链失效。所以逐字节比一次。
"""

import copy
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl.core import nfa, pii  # noqa: E402
from policydsl.core.compile import compile_policy  # noqa: E402
from policydsl.core.model import Policy, Rule  # noqa: E402
from policydsl.core.serialize import spec_canonical_text  # noqa: E402

PATTERN = pii.PII_PATTERNS["email"]
TEXT = "reach me at alice@example.com before noon"


def fresh_compile(pattern: str) -> dict:
    """绕开缓存编译一次 —— 用作「没被任何人碰过」的对照。

    清缓存是安全的：它只是个记忆化，清掉之后下次调用重新算，结果逐字节相同
    （这一点本身由 ``test_cache_does_not_change_the_compiled_bytes`` 钉住）。
    """
    nfa.compile_pattern.cache_clear()
    try:
        return nfa.compile_pattern(pattern)
    finally:
        nfa.compile_pattern.cache_clear()   # 不留一个「只有本条用例碰过」的状态


class TestCompilePatternCache(unittest.TestCase):
    """缓存命中同一对象，而对象本身与新鲜编译逐字节相同。"""

    def test_same_pattern_returns_the_same_object(self):
        """同一个 pattern 编译两次拿到**同一个**对象（缓存真的在起作用）。

        只断言 `==` 不够 —— 缓存没生效时两个等值的新对象也满足 `==`，
        用例会退化成恒真。
        """
        self.assertIs(nfa.compile_pattern(PATTERN), nfa.compile_pattern(PATTERN))

    def test_cache_does_not_change_the_compiled_bytes(self):
        """缓存对象与新鲜编译的规范字节**逐字节相同**（子类没有漏进序列化）。"""
        cached = json.dumps(nfa.compile_pattern(PATTERN), sort_keys=True)
        revived = json.dumps(fresh_compile(PATTERN), sort_keys=True)
        self.assertEqual(revived, cached)

    def test_cache_does_not_change_the_policy_hash(self):
        """整条链上再验一次：编译出的策略绑定哈希 `spec["sha256"]` 与新鲜编译相同。

        比的是**同一个策略**走缓存与不走缓存两条路 —— 若子类改变了规范字节，
        契约的 `sha256` 就会跟着变，而它正是证书里 `policy_hash` 的出处：
        已入库的证明会**集体**对不上。
        """
        policy = Policy("p", "1", rules=[
            Rule("pattern_block", "pb", {"patterns": [PATTERN]})])
        spec = compile_policy(policy)
        expected = compile_policy(policy)["sha256"]

        nfa.compile_pattern.cache_clear()               # 走「没有缓存可用」的那条路
        try:
            cold_spec = compile_policy(policy)
        finally:
            nfa.compile_pattern.cache_clear()

        self.assertEqual(cold_spec["sha256"], spec["sha256"])
        self.assertEqual(expected, spec["sha256"])
        self.assertEqual(spec_canonical_text(cold_spec), spec_canonical_text(spec))


class TestCachedSpecIsReadOnly(unittest.TestCase):
    """**把四个消费者都跑一遍，再与新鲜编译比** —— 谁改了缓存，这里就红。"""

    def test_consumers_do_not_mutate_the_cached_spec(self):
        """跑完四个消费者后的缓存对象，必须仍等于「没被碰过」的那一份。"""
        spec = nfa.compile_pattern(PATTERN)
        pristine = fresh_compile(PATTERN)

        # 四个消费者逐一跑过（同一个 spec 对象复用四次，正是共享场景）。
        nfa.match_search(spec, TEXT)
        nfa.find_spans(spec, TEXT)
        nfa.mask_indices([spec], TEXT)
        nfa.anchored_full_match(spec, TEXT, 13, 30)
        nfa.match_search_naive(spec, TEXT)

        self.assertEqual(
            pristine, spec,
            "有消费者就地改动了缓存的 spec —— 改的不只是它自己手里那份，"
            "而是所有调用方共享的那一份。见本文件模块 docstring。")
        # 闭包表挂在 slot 上、不在 dict 内容里，上面那条比不到 —— 单独比一次：
        # 它同样是共享的，被谁就地改一下就是「静默地判错」，不是报错。
        self.assertIsNotNone(spec.closure_memo, "消费者没走到闭包表？这一条就成了空断言")
        self.assertEqual(nfa._build_closure_table(spec), spec.closure_memo,
                         "有消费者改动了共享的 ε-闭包表")
        # 转移表（R10）同样是挂在 slot 上的共享状态，而且它装的是**列表**
        # （starts / ends），比 frozenset 更容易被就地改 —— 所以一并钉住。
        self.assertIsNotNone(spec.trans_memo, "消费者没走到转移表？这一条就成了空断言")
        recold = fresh_compile(PATTERN)
        self.assertEqual(nfa._transition_table(recold), spec.trans_memo,
                         "有消费者改动了共享的转移表")

    def test_repeated_calls_stay_equal(self):
        """同一份 spec 反复判同一段文本，结论必须稳定（不是「第一次对」）。"""
        spec = nfa.compile_pattern(PATTERN)
        first = nfa.match_search(spec, TEXT)
        for _ in range(20):
            self.assertEqual(first, nfa.match_search(spec, TEXT))
        self.assertTrue(first)


class TestClosureTableMemo(unittest.TestCase):
    """ε-闭包表的记忆化：命中时不重算，且结果与现算的一致。"""

    def test_memo_is_populated_and_reused(self):
        """第一次算完挂到 spec 上，第二次拿到的是**同一个**对象。

        用 ``fresh_compile`` 取「刚出炉」的那一份：缓存是**进程级**的，别的用例
        可能已经碰过 ``compile_pattern(PATTERN)`` 了 —— 那样一来本条的「刚编译出来
        不该有闭包表」就变成了用例执行顺序的断言，而不是代码的断言。
        """
        spec = fresh_compile(PATTERN)
        self.assertIsNone(spec.closure_memo, "刚编译出来的 spec 不该已经有闭包表")
        first = nfa._closure_table(spec)
        self.assertIsNotNone(spec.closure_memo, "闭包表没有挂到 spec 上，缓存没生效")
        self.assertIs(first, nfa._closure_table(spec))

    def test_memoized_table_equals_a_fresh_computation(self):
        """缓存下来的表与现算的逐项相等 —— 否则缓存就是把答案抄错了。"""
        spec = nfa.compile_pattern(PATTERN)
        memoized = nfa._closure_table(spec)
        self.assertEqual(nfa._build_closure_table(spec), memoized)

    def test_plain_dict_spec_is_not_memoized(self):
        """手工构造的普通 dict **不**被缓存 —— 不为了性能改动对外行为面。"""
        plain = json.loads(json.dumps(nfa.compile_pattern(PATTERN)))
        self.assertIs(type(plain), dict)
        self.assertEqual(nfa._build_closure_table(plain), nfa._closure_table(plain))
        self.assertFalse(hasattr(plain, "closure_memo"),
                         "普通 dict 上不该出现 closure_memo")


class TestSpecIsStillACopyableDict(unittest.TestCase):
    """契约对 spec 的其余期待：可深拷贝、可序列化往返。"""

    def test_deepcopy_is_independent(self):
        """``deepcopy`` 出来的是**独立**对象：改副本不影响缓存。

        docstring 里写了「需要变体就 deepcopy」，这一条保证那句话是真的 ——
        子类带 ``__slots__``，深拷贝走的是另一条路径，值得钉一下。
        """
        spec = nfa.compile_pattern(PATTERN)
        clone = copy.deepcopy(spec)
        self.assertEqual(spec, clone)
        self.assertIsNot(spec, clone)
        clone["start"] = 99999                    # 改副本
        self.assertNotEqual(99999, nfa.compile_pattern(PATTERN)["start"])

    def test_json_round_trip_preserves_the_spec(self):
        """``json`` 往返后逐字段相等（它是跨层契约，必须过得了这一关）。"""
        spec = nfa.compile_pattern(PATTERN)
        self.assertEqual(json.loads(json.dumps(spec)), spec)


if __name__ == "__main__":
    unittest.main()
