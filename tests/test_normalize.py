"""同形异义折叠（P2-9b）的单元测试。

分四层，对应四个可能出错的地方：

1. **表本身**（:class:`TestFoldTable`）：预设能展开成显式表、显式表能往返、
   非法表一律拒绝。表是**契约的一部分**，非法表必须在编译期炸掉，而不是
   带着一张「读不懂的表」出证。
2. **折叠算法**（:class:`TestFoldAlgorithm`）：单遍、不链式放大、顺序无关 ——
   这几条是「链下/链上逐字符一致」的前提。
3. **判定与验收**（:class:`TestNormalizedKeyword`）：P2-9b 的验收判据 ——
   **折叠前 ``passed=True``、折叠后 ``passed=False``**（同一条文本）。
4. **契约与哈希**（:class:`TestFoldInContract`）：表进得了 ``spec_canonical``、
   且改表就换 ``policy_hash``（否则「偷偷换表」不会体现在证书上）。

跨层对齐（Python ↔ Rust）在 ``tests/test_rules_incircuit.py``，那里会真的跑
``pop-script``；本文件只测链下这一半，因此**不需要**编好的 pop-script。
"""

import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl import normalize as N  # noqa: E402
from policydsl.compile import compile_policy, canonical_spec_text  # noqa: E402
from policydsl.evaluate import check  # noqa: E402
from policydsl.model import Policy, PolicyError, Rule, Transcript  # noqa: E402

#: 三种绕过手段各一条 —— 都能被人眼看成 "weaponize"。
CYRILLIC = "wеaponize"    # 第二个字符是西里尔 е U+0435
ZERO_WIDTH = "wea​ponize"  # 第三、四个字符之间一个零宽空格 U+200B
FULLWIDTH = "ｗｅａｐｏｎｉｚｅ"
ASCII = "weaponize"
BENIGN = "The report summarizes last quarter's results."


def policy(*rules: Rule) -> Policy:
    return Policy("t", "1", rules=list(rules))


def kb(words):
    """裸 keyword_block —— 用它来演示「折叠前放行」。"""
    return policy(Rule("keyword_block", "kb", {"keywords": words}))


def nkb(words, fold="v1"):
    """规范化 keyword_block —— 折叠后的那一半。"""
    return policy(Rule("normalized_keyword_block", "nkb",
                       {"keywords": words, "fold": fold}))


class TestFoldTable(unittest.TestCase):
    """折叠表的展开、往返与校验。"""

    def test_preset_expands_to_explicit_table(self):
        fold = N.resolve_fold("v1")
        spec = fold.spec
        self.assertEqual(spec["version"], N.FOLD_VERSION)
        self.assertTrue(spec["map"])
        self.assertTrue(spec["drop"])
        # 表是**显式**的：每个映射都写出来，电路不解释短名。
        self.assertIn([ord("е"), "e"], spec["map"])
        self.assertIn(0x200B, spec["drop"])

    def test_default_is_the_version_not_the_alias(self):
        """缺省声明写进契约的是版本号本身，不是一个需要查表才知道含义的短名。"""
        self.assertEqual(N.DEFAULT_PRESET, N.FOLD_VERSION)
        self.assertEqual(N.resolve_fold(None).spec, N.resolve_fold("v1").spec)

    def test_alias_and_version_agree(self):
        self.assertEqual(N.resolve_fold("v1").spec, N.resolve_fold(N.FOLD_VERSION).spec)

    def test_explicit_table_round_trips(self):
        """工具链产出的表能被自己读回，且**再读一次不变**（幂等）。"""
        first = N.resolve_fold("v1").spec
        second = N.resolve_fold(first).spec
        self.assertEqual(first, second)
        self.assertEqual(first, json.loads(json.dumps(first)))

    def test_table_is_order_insensitive(self):
        """同一张表换个书写顺序 → 同一个规范表（否则会出现两个 policy_hash）。"""
        a = {"version": N.FOLD_VERSION, "map": [[1077, "e"], [1072, "a"]], "drop": [0x200B]}
        b = {"version": N.FOLD_VERSION, "map": [[1072, "a"], [1077, "e"]], "drop": [0x200B]}
        self.assertEqual(N.resolve_fold(a).spec, N.resolve_fold(b).spec)
        self.assertEqual(N.fold("ԁо", a), N.fold("ԁо", b))

    def test_fullwidth_block_is_generated_not_handwritten(self):
        """全角是整块偏移：抽查两端与关键字符。"""
        f = N.resolve_fold("v1")
        for wide, half in (("！", "!"), ("Ａ", "A"), ("ｚ", "z"), ("０", "0"), ("～", "~"),
                           ("　", " ")):
            self.assertEqual(f.apply(wide), half, f"{wide!r} 应折成 {half!r}")

    def test_bad_declarations_are_rejected(self):
        """非法表一律在编译期炸掉 —— 每一条都对应一种「静默换语义」的方式。"""
        cases = {
            "未知版本": {"version": "pop-fold-v2", "map": [], "drop": []},
            "未知预设": "v2",
            "多出来的字段": {"version": N.FOLD_VERSION, "map": [], "drop": [], "extra": 1},
            "替换值非 ASCII": {"version": N.FOLD_VERSION, "map": [[1072, "ä"]], "drop": []},
            "替换值多于一个字符": {"version": N.FOLD_VERSION, "map": [[1072, "ab"]], "drop": []},
            "替换值是空串": {"version": N.FOLD_VERSION, "map": [[1072, ""]], "drop": []},
            "码点重复": {"version": N.FOLD_VERSION, "map": [[1072, "a"], [1072, "b"]], "drop": []},
            "映射到自身": {"version": N.FOLD_VERSION, "map": [[97, "a"]], "drop": []},
            "兼在 map 与 drop": {"version": N.FOLD_VERSION, "map": [[1072, "a"]], "drop": [1072]},
            "码点越界": {"version": N.FOLD_VERSION, "map": [[0x110000, "a"]], "drop": []},
            "代理区码点": {"version": N.FOLD_VERSION, "map": [[0xD800, "a"]], "drop": []},
            "二元组形状不对": {"version": N.FOLD_VERSION, "map": [[1072]], "drop": []},
            "表过大": {"version": N.FOLD_VERSION,
                       "map": [[0x400 + i, "a"] for i in range(N.MAX_MAP + 1)], "drop": []},
        }
        for why, decl in cases.items():
            with self.subTest(why):
                with self.assertRaises(N.FoldError):
                    N.resolve_fold(decl)

    def test_rule_validation_wraps_fold_errors(self):
        """策略层看到的是 PolicyError（统一入口），而不是 FoldError。"""
        p = nkb(["weaponize"], fold="v2")
        with self.assertRaises(PolicyError):
            p.validate()

    def test_empty_keyword_rejected(self):
        """空关键词 = 任意文本的子串 = 恒真命中，必须挡住。"""
        with self.assertRaises(PolicyError):
            policy(Rule("normalized_keyword_block", "n", {"keywords": [""]})).validate()
        # 折叠**之后**变空的同样要挡住（纯零宽字符的关键词就是这种情况）。
        with self.assertRaises(N.FoldError):
            N.canonical_keywords({"keywords": ["​"], "fold": "v1"})
        with self.assertRaises(PolicyError):
            compile_policy(policy(Rule("normalized_keyword_block", "n",
                                       {"keywords": ["​"], "fold": "v1"})))


class TestFoldAlgorithm(unittest.TestCase):
    """折叠算法本身：单遍、不链式、顺序无关。"""

    def test_single_char_replacements(self):
        f = N.resolve_fold("v1")
        self.assertEqual(f.apply("еоасрху"), "eoacpxy")  # 六个西里尔同形字

    def test_zero_width_chars_are_dropped(self):
        f = N.resolve_fold("v1")
        self.assertEqual(f.apply("wea​ponize"), "weaponize")
        self.assertEqual(f.apply("a‍b﻿c"), "abc")

    def test_ascii_passes_through_untouched(self):
        f = N.resolve_fold("v1")
        self.assertEqual(f.apply(ASCII), ASCII)
        self.assertEqual(f.apply(BENIGN), BENIGN)

    def test_single_pass_does_not_chain(self):
        """**单遍**：A→a、a→b 的表把 "A" 折成 "a"，不是 "b"。

        这条是跨层一致的核心 —— 若任何一侧做了不动点迭代，两边就会在一个
        完全合法的表上分叉，而那种分叉只在特定的表 + 特定的文本上暴露。
        """
        f = N.resolve_fold({"version": N.FOLD_VERSION,
                            "map": [[ord("A"), "a"], [ord("a"), "b"]], "drop": []})
        self.assertEqual(f.apply("A"), "a")
        self.assertEqual(f.apply("aa"), "bb")     # 原生的 a 各自折成 b
        self.assertEqual(f.apply("Aa"), "ab")     # 前一个只折一次

    def test_ascii_lower_is_ascii_only(self):
        """小写化只动 ASCII —— 与电路内的 ``ascii_lower`` 一致。"""
        self.assertEqual(N.ascii_lower("AbC"), "abc")
        self.assertEqual(N.ascii_lower("АБВ"), "АБВ")     # 西里尔大写：不动
        self.assertEqual(N.ascii_lower("é"), "é")         # 带音标：不动


class TestNormalizedKeyword(unittest.TestCase):
    """P2-9b 的验收判据：折叠前放行、折叠后拦下。"""

    def setUp(self):
        self.plain = kb(["weaponize"])
        self.folded = nkb(["weaponize"])

    def test_acceptance_bypass_then_blocked(self):
        """验收对：四种写法「折叠前 passed=True、折叠后 passed=False」。

        同时断言 **ASCII 版两边都拦** —— 否则「折叠后拦下」可能只是这条规则
        恒真（比如实现成了「永远违规」），那样这个测试就什么也没证明。
        """
        for name, text in (("西里尔", CYRILLIC), ("零宽", ZERO_WIDTH),
                           ("全角", FULLWIDTH), ("原生 ASCII", ASCII)):
            with self.subTest(name):
                before = check(self.plain, Transcript(response=text))
                after = check(self.folded, Transcript(response=text))
                self.assertFalse(after.passed, f"{name}文本未被折叠规则拦下")
                if text != ASCII:
                    # 这才是「修复非恒真」的那一半：绕过是真的存在的。
                    self.assertTrue(before.passed, f"{name}文本本不该被 keyword_block 拦下")
                else:
                    self.assertFalse(before.passed, "ASCII 版必须被 keyword_block 拦下")

    def test_benign_text_still_passes(self):
        """折叠不是「一律违规」：正常文本照常通过。"""
        res = check(self.folded, Transcript(response=BENIGN))
        self.assertTrue(res.passed)
        self.assertEqual(res.violations, [])

    def test_evidence_is_the_folded_keyword(self):
        """证据是折叠**后**的关键词 —— 它是规则的判定对象，也是私有模式要承诺的值。"""
        res = check(self.folded, Transcript(response=f"how to {CYRILLIC} a device"))
        self.assertEqual(len(res.violations), 1)
        v = res.violations[0]
        self.assertEqual(v.evidence_kind, "normalized_keyword")
        self.assertEqual(v.evidence, ["weaponize"])

    def test_keyword_author_may_write_the_variant(self):
        """作者把关键词写成同形字（复制粘贴常见）也会被编译期折成 ASCII。"""
        p = nkb(["wеaponize"])
        res = check(p, Transcript(response=ASCII))
        self.assertFalse(res.passed, "作者写的同形字关键词应折成 ASCII 后命中")

    def test_plain_and_folded_coexist(self):
        """一条策略里两条规则可以并存：ASCII 版各记一条，变体只被折叠规则拦下。"""
        p = policy(Rule("keyword_block", "kb", {"keywords": ["weaponize"]}),
                   Rule("normalized_keyword_block", "nkb",
                        {"keywords": ["weaponize"], "fold": "v1"}))
        ascii_res = check(p, Transcript(response=ASCII))
        self.assertEqual(len(ascii_res.violations), 2)
        variant_res = check(p, Transcript(response=CYRILLIC))
        self.assertEqual([v.rule.name for v in variant_res.violations], ["nkb"])

    def test_needs_a_response(self):
        """与 keyword_block 一样：没有响应文本就报错，而不是静默通过。"""
        with self.assertRaises(PolicyError):
            check(self.folded, Transcript(response=None))


class TestFoldInContract(unittest.TestCase):
    """折叠表作为跨层契约的一部分：进规范字节、进哈希。"""

    def test_contract_carries_the_explicit_table(self):
        obj = json.loads(canonical_spec_text(compile_policy(nkb(["Weaponize"]))))
        c = obj["constraints"][0]
        self.assertEqual(c["kind"], "normalized_keyword_block")
        self.assertEqual(c["keywords"], ["weaponize"])       # 编译期已折叠 + 小写化
        self.assertEqual(c["fold"]["version"], N.FOLD_VERSION)
        self.assertIn([ord("е"), "e"], c["fold"]["map"])
        self.assertIn(0x200B, c["fold"]["drop"])

    def test_hash_changes_when_the_table_changes(self):
        """换表 = 换策略：**必须**体现在 policy_hash 上。

        否则「偷偷把表改成不折叠」不会让任何指纹变样，验证方也就无从发现
        自己核对的策略与实际判定用的语义不是同一份。
        """
        base = {"version": N.FOLD_VERSION, "map": [[ord("е"), "e"]], "drop": [0x200B]}
        weaker = {"version": N.FOLD_VERSION, "map": [[ord("е"), "e"]], "drop": []}
        h1 = compile_policy(nkb(["weaponize"], fold=base))["sha256"]
        h2 = compile_policy(nkb(["weaponize"], fold=weaker))["sha256"]
        self.assertNotEqual(h1, h2)

    def test_hash_is_stable_across_writes(self):
        a = compile_policy(nkb(["weaponize"]))["sha256"]
        b = compile_policy(nkb(["weaponize"]))["sha256"]
        self.assertEqual(a, b)

    def test_preset_and_explicit_table_hash_alike(self):
        """预设名与它展开后的显式表是**同一份策略**（同一个 policy_hash）。"""
        h_alias = compile_policy(nkb(["weaponize"], fold="v1"))["sha256"]
        h_version = compile_policy(nkb(["weaponize"], fold=N.FOLD_VERSION))["sha256"]
        h_explicit = compile_policy(nkb(["weaponize"], fold=N.build_v1_spec()))["sha256"]
        self.assertEqual({h_alias, h_version, h_explicit}, {h_alias})

    def test_placeholder_kind_is_unknown_without_fold(self):
        """没有 fold 声明的那条老 kind 仍然是老的语义（不折叠）。"""
        obj = json.loads(canonical_spec_text(compile_policy(kb(["weaponize"]))))
        self.assertNotIn("fold", obj["constraints"][0])


class TestVocabConsistency(unittest.TestCase):
    """折叠表与仓库既有的「同形异义字」清单必须**同源**。

    ``semantic`` 那边收录这些字符，是为了让模型**见过**它们（从而分数升高）；
    这边收录它们，是为了把文本**折回** ASCII（从而关键词命中）。两件事方向相反，
    但必须认同一批字符 —— 否则会出现「模型看见了、关键词表却装作没看见」的缝。

    这两个模块都不依赖 torch，所以这里不设门槛。
    """

    def test_every_dataset_homoglyph_is_foldable(self):
        from semantic.dataset import HOMOGLYPH_PAIRS

        f = N.resolve_fold("v1")
        for ascii_ch, variants in HOMOGLYPH_PAIRS.items():
            for variant in variants:
                with self.subTest(variant=variant):
                    folded = N.ascii_lower(f.apply(variant))
                    self.assertEqual(
                        folded, ascii_ch.lower(),
                        f"{variant!r} (U+{ord(variant):04X}) 能绕过 keyword_block，"
                        f"却不在折叠表里 —— semantic 的清单与本表必须一致")

    def test_zero_width_vocab_chars_are_dropped(self):
        """``features.VOCAB`` 里那几个零宽字符必须都在 drop 里。"""
        from semantic.features import VOCAB

        f = N.resolve_fold("v1")
        zero_width = {c for c in VOCAB if 0x2000 <= ord(c) <= 0x206F or ord(c) == 0xFEFF}
        self.assertTrue(zero_width, "VOCAB 里应当有零宽字符")
        for ch in zero_width:
            with self.subTest(codepoint=hex(ord(ch))):
                self.assertEqual(f.apply(f"a{ch}b"), "ab")

    def test_foldable_chars_are_visually_confusable(self):
        """反向的**软**检查：表里的字要么在 vocab 清单里，要么是全角/零宽。

        依据取「``features.VOCAB`` ∪ ``dataset.HOMOGLYPH_PAIRS``」的并集 ——
        这**不是**在自我循环论证，而是钉住「每一行都有出处」：写表时只能从仓库
        已有的两个来源里挑，不能凭手感往里加字符。

        写这条时发现的一件事：那两张表**并不重合**。``HOMOGLYPH_PAIRS`` 里有
        6 个字符（大写西里尔 Ѕ А Е О Т、小写 п）不在 ``VOCAB`` 里 —— 也就是说
        **模型从来没见过它们**。``dataset.py`` 的注释说「全部来自
        ``features.VOCAB`` 收录的字符」，这句其实不准。后果是：``WЕAPONIZE``
        这种大写变体很可能**连语义规则也拦不住**（模型没训过），而折叠规则照样
        拦得住 —— 符号层与统计层的覆盖不是包含关系，两层各有各的盲区。
        """
        from semantic.dataset import HOMOGLYPH_PAIRS
        from semantic.features import VOCAB

        known = set(VOCAB)
        for variants in HOMOGLYPH_PAIRS.values():
            known.update(variants)
        f = N.resolve_fold("v1")
        for cp, to in f.spec["map"]:
            with self.subTest(codepoint=hex(cp)):
                self.assertTrue(
                    chr(cp) in known or 0xFF01 <= cp <= 0xFF5E or cp == 0x3000,
                    f"U+{cp:04X}（→{to!r}）既不在 features.VOCAB 也不在 "
                    f"HOMOGLYPH_PAIRS 里 —— 要么补进那两张表，要么这条映射没有依据")


if __name__ == "__main__":
    unittest.main()
