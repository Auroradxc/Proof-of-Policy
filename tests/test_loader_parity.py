"""策略加载器的**对拍基线**：11 份加载器在这 7 个包上是同一件事（R7 的前提）。

.. note:: ``differences`` 一节里的取值是 **``repr()`` 过的 Python 字面量**，不是 JSON
   —— 采集器要把它们当 dict 的键用（``''`` 与 ``"''"`` 必须能分开）。所以这里解析
   一律用 ``ast.literal_eval``。

``scripts/verify/loader_parity.py`` 的常驻消费者，形状与 ``tests/test_acceptance_baseline.py``
一致 —— 照仓库惯例，采集器光有脚本等于没人跑它（``docs/development.md`` §4.3 记的四种
「不响的失败」里就有这一类）。

**为什么这一条必须现在就有。** R7 要做的是把十六份策略加载器收敛成一份。收敛的每一步
都要能回答「新的和旧的等价吗」—— 而旧的那些**改完就没了**。所以顺序只能是
先采快照（本文件 + ``loader_parity_baseline.json``）、再动 R7、再用快照核。
快照是那次收敛唯一的活口。

**快照里有一处真分歧，不是噪声。** 7 个包上 11 份加载器给出**同一个** ``policy_hash``
（这正是 R7 在哈希这一层成立的证据），但**两种签名**：3 份把包里声明的 ``description``
带进 :class:`Policy`，8 份丢成 ``''``。

``description`` 不进 ``policy_hash``（``core/compile.py`` 的 ``STABLE_KEYS`` 里没有它）、
不进证书、CLI 也不打印 —— 对**当前所有可观察输出**是惰性的，所以这个分歧一直没人看见。
:meth:`TestDeclaredDivergence` 把它**点名**钉住：名单在一天，就是一天有人知道；谁改了它，
这里当场红。而「只此一处、且只在这一处」本身就是断言 —— 再冒出第二处分歧，同样当场红。

**R7 落地后怎么用这个文件。** 快照**不要重新采集**。R7 把那 11 份变成薄包装（或把
``LOADERS`` 表缩成 1 行 —— 那属于 R7 的提交）之后，:class:`TestLiveLoadersMatchSnapshot`
比对的东西自然从「11 份旧加载器」变成「收敛后的那一份」，而它比的**仍然是同一份快照**：
那一步就是等效替代的证明本身。

**R7 已经落地（2026-09-17），上面那句话照办了。** 11 份加载器全部改成
``Policy.from_dict`` 的一行委派，``LOADERS`` 表**保持 11 行**（标签留着，逐份比对才有
对象 —— 它们现在是同一个函数的 11 个入口，不是 11 份实现）。快照没重采，只按
:data:`DECLARED_R7_NORMALIZATION` **折算了一次再比**：R7 把 ``description`` 统一成
「带」，于是快照里那 8 份「丢」的记录要按这条归一改写成「带」。折算不是免检 ——
:meth:`TestLiveLoadersMatchSnapshot.test_the_live_delta_is_exactly_the_declared_normalization`
逐 ``(加载器, 包)`` 断言**差异恰好就是这一处**：除了 ``description`` 由 ``''`` 变成包里
那句，别的字段一个都不许动，``policy_hash`` 尤其不许动。

变红了怎么办，同 ``tests/test_acceptance_baseline.py``：**不该变的变了** → 改代码；
**有意变更** → 人工确认后重新采集（``--snapshot``），diff 连同代码一起提交。
但先读完上一段 —— 重新采集会**抹掉 R7 的比对依据**，采集器会拒绝一份采不到东西的快照，
却拦不住一份采得太少、因而证明不了什么的快照，:meth:`TestSnapshotShape` 补这一刀。
"""

import ast
import copy
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(REPO / "scripts"))
from _bootstrap import bootstrap  # noqa: E402

bootstrap()  # 5 个组目录进 sys.path（与脚本自身走同一条引导）

import loader_parity  # noqa: E402

BASELINE = Path(__file__).resolve().parent / "loader_parity_baseline.json"

#: 采集时**保留** ``description`` 的那几份（按标签排序）。其余 8 份丢成 ``''``。
#:
#: 名单是钉住的常量而非从快照现算：从快照现算的话，快照被重新采集过就自动跟着变，
#: 「有人动过这几份加载器」这件事就再也不会有人知道。
#:
#: .. note:: 这两个名单描述的是**快照当时**（R7 之前）的状态。R7 之后 11 份全都保留
#:   ``description`` —— 那处变化按 :data:`DECLARED_R7_NORMALIZATION` 折算，两个名单
#:   本身**不改**：改了就抹掉了「快照记的是什么」。
DESCRIPTION_KEEPERS = (
    "policydsl/__main__._load_policy",
    "scripts/prove/prove_multiparty.load_policy",
    "scripts/prove/prove_policy.load_policy",
)

#: R7 之前**丢掉** ``description`` 的那 8 份（= 全部 11 份减去上面 3 份）。
DESCRIPTION_DROPPERS = (
    "policydsl/proofs/compose._load_policy",
    "policydsl/proofs/multiparty._load_policy",
    "policydsl/proofs/session._load_policy",
    "policydsl/runtime/service.load_policy",
    "scripts/prove/compose_proof.load_policy",
    "scripts/prove/issue_cert.load_policy",
    "scripts/verify/verify_cert.load_policy",
    "scripts/verify/verify_session.load_policy",
)

#: ── R7 的**一处已声明归一** ─────────────────────────────────────────────────
#:
#: 内容是：``description`` 统一取**包内声明的那一句**。理由见 ``docs/dev-plan.md``
#: §5.7.7 末段 —— 这个字段存在就是为了承载包作者的声明，而 :class:`Policy` 的缺省值
#: 本就是 ``''``，**只有显式不传的加载器**才得到它；丢是信息丢失，不是省略。
#:
#: **为什么不直接重采快照**：重采会**抹掉 R7 的比对依据**（快照变成「一份加载器与
#: 它自己一致」）。采集器拦得住一份**采不到东西**的快照（覆盖守卫），却拦不住一份
#: 「采到了、但因此什么都证明不了」的快照 —— :meth:`TestSnapshotShape` 只是补了
#: 「≥2 份」这道下限。所以归一**写在消费方**，快照原样留着。
#:
#: 折算**不是免检**：归一后的快照与现算之间的差异被逐处断言（见
#: :meth:`TestLiveLoadersMatchSnapshot.test_the_live_delta_is_exactly_the_declared_normalization`），
#: 差异集必须**恰好**是这 3 处名字里那 8 份 × 7 个包的 ``description``，
#: 且只许 ``''`` → 包里那句。
DECLARED_R7_NORMALIZATION = "description 统一取包内声明的那一句（不再丢成 ''）"

#: 同一份输入喂给**每一次**采集，结论必须逐字相同 —— 快照里记的就是这一条。
_golden_cache = None
_fresh_cache = None


def golden() -> dict:
    """入库的快照（采集于收敛之前）。"""
    global _golden_cache
    if _golden_cache is None:
        _golden_cache = json.loads(BASELINE.read_text(encoding="utf-8"))
    return _golden_cache


def fresh() -> dict:
    """现算一份（跑真的加载器，≈0.5 s；两个用例类共用，只采一次）。"""
    global _fresh_cache
    if _fresh_cache is None:
        _fresh_cache = loader_parity.collect()
    return _fresh_cache


def _declared_description(pack: str) -> str:
    """包文件里写的那句 ``description``（归一的**目标值**，从包现读、不从快照取）。"""
    data = json.loads((REPO / "policy_packs" / pack).read_text(encoding="utf-8"))
    text = data.get("description")
    if not text:
        raise AssertionError(f"{pack} 里没有 description —— 这一处归一成了空断言")
    return text


def normalized_golden() -> dict:
    """快照按 :data:`DECLARED_R7_NORMALIZATION` **折算一次**后的形态。

    只改 ``policy.description`` 一个字段，且只改「原来是 ``''``」的那些记录 ——
    折算完把 ``judged`` / ``differences`` 用与采集器**同一个函数**重算，避免
    「归一了记录、忘了归一判据载荷」这种半截折算（那样比的是两个不同口径的东西，
    反而比不折算更容易假绿）。
    """
    out = copy.deepcopy(golden())
    for pack in out["packs"]:
        declared = _declared_description(pack)
        for rec in out["loaders"].values():
            entry = rec.get(pack)
            if entry and "policy" in entry and entry["policy"]["description"] == "":
                entry["policy"]["description"] = declared
    out["judged"] = loader_parity._judged(out["loaders"], out["packs"])
    out["differences"] = loader_parity._differences(out["loaders"], out["packs"])
    return out


def _coverage_of(report: dict) -> dict:
    return report["coverage"]


class TestSnapshotShape(unittest.TestCase):
    """先证明快照**查到了东西**，再谈它说了什么。

    「空集合上全绿」是普查工具的默认失败模式，本仓的文档链接普查与跨层常量比对
    各防过一遍。本工具的第一版正是这么坏的：子进程按绝对路径做键、父进程按文件名查，
    7 个包齐刷刷报出「1 种哈希」—— 看着是最理想的结果，其实一条都没查到。
    采集器已把「查到了几份」写进快照，这一组用例是它的**复核**。
    """

    def test_snapshot_covered_every_loader_on_every_pack(self):
        """每一份加载器 × 每一个包都要有记录，且没有整份失败的。"""
        self.assertFalse(
            [lab for lab, rec in golden()["loaders"].items()
             if "__loader_failed__" in rec],
            "快照里有整份没跑起来的加载器 —— 那份的「一致」是假的："
            f"{[lab for lab, rec in golden()['loaders'].items() if '__loader_failed__' in rec]}")
        for pack, cov in sorted(_coverage_of(golden()).items()):
            with self.subTest(pack=pack):
                self.assertGreater(cov["expected"], 0, f"{pack}: 一份加载器都没采")
                self.assertEqual(
                    cov["loaded"], cov["expected"],
                    f"{pack}: 只读到 {cov['loaded']}/{cov['expected']} 份。"
                    "没读到的那几份不会被比，它们的分歧也就不会现身。")

    def test_snapshot_recorded_enough_loaders_to_prove_a_convergence(self):
        """快照必须采到 **≥2 份**加载器 —— 只采到 1 份的话它什么也证明不了。

        这条防的是**重新采集**：R7 把十六份收敛成一份之后，若有人顺手把快照也重采一遍，
        快照就变成「一份加载器与它自己一致」，看着全绿，而「新旧等价」这个论断
        从此失去了全部依据。要重采，得先想清楚这个文件为什么存在。
        """
        n = len(golden()["loaders"])
        self.assertGreaterEqual(
            n, 2,
            f"快照里只有 {n} 份加载器。它证明不了「收敛前后等价」—— 若这是一次重采，"
            "请把它换回入库的那一版（git 里有）。")

    def test_every_pack_hashes_to_exactly_one_value(self):
        """逐包**只有一种** ``policy_hash`` —— 这就是 R7 的闸门所比的那一条。

        单独成一条（而不是并进「逐路径一致」）：它红了要说的话很短 ——
        「同一个策略包，两份加载器编译出了两个哈希」。那意味着出证方算一个、
        验证方算另一个，两边都自洽，而证书在第三方手里才验不过。
        """
        for pack, judged in sorted(golden()["judged"].items()):
            with self.subTest(pack=pack):
                self.assertGreaterEqual(len(judged["hashes"]), 1,
                                        f"{pack}: 一个哈希都没采到，下一条会是空断言")
                self.assertEqual(
                    len(judged["hashes"]), 1,
                    f"{pack}: 有 {len(judged['hashes'])} 种 policy_hash —— "
                    "同一个包被不同的加载器编译出了不同的哈希。见本文件模块 docstring。")

    def test_hashes_look_like_sha256(self):
        """形状检查：它们得像 SHA-256，不是空串或错误信息。"""
        for pack, judged in sorted(golden()["judged"].items()):
            for h in judged["hashes"]:
                with self.subTest(pack=pack):
                    self.assertEqual(len(h), 64, f"{pack}: {h!r} 不像 SHA-256")
                    int(h, 16)  # 不是十六进制就抛 ValueError


class TestDeclaredDivergence(unittest.TestCase):
    """**已知且已声明**的唯一一处分歧：``description``。多一处就红。"""

    def test_only_description_diverges_and_only_on_these_loaders(self):
        diffs = golden()["differences"]
        self.assertEqual(
            sorted(diffs), sorted(golden()["packs"]),
            "每个包都该恰有一处已声明的分歧（description）—— 有包一处分歧都没有，"
            "说明采集或比对变了")
        for pack, fields in sorted(diffs.items()):
            with self.subTest(pack=pack):
                self.assertEqual(
                    sorted(fields), ["description"],
                    f"{pack}: 分歧不止 description 一处，还有 {sorted(fields)}。"
                    "新冒出来的分歧要单独查：它是否也像 description 一样对可观察输出惰性？")
                self.assertEqual(len(fields["description"]), 2,
                                 f"{pack}: description 出现了两种以上写法")

    def test_description_divergence_has_exactly_the_declared_takers(self):
        """保留 ``description`` 的恰好是那 3 份，丢掉的恰好是其余 8 份。"""
        n_all = len(golden()["loaders"])
        for pack in sorted(golden()["packs"]):
            with self.subTest(pack=pack):
                by_value = golden()["differences"][pack]["description"]
                keepers = sorted(
                    lab for val, labs in by_value.items() if val != "''" for lab in labs)
                droppers = sorted(
                    lab for val, labs in by_value.items() if val == "''" for lab in labs)
                self.assertEqual(keepers, sorted(DESCRIPTION_KEEPERS),
                                 f"{pack}: 保留 description 的加载器名单变了")
                self.assertEqual(len(droppers), n_all - len(DESCRIPTION_KEEPERS),
                                 f"{pack}: 丢掉 description 的份数不对")
                self.assertTrue(
                    all(v for v in by_value if v != "''"),
                    f"{pack}: 保留的那一份 description 是空的 —— 那就不是真分歧了")

    def test_the_kept_description_is_the_one_declared_in_the_pack(self):
        """保留的那一份**就是包文件里写的那一句** —— 不是第三个值。

        这一条才是这个分歧的定性：不是「三种写法各有各的说法」，而是
        「一份照包里的写了，一份丢了」。顺带钉住包文件的 description 非空，
        否则整条断言会退化成「'' 等于 ''」。
        """
        for pack in sorted(golden()["packs"]):
            with self.subTest(pack=pack):
                declared = json.loads(
                    (REPO / "policy_packs" / pack).read_text(encoding="utf-8"))
                self.assertTrue(declared.get("description"),
                                f"{pack}: 包文件里没有 description，这一条成了空断言")
                by_value = golden()["differences"][pack]["description"]
                kept = [v for v in by_value if v != "''"]
                self.assertEqual(len(kept), 1)
                self.assertEqual(
                    ast.literal_eval(kept[0]), declared["description"],
                    f"{pack}: 保留的那一份 description 与包文件里写的不一样")


class TestLiveLoadersMatchSnapshot(unittest.TestCase):
    """现算全部加载器，与快照逐路径比 —— **R7 的闸门就是这一条**。

    比的是 :func:`loader_parity.judged_payload`（逐包的去重哈希集合与去重签名集合），
    不是每一份加载器的完整记录 —— 所以把 ``LOADERS`` 表从 11 行缩成 1 行时，
    这里不需要跟着改：两边都归约成同一个问题，*这批包上出现过几种答案？*
    """

    def test_live_agrees_with_the_snapshot(self):
        # 快照按 R7 的那一处已声明归一折算后再比 —— 理由见 DECLARED_R7_NORMALIZATION。
        # 折算本身由下面 test_the_live_delta_is_exactly_the_declared_normalization 逐处核。
        want = loader_parity.judged_payload(normalized_golden())
        got = loader_parity.judged_payload(fresh())
        if want != got:
            lines = []
            for key in sorted(set(want["judged"]) | set(got["judged"])):
                if want["judged"].get(key) != got["judged"].get(key):
                    lines.append(f"  [{key}]")
                    lines.append("    快照: " + json.dumps(
                        want["judged"].get(key), ensure_ascii=False)[:400])
                    lines.append("    现算: " + json.dumps(
                        got["judged"].get(key), ensure_ascii=False)[:400])
            self.fail(
                f"现算的加载器与 {BASELINE.name} 不一致：\n" + "\n".join(lines) + "\n"
                "不该变的 → 改代码；有意变的 → 先读本文件模块 docstring 里"
                "「R7 落地后怎么用这个文件」一段，再决定要不要重采快照。")

    def test_each_surviving_loader_still_behaves_exactly_as_snapshotted(self):
        """两边都有的标签，**逐份比完整记录**（含「谁带 description」）—— 比上面那条更严。

        为什么单靠 :meth:`test_live_agrees_with_the_snapshot` 不够：它比的是
        **答案的集合**。把某一份加载器从「丢 ``description``」改成「带 ``description``」，
        集合仍然是 ``{包里那句, ''}`` 两种 —— **没有一条会红**。而「谁持哪种行为」
        恰恰就是 R7 要收敛的东西，它必须是有观察的。

        标签只在一边出现的（R7 把 11 行缩成 1 行时就是这种情形）不参与逐份比对：
        那时整体判据由上面那条承担。

        R7 之后比的是**折算过的**快照（见 :func:`normalized_golden`）：11 行标签
        全留着，所以逐份比对一点没退化 —— 每一份入口都仍被单独盯着。
        """
        want, got = normalized_golden()["loaders"], fresh()["loaders"]
        common = sorted(set(want) & set(got))
        self.assertTrue(common, "两边没有任何共同标签 —— 逐份比对退化成了空断言")
        for label in common:
            with self.subTest(loader=label):
                self.assertEqual(
                    got[label], want[label],
                    f"{label} 的行为与快照（按 R7 归一折算后）不一致。它的每一次改动"
                    "都该是有意的：若是 R7 的归一（比如统一成「带 description」），"
                    "就在本文件里把这处归一**声明**出来，而不是重采快照。")

    def test_the_live_delta_is_exactly_the_declared_normalization(self):
        """**折算不是免检**：现算与入库快照的差异，必须逐处等于申报的那一处归一并仅此而已。

        只比折算后的快照是不够的 —— 那样「折算」就成了一个可以夹带任何东西的黑箱。
        这条把黑箱打开：逐 ``(加载器, 包)`` 列出差异，要求

        * 有差异的**恰好**是 :data:`DESCRIPTION_DROPPERS` 那 8 份 × 全部 7 个包；
        * 差异只出现在 ``policy.description`` 一个字段上（其余字段逐字相同，
          ``policy_hash`` 尤其 —— **它是 R7 那条回退判据**）；
        * 且方向唯一：``''`` → 包文件里写的那句。

        任何一条不成立，R7 就不是「等效替代 + 一处已声明归一」，而是一次未申报的
        行为变化 —— 那正是这套闸门存在的理由。
        """
        want, got = golden()["loaders"], fresh()["loaders"]
        changed: dict = {}
        for label in sorted(set(want) & set(got)):
            for pack in golden()["packs"]:
                a = (want[label].get(pack) or {})
                b = (got[label].get(pack) or {})
                if a == b:
                    continue
                changed.setdefault(label, set()).add(pack)
                with self.subTest(loader=label, pack=pack):
                    self.assertEqual(sorted(set(a) | set(b)), ["policy", "policy_hash"],
                                     "记录顶层字段变了")
                    self.assertEqual(a["policy_hash"], b["policy_hash"],
                                     "policy_hash 变了 —— 这正是 R7 要防的那件事")
                    self.assertEqual(
                        sorted(set(a["policy"]) | set(b["policy"])),
                        ["description", "id", "rules", "semantic", "version"])
                    for field in ("id", "version", "rules", "semantic"):
                        self.assertEqual(a["policy"][field], b["policy"][field],
                                         f"{field} 不该被这处归一碰到")
                    self.assertEqual(a["policy"]["description"], "",
                                     "差异不是从「丢」这一侧发生的")
                    self.assertEqual(b["policy"]["description"], _declared_description(pack),
                                     "归一后的值不是包文件里写的那句")
        self.assertEqual(
            {lab: sorted(packs) for lab, packs in changed.items()},
            {lab: sorted(golden()["packs"]) for lab in DESCRIPTION_DROPPERS},
            "差异集不是「那 8 份 × 全部 7 个包」。多了 = 有未申报的变化；"
            "少了 = 申报的归一没真的发生（或者快照被重采过）")

    def test_live_run_is_itself_not_vacuous(self):
        """现算这一份也必须采满 —— 否则上一条比的是两堆空集合。"""
        for pack, cov in sorted(_coverage_of(fresh()).items()):
            with self.subTest(pack=pack):
                self.assertEqual(cov["loaded"], cov["expected"],
                                 f"{pack}: 现算只读到 {cov['loaded']}/{cov['expected']} 份")


if __name__ == "__main__":
    unittest.main()
