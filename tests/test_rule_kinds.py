"""规则 kind 的**分派一致性**保障：四份实现不许悄悄漂移。

外加第五件东西：``Violation.evidence_kind`` → ``rule.kind`` 的**翻译表**
（``evaluate.EVIDENCE_KIND_TO_RULE_KIND``，R6 收敛）。它一度被抄成三份，其中
``prove_policy.py`` 与 ``test_commit.py`` 那两份**各只有 7 项里的 3 项** —— 之所以
今天不炸，只是因为现有 7 个策略包用到的 ``evidence_kind`` 恰好都落在那 3 项里。
本文件末尾两道闸门把它钉住：① 表与 ``check`` 真正会产生的配对逐项相等（``ast``
从分支体里抽，不靠人维护）；② 全仓不许再出现第二份。

为什么需要这套用例：按 ``kind`` 分派的逻辑在项目里有**四份**，各自独立维护——

1. ``policydsl/core/model.py``            —— ``Rule.validate``（参数校验）
2. ``policydsl/core/evaluate.py``         —— ``check``（参考判定）
3. ``policydsl/core/compile.py``          —— ``compile_constraints``（编译成约束）
4. ``policydsl/privacy/commit.py``        —— ``canonical_violations``（隐私模式镜像）

外加 ``policydsl/proofs/multiparty.py`` 的 ``KIND_OWNER``（唯一的**运行期**全量枚举）。
新增一种 kind 时漏改其中任意一处，症状都是**静默**的 —— 没有异常、没有报错：

* 漏在 ``evaluate.check``：该规则被判成「无违规」。而 ``check`` 的分支链**没有
  ``else``**，未知 kind 会直接穿过整个循环。今天它之所以还没漏，全靠
  ``evaluate.py:106`` 的 ``policy.validate()`` 在前面挡着 —— 也就是说，
  ``model.py`` 那份名单是其余几份的**兜底**，它必须是最全的。
* 漏在 ``compile.compile_constraints``：约束变成 ``{"stub": True}``（该分支在
  ``validate`` 之后其实是死代码，但正是靠这条前提）。
* 漏在 ``commit.canonical_violations``：抛 ``NotImplementedError``。

所以这里把「四份名单 + 一份运行期枚举」钉在一起。``model._RULE_VALIDATORS``
的键就是权威名单（它同时是 ``Rule.validate`` 的分派表，不会与实现脱节）。

前两份用 ``ast`` 从源码里抽字面量（它们是裸 ``if/elif`` 链，没有可 import 的
枚举）；``multiparty.KIND_OWNER`` 直接 import 来比，不抄第二份。
"""

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl.core.evaluate import EVIDENCE_KIND_TO_RULE_KIND  # noqa: E402
from policydsl.core.model import _RULE_VALIDATORS  # noqa: E402
from policydsl.proofs.multiparty import KIND_OWNER  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
EVALUATE_PY = REPO / "policydsl" / "core" / "evaluate.py"

#: kind 名单的出处：逻辑路径 → 源码文件。文案里要用，顺手放一处。
SOURCES = {
    "evaluate.check": REPO / "policydsl" / "core" / "evaluate.py",
    "compile.compile_constraints": REPO / "policydsl" / "core" / "compile.py",
    "commit.canonical_violations": REPO / "policydsl" / "privacy" / "commit.py",
}

#: ``commit.py`` 有意不覆盖的那一个 kind。
#:
#: 不是漏了：``semantic_bound`` 是**委托**给 ezkl 的约束，判定根本不在这一层做，
#: 所以隐私模式的镜像里没有它 —— 上游 ``runtime/service.py:280`` 会先把
#: ``kind == "semantic_bound"`` 的约束过滤掉，才走到 ``canonical_violations``。
#: 这里按「子集」断言，并且把差集**精确**钉死：将来多出别的差集，测试照样红。
COMMIT_EXEMPT = {"semantic_bound"}


def _is_kind_expr(node: ast.AST) -> bool:
    """``rule.kind`` / ``c.kind`` 这类属性，或形如 ``kind`` 的局部变量。

    只认 ``.kind`` 或名为 ``kind`` 的名字 —— 这样 ``v.evidence_kind == "…"``
    不会误收（它比较的是证据种类，不是规则种类）。
    """
    if isinstance(node, ast.Attribute):
        return node.attr == "kind"
    return isinstance(node, ast.Name) and node.id == "kind"


def _str_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def kind_literals(path: Path) -> set:
    """从源码里抽出所有与 ``kind`` 比较的字符串字面量。

    支持两种写法（项目里两种都有）::

        if rule.kind == "keyword_block": ...        # 属性
        if kind == "keyword_block": ...             # 先解构出来的局部变量

    也收 ``kind in (...)"`` / ``kind not in (...)`` 这种白名单形式。
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left, *node.comparators]
        for i, op in enumerate(node.ops):
            left, right = operands[i], operands[i + 1]
            if not _is_kind_expr(left):
                continue
            if isinstance(op, (ast.Eq, ast.NotEq)):
                if _str_const(right):
                    found.add(right.value)
            elif isinstance(op, (ast.In, ast.NotIn)):
                if isinstance(right, (ast.Tuple, ast.List, ast.Set)):
                    found.update(e.value for e in right.elts if _str_const(e))
    return found


class TestRegistryIsAuthoritative(unittest.TestCase):
    """``_RULE_VALIDATORS`` 本身：非空、键是字符串、函数可调用。"""

    def test_registry_shape(self):
        self.assertTrue(_RULE_VALIDATORS, "_RULE_VALIDATORS 不能是空表")
        for kind, fn in _RULE_VALIDATORS.items():
            with self.subTest(kind=kind):
                self.assertIsInstance(kind, str)
                self.assertTrue(kind, "kind 不能是空串")
                self.assertTrue(callable(fn))

    def test_covers_the_documented_eight(self):
        """docs/modules/01-policy-dsl.md §7 列的 8 种 kind，一个不少。"""
        self.assertEqual(_RULE_VALIDATORS.keys(), {
            "keyword_block",
            "normalized_keyword_block",
            "length_bound",
            "pattern_block",
            "format_check",
            "tool_arg_guard",
            "budget_bound",
            "semantic_bound",
        })


class TestDispatchSitesAgree(unittest.TestCase):
    """四份按 kind 的分派 + multiparty 的运行期枚举，必须对得上。"""

    def setUp(self):
        self.kinds = set(_RULE_VALIDATORS)

    def test_ast_extraction_finds_something(self):
        """先确认抽取器本身没坏 —— 抽不到东西会导致下面的断言空转通过。"""
        for label, path in SOURCES.items():
            with self.subTest(source=label):
                self.assertTrue(
                    kind_literals(path),
                    f"{label}: 从 {path.name} 里没抽到任何 kind 字面量，"
                    f"抽取器可能已经与源码写法脱节")

    def test_evaluate_matches_registry(self):
        """evaluate.check 必须覆盖全部 kind，一个不能少。"""
        got = kind_literals(SOURCES["evaluate.check"])
        self.assertEqual(
            got, self.kinds,
            f"evaluate.check 与 _RULE_VALIDATORS 不一致："
            f"少了 {sorted(self.kinds - got)}，多了 {sorted(got - self.kinds)}")

    def test_compile_matches_registry(self):
        """compile.compile_constraints 必须覆盖全部 kind。"""
        got = kind_literals(SOURCES["compile.compile_constraints"])
        self.assertEqual(
            got, self.kinds,
            f"compile_constraints 与 _RULE_VALIDATORS 不一致："
            f"少了 {sorted(self.kinds - got)}，多了 {sorted(got - self.kinds)}")

    def test_commit_covers_registry_minus_exempt(self):
        """commit.canonical_violations 覆盖除 COMMIT_EXEMPT 外的全部 kind。"""
        got = kind_literals(SOURCES["commit.canonical_violations"])
        self.assertTrue(
            got <= self.kinds,
            f"commit.py 处理了 _RULE_VALIDATORS 里没有的 kind：{sorted(got - self.kinds)}")
        self.assertEqual(
            self.kinds - got, COMMIT_EXEMPT,
            f"commit.py 的豁免集变了：实际 {sorted(self.kinds - got)}，"
            f"预期 {sorted(COMMIT_EXEMPT)}。"
            f"若是有意新增豁免，请同时更新 COMMIT_EXEMPT 与本注释的理由")

    def test_multiparty_kind_owner_matches_registry(self):
        """KIND_OWNER 是运行期的全量枚举，直接 import 来比（不抄第二份）。"""
        self.assertEqual(
            set(KIND_OWNER), self.kinds,
            f"KIND_OWNER 与 _RULE_VALIDATORS 不一致："
            f"少了 {sorted(self.kinds - set(KIND_OWNER))}，"
            f"多了 {sorted(set(KIND_OWNER) - self.kinds)}")


#: 合成规则 ``_TraceRule`` 的 kind：坏回执链的落点，不属于任何策略规则。
SYNTHETIC_EVIDENCE_KIND = "trace_unbound"

#: 扫描全仓时跳过的目录（与 tests/test_driver_paths.py、test_artifact_digest.py 同）。
SKIP_DIRS = {".git", "target", "__pycache__", "node_modules", ".venv", "out", ".work"}

#: 「一次抄了至少两项」才算副本 —— 单个巧合配对（如某处只映射一个词）不算。
COPY_MIN_PAIRS = 2

#: ── 申报的例外（逐条给理由，条数钉死）──────────────────────────────────────
#:
#: 定义了翻译表的文件 → 该文件里「表形态的字典字面量」个数（不是配对条数）。
DECLARED_TABLE_SITES = {
    # 唯一出处本身 —— 全仓就这一个字典字面量。
    "policydsl/core/evaluate.py": 1,
}

MIN_SCANNED = 100


def _branch_kind(test: ast.AST):
    """若 ``test`` 形如 ``rule.kind == "X"`` 则返回 ``"X"``，否则 ``None``。"""
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)):
        return None
    if not _is_kind_expr(test.left) or not _str_const(test.comparators[0]):
        return None
    return test.comparators[0].value


def _violation_evidence_kinds(stmts) -> set:
    """在一段语句里数 ``Violation(<rule>, "<evidence_kind>", …)`` 的第二个位置参数。"""
    found = set()
    for stmt in stmts:
        for node in ast.walk(stmt):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "Violation" and len(node.args) >= 2
                    and _str_const(node.args[1])):
                found.add(node.args[1].value)
    return found


def emit_table(path: Path) -> dict:
    """从 ``check`` 的分派链里抽出 ``{规则 kind: {evidence_kind, …}}``。

    走的是 ``if/elif rule.kind == "X":`` 的**分支体**（``node.body``，不含
    ``orelse``）—— 用 ``ast.walk(node)`` 会把 ``elif`` 链一起吞掉，所以这里只
    对分支体逐条 walk。
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        kind = _branch_kind(node.test)
        if kind is None:
            continue
        ev = _violation_evidence_kinds(node.body) - {SYNTHETIC_EVIDENCE_KIND}
        if ev:
            out[kind] = ev
    return out


def _py_files() -> list:
    return [p for p in sorted(REPO.rglob("*.py"))
            if not (SKIP_DIRS & set(p.relative_to(REPO).parts))]


def _table_copies() -> dict:
    """→ ``{相对路径: 该文件里「含 ≥COPY_MIN_PAIRS 项本表配对」的字典字面量个数}``。

    字典字面量是这份表被抄写时的实际形态（三份副本都是）。改名、拆成两句赋值
    这类变体扫不到 —— 闸门按**已观察到的形态**写，并留申报口子。
    """
    pairs = set(EVIDENCE_KIND_TO_RULE_KIND.items())
    out = {}
    for p in _py_files():
        rel = str(p.relative_to(REPO))
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        n = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            hit = 0
            for k, v in zip(node.keys, node.values):
                if _str_const(k) and _str_const(v) and (k.value, v.value) in pairs:
                    hit += 1
            if hit >= COPY_MIN_PAIRS:
                n += 1
        if n:
            out[rel] = n
    return out


class TestEvidenceKindVocabularyIsSingleSourced(unittest.TestCase):
    """``EVIDENCE_KIND_TO_RULE_KIND``：既**对**（与 ``check`` 逐项相符），又**独**。"""

    def test_the_table_matches_what_check_actually_emits(self):
        """表不是靠人维护的：与 ``check`` 里每个分支真正产生的配对逐项相等。

        人维护的那一半会烂在「新增一种 kind 却没加表」上 —— 而症状是**静默**的：
        调用方的 ``.get(k, k)`` 会把 ``"format"`` 本身当成 kind 交出去，guest 那侧
        写的是 ``format_check``，两边对不上，出证时才报「违规集合不同」。
        """
        emitted = emit_table(EVALUATE_PY)
        actual = {k: sorted(v) for k, v in emitted.items()}
        # 表的方向是 evidence_kind → 规则 kind（给调用方翻译用）；分支链的方向
        # 相反。这里把表**反过来**再比，方向别搞混 —— 搞混了失败信息会读起来像
        # 「七个键两两不相干」，而不是「方向错了」。
        declared = {}
        for ev, kind in EVIDENCE_KIND_TO_RULE_KIND.items():
            declared.setdefault(kind, []).append(ev)
        self.assertEqual(
            actual, {k: sorted(v) for k, v in declared.items()},
            "evaluate.check 的 (规则 kind → evidence_kind) 与 "
            "EVIDENCE_KIND_TO_RULE_KIND 不一致。实测：\n" + repr(actual))
        # 每个分支**恰好**一个 evidence_kind：多一个就说明该分支有两条互不相干的
        # 违规来源，而表只有一列 —— 那种情况必须先把表的结构想清楚，不能默认通过。
        for kind, ev in emitted.items():
            with self.subTest(kind=kind):
                self.assertEqual(len(ev), 1,
                                 f"{kind} 分支产生了 {sorted(ev)} 种 evidence_kind")

    def test_the_table_speaks_the_registrys_language(self):
        """表的值必须是 ``_RULE_VALIDATORS`` 认得的 kind，键必须非空。"""
        for ev, kind in EVIDENCE_KIND_TO_RULE_KIND.items():
            with self.subTest(evidence_kind=ev):
                self.assertIn(kind, _RULE_VALIDATORS,
                              f"evidence_kind {ev!r} 映射到了不存在的规则 kind {kind!r}")

    def test_no_second_copy_of_the_table(self):
        copies = _table_copies()
        self.assertEqual(
            copies, DECLARED_TABLE_SITES,
            "出现未申报的翻译表副本（或申报的例外已失效）。一律改用 "
            "`from policydsl.core.evaluate import EVIDENCE_KIND_TO_RULE_KIND`；"
            "确有正当理由就把条目加进 DECLARED_TABLE_SITES 并写明理由。实测：\n"
            f"{copies!r}")

    def test_the_scan_is_not_vacuous(self):
        files = _py_files()
        self.assertGreaterEqual(len(files), MIN_SCANNED, f"只扫到 {len(files)} 个 .py")
        self.assertIn(str(EVALUATE_PY.relative_to(REPO)),
                      {str(p.relative_to(REPO)) for p in files})

    def test_the_scanner_can_actually_see_a_copy(self):
        """扫描器自身的探针：喂一段**已知**的副本，它必须报出来。"""
        sample = ast.parse('KIND_MAP = {"keyword": "keyword_block",\n'
                           '            "length": "length_bound"}\n')
        pairs = set(EVIDENCE_KIND_TO_RULE_KIND.items())
        d = next(n for n in ast.walk(sample) if isinstance(n, ast.Dict))
        hit = sum(1 for k, v in zip(d.keys, d.values)
                  if _str_const(k) and _str_const(v) and (k.value, v.value) in pairs)
        self.assertGreaterEqual(hit, COPY_MIN_PAIRS)

    def test_the_extractor_can_actually_see_a_branch(self):
        """抽取器自身的探针：一段**已知**的分派链，必须抽出那个配对。"""
        sample = ast.parse(
            'if rule.kind == "length_bound":\n'
            '    violations.append(Violation(rule, "length", {}))\n'
            'elif rule.kind == "budget_bound":\n'
            '    if not chain_ok:\n'
            '        violations.append(Violation(rule, "trace_unbound", why))\n'
            '    violations.append(Violation(rule, "budget", {}))\n')
        out = {}
        for node in ast.walk(sample):
            if isinstance(node, ast.If):
                k = _branch_kind(node.test)
                if k is not None:
                    out[k] = _violation_evidence_kinds(
                        node.body) - {SYNTHETIC_EVIDENCE_KIND}
        self.assertEqual(out, {"length_bound": {"length"}, "budget_bound": {"budget"}})


class TestUnknownKindFailsClosed(unittest.TestCase):
    """未知 kind 必须**拒绝**，不能被静默放过。"""

    def test_validate_rejects_unknown_kind(self):
        from policydsl.core.model import PolicyError, Rule

        with self.assertRaises(PolicyError):
            Rule("no_such_kind", "r", {}).validate()

    def test_unhashable_kind_is_policy_error_not_type_error(self):
        """畸形的 kind 要报 ``PolicyError``，不能漏成 ``TypeError``。

        kind 来自 JSON（``policydsl/__main__.py`` 的 ``_load_policy`` 原样透传），
        而 JSON 的值可以是数组/对象 —— 不可哈希的值喂给分派表的 ``dict.get``
        会抛 ``TypeError``，那就绕过了 ``PolicyError``，把「可诊断的策略包错误」
        变成「未捕获的崩溃」。``PolicyError`` 是 ``ValueError`` 子类，上层按它
        收敛错误，所以这条必须成立。
        """
        from policydsl.core.model import PolicyError, Rule

        for bad in (["keyword_block"], {"keyword_block"}, {"a": 1}, bytearray(b"x")):
            with self.subTest(kind=bad):
                with self.assertRaises(PolicyError):
                    Rule(bad, "r", {}).validate()

    def test_non_string_kind_is_policy_error(self):
        """非字符串但可哈希的 kind 同样走 ``PolicyError``（与重构前一致）。"""
        from policydsl.core.model import PolicyError, Rule

        for bad in (None, 123, 4.5, True, b"keyword_block", ("keyword_block",)):
            with self.subTest(kind=bad):
                with self.assertRaises(PolicyError):
                    Rule(bad, "r", {}).validate()


if __name__ == "__main__":
    unittest.main()
