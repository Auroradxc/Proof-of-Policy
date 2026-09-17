"""驱动路径（``pop-script`` / ``pop-verify``）**只能有一个出处**的结构性闸门。

为什么值得一个测试：这两个路径一度被**逐字抄在 26 个文件 / 33 行**里。它们抄得
一字不差，所以从任何一处看都「没问题」—— 问题在于「一字不差」是靠人抄对维持的，
而抄错的后果恰好是 ``policydsl/paths.py`` docstring 记的那类事故：路径指向一个
不存在的位置，于是 26 处各自决定怎么办（抛 ``FileNotFoundError`` / ``skipUnless``
静默跳过 / ``raise SystemExit``），同一个故障有 26 种表现。§5.7.9 已把它们收敛到
``policydsl/paths.py`` 的两行。

本文件把「收敛」这件事钉成结构，而不是钉成一次性的普查结果：

- 谁再抄一份字面量 → 红（``test_no_other_module_spells_the_driver_paths``）；
- 谁再拷一份别名（``POP_SCRIPT = 别处.POP_SCRIPT``，历史上真的有过两处）→ 红
  （``test_no_other_module_copies_the_constants_by_alias``）；
- 例外**必须逐条申报**（带理由）且**条数钉死**：多一处要改数字，少一处也要改 ——
  于是例外不会悄悄长大，也不会腐烂成「反正这个文件豁免」（对照 §5.7.7 的做法）；
- 扫描本身**非空转**：范围、以及「真有模块从这个出处取路径」都有下限
  （``test_the_scan_is_not_vacuous``）。

**不是**在测路径的值 —— 那个由 ``tests/acceptance_baseline.json`` 与真出证覆盖。
这里只测「只有一处能说它是什么」。
"""

import ast
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl import paths  # noqa: E402

#: 只认这两个**恰好等于**驱动器名的字符串字面量。长句子里提到 `pop-script`
#: （报错文案、docstring、注释）一律不算 —— 那是在**说**它，不是在**定位**它。
DRIVER_NAMES = {"pop-script", "pop-verify"}

#: 会构成「第二处出处」的模块级名字。
DRIVER_CONST = {"POP_SCRIPT", "POP_VERIFY", "DEFAULT_POP"}

#: 不参与扫描的目录（构建产物 / 第三方 / 缓存）。
SKIP_DIRS = {".git", "target", "__pycache__", "node_modules", ".venv", "out", ".work"}

#: ── 申报的例外 ────────────────────────────────────────────────────────────
#:
#: 字面量例外：值恰好等于驱动器名，但**不是在定位驱动器**。逐文件钉死条数，
#: 任一文件里新增/减少一处都会红 —— 这是「申报」与「漏网」的分界。
DECLARED_LITERAL_EXCEPTIONS = {
    # 唯一出处本身。少了它才是奇怪。
    "policydsl/paths.py": 2,
    # `subprocess.CalledProcessError(..., ["pop-script", ...])`：替身 argv 的 **argv[0]**，
    # 是个名字不是路径。两条用例分别验 SIGKILL 翻译与 job.error 的可读性。
    "tests/test_proof_service.py": 2,
    # 在 TemporaryDirectory 里**造**一个名叫 pop-verify 的假二进制，喂给
    # prefer_verifier_only 测判定逻辑 —— 正是「不能被当成真驱动器」的那种假货。
    "tests/test_verifier_only.py": 2,
    # 闸门自己的词汇表（`DRIVER_NAMES`）与两条「常量名 = 文件名」的断言。
    # 它们写的是**驱动器叫什么**，本来就该在改名字的时候一起红。
    "tests/test_driver_paths.py": 4,
}

#: 模块级别名例外。同上，钉条数。
DECLARED_ALIAS_EXCEPTIONS = {
    "policydsl/paths.py": 2,
    # 全仓唯一**有意**认 `$POP_SCRIPT` 的地方（单测/定时回归靠它注入替身驱动）。
    # 写法是「以本出处为缺省值再让环境变量覆盖」，不是另抄一份。
    "scripts/prove/cross_validate.py": 1,
}

#: 扫描范围的下限（防止 glob 写错导致「零处违规 = 全绿」）。实测 106。
MIN_SCANNED = 100
#: 「真有人从这里取路径」的下限。实测 29；留出 P3 清死代码的余量。
MIN_IMPORTERS = 25


def _docstring_nodes(tree: ast.AST) -> set:
    """模块/类/函数首条的字符串表达式节点 —— 它们是在**叙述**，不是在**定位**。"""
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                ids.add(id(node.body[0].value))
    return ids


def _py_files() -> list:
    return [p for p in sorted(Path(REPO).rglob("*.py"))
            if not (SKIP_DIRS & set(p.relative_to(REPO).parts))]


def _scan():
    """返回 (字面量站点, 别名站点)，均以**相对路径**为键、行号列表为值。"""
    literals, aliases = {}, {}
    for p in _py_files():
        rel = str(p.relative_to(REPO))
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:  # 扫不动的文件不能算「干净」
            literals.setdefault(rel, []).append(f"<SyntaxError>")
            continue
        docs = _docstring_nodes(tree)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and node.value in DRIVER_NAMES and id(node) not in docs):
                literals.setdefault(rel, []).append(node.lineno)
            # 只看**模块级**赋值：函数里的局部变量影响不到别处（但见 R4 前的
            # verify_cert/verify_session —— 它们把局部重算成模块级是收敛的一部分）。
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.col_offset == 0:
                target = node.targets[0] if isinstance(node, ast.Assign) else node.target
                name = (target.id if isinstance(target, ast.Name)
                        else target.attr if isinstance(target, ast.Attribute) else None)
                if name in DRIVER_CONST:
                    aliases.setdefault(rel, []).append(node.lineno)
    return literals, aliases


def _counts(sites: dict) -> dict:
    """{文件: 处数}，只留非空的。"""
    return {k: len(v) for k, v in sites.items() if v}


class TestAuthority(unittest.TestCase):
    """出处本身：它得真的是它自称的那两个路径。"""

    def test_the_two_constants_resolve_under_the_repo(self):
        for const, filename in ((paths.POP_SCRIPT, "pop-script"),
                                (paths.POP_VERIFY, "pop-verify")):
            self.assertEqual(const.name, filename)
            self.assertEqual(const.parent, REPO / "circuits" / "target" / "release")

    def test_the_authority_is_a_leaf(self):
        """出处不能反过来依赖重型模块 —— 否则「读路径」这件事会付不起代价，
        于是大家又会各自抄一份（这正是它当初被抄 33 次的原因之一）。"""
        allowed = {"pathlib", "__future__"}
        src = (REPO / "policydsl" / "paths.py").read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.ImportFrom):
                self.assertIn(node.module, allowed, f"paths.py 引入了 {node.module}")
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name, allowed, f"paths.py 引入了 {a.name}")


class TestOnlyOneSource(unittest.TestCase):
    """除申报的例外外，全仓不许再出现第二处出处。"""

    def test_no_other_module_spells_the_driver_paths(self):
        literals, _ = _scan()
        got = _counts(literals)
        self.assertEqual(
            got, DECLARED_LITERAL_EXCEPTIONS,
            "出现未申报的驱动路径字面量（或申报的例外已失效）。新增出处一律改为 "
            "`from policydsl.paths import POP_SCRIPT`；确有正当理由就把条数加进 "
            "DECLARED_LITERAL_EXCEPTIONS 并写明理由。实测：\n"
            + json.dumps({k: v for k, v in literals.items()}, ensure_ascii=False, indent=2))

    def test_no_other_module_copies_the_constants_by_alias(self):
        _, aliases = _scan()
        got = _counts(aliases)
        self.assertEqual(
            got, DECLARED_ALIAS_EXCEPTIONS,
            "出现未申报的模块级别名（`POP_SCRIPT = 别处.POP_SCRIPT` 这种拷贝照样是"
            "第二处出处 —— 历史上 policydsl/proofs/session.py:65 与 "
            "tests/test_session.py:44 就是）。实测：\n"
            + json.dumps({k: v for k, v in aliases.items()}, ensure_ascii=False, indent=2))

    def test_the_declared_literal_exceptions_are_still_justified(self):
        """例外不是「豁免整个文件」，是「这几处不是路径」。逐条复述理由并核对。

        值恰好等于驱动器名、却不是在定位驱动器的，只有两类：替身 argv[0]、
        临时目录里的假二进制。任一文件里出现了**新**的一处，上面的条数比对已经
        报红；这里再把「现有这几处确实属于这两类」钉住。
        """
        src_ps = (REPO / "tests" / "test_proof_service.py").read_text(encoding="utf-8")
        src_vo = (REPO / "tests" / "test_verifier_only.py").read_text(encoding="utf-8")
        # 替身 argv[0]：必须真的写成 CalledProcessError 的 argv，而不是路径拼接
        self.assertEqual(src_ps.count('["pop-script"'), 2)
        # 假二进制：必须落在临时目录里（`/ "pop-verify"`），而不是 REPO 下
        self.assertEqual(src_vo.count('/ "pop-verify"'), 2)


class TestTheEnvOverrideSurvives(unittest.TestCase):
    """R4 收敛时**必须保留**的能力：`cross_validate.py` 认 `$POP_SCRIPT`。

    定时回归（``regression_prove.py:220`）与 `tests/test_regression_prove.py`
    都靠它注入替身驱动，从而不必有 Rust 工具链也能走完整流程。收敛的写法是
    「以出处为缺省值，再让环境变量覆盖」—— 这里用两个子进程把两种情形各跑一次。
    """

    def _resolve(self, env_value=None):
        code = ("import sys, json; sys.path.insert(0, sys.argv[1] + '/scripts');"
                "from _bootstrap import bootstrap; bootstrap();"
                "import cross_validate as cv; print(cv.POP_SCRIPT)")
        import os
        env = dict(os.environ)
        env.pop("POP_SCRIPT", None)
        if env_value is not None:
            env["POP_SCRIPT"] = env_value
        r = subprocess.run([sys.executable, "-c", code, str(REPO)],
                           capture_output=True, text=True, env=env, cwd=str(REPO))
        self.assertEqual(r.returncode, 0, r.stderr)
        return Path(r.stdout.strip())

    def test_default_comes_from_the_authority(self):
        self.assertEqual(self._resolve(), paths.POP_SCRIPT)

    def test_env_still_overrides(self):
        self.assertEqual(self._resolve("/tmp/stand-in-pop"), Path("/tmp/stand-in-pop"))


class TestTheScanIsNotVacuous(unittest.TestCase):
    """一个扫不到东西的闸门，和没有闸门是同一件事。"""

    def test_it_scanned_the_whole_repo(self):
        files = _py_files()
        self.assertGreaterEqual(len(files), MIN_SCANNED, f"只扫到 {len(files)} 个 .py")
        rels = {str(p.relative_to(REPO)) for p in files}
        # 出处本身、以及 R4 收敛过来的几处，都在扫描范围内
        for must in ("policydsl/paths.py", "scripts/prove/cross_validate.py",
                     "scripts/verify/verify_cert.py", "bench/bench_verify.py"):
            self.assertIn(must, rels)

    def test_enough_modules_still_take_the_path_from_the_authority(self):
        """扫描是**反向**的（只看「有没有第二处」）。再补一个正向下限：确有模块
        从这里取路径 —— 否则把 import 全删光也照样全绿。"""
        n = 0
        for p in _py_files():
            if "from policydsl.paths import" in p.read_text(encoding="utf-8"):
                n += 1
        self.assertGreaterEqual(n, MIN_IMPORTERS,
                                f"只有 {n} 个模块从 policydsl.paths 取路径")


if __name__ == "__main__":
    unittest.main()
