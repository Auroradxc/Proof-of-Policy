"""分层闸门：``core`` 不许 import ``proofs``（R14）。

## 这条契约陈述的是什么

``core`` 是**判定层**（决定「合不合规」），``proofs`` 是**出证编排层**（决定
「怎么把判定包成一份可验证的产物」）。两层的关系是**单向**的：出证层产出的东西
要被判定层理解，而判定层不该反过来依赖出证层。

R14 之前这里是真倒置 —— ``core/compile.py`` 与 ``core/evaluate.py`` 为了取模型
指纹，写了四处 ``from policydsl.proofs import semantic``。修法是把那组**纯契约**
函数（模型指纹 / 路径口径 / 图的字符上限）下沉到 :mod:`policydsl.core.model_fp`。

## 为什么值得有一条用例

倒置是**能被重新引入的**，而重新引入时不会有什么东西变红：多一条 import 而已，
功能照跑。``core/model_fp.py`` 的 docstring 里写着「往这里加任何一条
``from policydsl.proofs import ...`` 都会把倒置原样搬回来」—— 那句是**文档**，
这条是**契约**。

## 为什么必须走 AST 而不是正则

``core/model_fp.py`` 的模块 docstring 里**就写着**「``from policydsl.proofs
import ...``」这串字（那是说明「别这么干」，不是 import）。按文本扫会把它当成
违规、把这条用例变成一个假警报源。反过来，只扫模块级 import 又会漏掉 R14 修掉的
那四处 —— **它们全在函数体里**。所以：按 AST 扫，且 ``ast.walk`` 走全树。
"""

from __future__ import annotations

import ast
import pathlib
import unittest

from policydsl.paths import REPO

CORE_DIR = REPO / "policydsl" / "core"

#: 判定层不许依赖的包（其后代模块一并禁止）。
FORBIDDEN = "policydsl.proofs"


def _imported_modules(src: str):
    """``[(行号, 模块名)]`` —— 这段源码里所有 import 的目标。

    走 ``ast.walk`` 全树，所以**函数体内的 import 也算了**：R14 要修的那四处
    正是函数级 import，只看模块级会整条漏掉。相对导入（``level > 0``）本仓
    ``core`` 侧不用，真有的话会以 ``module is None`` 出现，下面按违规处理。
    """
    out = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            out.extend((node.lineno, a.name) for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            out.append((node.lineno, node.module))   # 相对导入 -> None
    return out


def _violations_in(sources):
    """``[(文件名, 行号, 模块名)]`` —— 命中 ``FORBIDDEN`` 的 import。"""
    bad = []
    for name, src in sources.items():
        for lineno, mod in _imported_modules(src):
            if mod is None or mod == FORBIDDEN or mod.startswith(FORBIDDEN + "."):
                bad.append((name, lineno, mod))
    return bad


def _core_sources():
    return {str(p.relative_to(REPO)): p.read_text(encoding="utf-8")
            for p in sorted(CORE_DIR.glob("*.py"))}


class TestCoreDoesNotDependOnProofs(unittest.TestCase):
    """``policydsl/core`` 里的任何模块都不得 import ``policydsl.proofs``。"""

    def test_no_core_module_imports_proofs(self):
        bad = _violations_in(_core_sources())
        self.assertEqual(
            bad, [],
            "core 反向依赖了 proofs —— 判定层不该依赖出证编排层。"
            "要取模型指纹/路径口径/图的字符上限，用 `policydsl.core.model_fp`；"
            "确有别的正当理由，是这层的划分该被重新讨论，而不是偷偷加一条 import。\n"
            f"实测违规：{bad!r}")

    def test_the_scan_actually_covers_the_core_package(self):
        """别让上一条在**空集合**上全绿 —— 目录改位置/glob 写错时它会静默通过。"""
        srcs = _core_sources()
        self.assertIn("policydsl/core/compile.py", srcs)
        self.assertIn("policydsl/core/model_fp.py", srcs)
        self.assertGreaterEqual(len(srcs), 5, f"core 下只扫到 {len(srcs)} 个文件：{sorted(srcs)}")


class TestTheGateWouldNoticeAnInjection(unittest.TestCase):
    """门槛的**可证伪性**：真把倒置加回去，这条用例必须变红。

    没有这一条，「扫描器永远返回空」与「真的没有违规」在同一双眼睛下长得一模一样
    —— 而那是本仓反复记过的失败模式（空集合上全绿）。下面两种写法都是 R14 实际
    修过的形态，各钉一遍。
    """

    def test_it_detects_a_module_level_import(self):
        src = "from policydsl.proofs import semantic\n"
        self.assertEqual(_violations_in({"plant.py": src}),
                         [("plant.py", 1, "policydsl.proofs")])

    def test_it_detects_a_function_level_import(self):
        """R14 修的四处**全在函数体里** —— 这条钉住「函数级也扫得到」。"""
        src = ("def f():\n"
               "    from policydsl.proofs.semantic import model_manifest\n"
               "    return model_manifest()\n")
        self.assertEqual(_violations_in({"plant.py": src}),
                         [("plant.py", 2, "policydsl.proofs.semantic")])

    def test_it_accepts_the_replacement(self):
        """换成 ``core.model_fp`` 就不算违规 —— 否则这条门槛会逼人绕路走。"""
        self.assertEqual(
            _violations_in({"ok.py": "from policydsl.core import model_fp\n"}), [])

    def test_prose_in_a_docstring_is_not_an_import(self):
        """``core/model_fp.py`` 的 docstring 里就写着那串字（作为反例说明）。

        这正是本模块必须走 AST 的理由：按文本扫会把它误判成违规。
        """
        src = '"""别写 ``from policydsl.proofs import semantic`` —— 那是倒置。"""\n'
        self.assertEqual(_violations_in({"doc.py": src}), [])


if __name__ == "__main__":
    unittest.main()
