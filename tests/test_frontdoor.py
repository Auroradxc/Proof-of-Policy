"""``policydsl`` 的门面（R12）：``__all__`` 是一份**承诺**，这组用例管住它别悄悄漏。

为什么值得单独一组用例。``from policydsl import Policy`` 是本包对外的稳定面 ——
模块 docstring 自己写着「本模块的门面是稳定的」。而 ``__all__`` 出问题时，
**没有任何东西会报错**：

- **漏掉一个名字**：``from policydsl import *`` 的使用者拿不到它，报错发生在
  **他的**代码里，不在本仓的 CI 里；
- **混进一个解析不了的名字**（拼错、被删、搬家没同步）：``import *`` 直接抛
  ``AttributeError``，而本包的测试若都只 ``from policydsl import Policy`` 点名导入，
  就一个都碰不到；
- **重名**：``len(__all__)`` 与实际导出的符号数对不上，而那个长度常被人当
  「门面有多大」读；
- **门面递出来的是另一个对象**（比如本地定义了个同名的包装/别名）：名字还在、
  也解析得了，但语义已经不是子包里的那一个了。

四条都不在「跑一遍看看」的射程里 —— 今天全绿只说明**今天**没漏。

**与验收快照第 6 面（``6_import_surface``）的分工**，两者都要：

| | 记的是 | 谁确认 | 何时红 |
|---|---|---|---|
| ``tests/acceptance_baseline.json`` | 这份名单的**内容** | **人**（重新采集 + diff 进提交）| 名单变了就红 —— 那是「变更被承认」 |
| 本文件 | 名单的**不变量**（不重不漏、能解析、与命名空间一致） | 不需要人 | 名单**坏**了才红 |

只有快照，改名单会退化成「反正重采一次就绿了」；只有不变量，名单被谁加了
十几个名字也没人看见。
"""

import inspect
import sys
import types
import unittest

import policydsl


def declared() -> list:
    return list(getattr(policydsl, "__all__", []))


def public_namespace() -> set:
    """包命名空间里**有意公开**的那些名字。

    排除两类：

    - ``_`` 开头的（含 ``__version__``、``__all__`` 自己）—— 按 Python 的约定
      就是「不是门面的一部分」；
    - **子模块对象**（``policydsl.core``、``policydsl.evidence``…）。它们出现在
      命名空间里是 ``import policydsl.core.model`` 的**副产物**，不是 ``__init__``
      有意放出来的东西；谁 ``import`` 谁就会把它们绑上去，绑了哪个取决于那条
      import 语句，**不适合当契约**。子包该不该进门面是另一个问题（见本文件末尾）。
    """
    return {k for k, v in vars(policydsl).items()
            if not k.startswith("_") and not isinstance(v, types.ModuleType)}


class TestAllIsWellFormed(unittest.TestCase):
    """``__all__`` 的**形状**：非空、不重、都解析得了。"""

    def test_it_is_declared_and_not_a_stub(self):
        """下界，避免下面几条在空列表上「全绿」。

        本仓反复栽过的坑（空集合上全绿）：``__all__ = []`` 时，「没有重名」「没有
        解析不了的名字」全都成立。所以先钉住它不是空的。
        """
        names = declared()
        self.assertGreaterEqual(len(names), 10,
                                f"门面只剩 {len(names)} 个符号，像是被清空了")

    def test_no_duplicates(self):
        names = declared()
        dupes = sorted({n for n in names if names.count(n) > 1})
        self.assertEqual(dupes, [],
                         "`__all__` 里有重名 —— `len(__all__)` 会撒谎，"
                         "而那个长度常被当「门面有多大」读")

    def test_every_name_resolves(self):
        missing = sorted(n for n in declared() if not hasattr(policydsl, n))
        self.assertEqual(missing, [],
                         "`__all__` 声明了却取不到 —— `from policydsl import *` "
                         "会直接抛 AttributeError")


class TestAllMatchesTheNamespace(unittest.TestCase):
    """``__all__`` 与包的命名空间**逐名相符** —— 不多不少。"""

    def test_all_is_exactly_the_public_namespace(self):
        """两个方向都查。

        **少**（命名空间里有、``__all__`` 里没有）：那个名字能被
        ``import policydsl; policydsl.foo`` 拿到，却不在 ``import *`` 里 ——
        同一条门面两套可见性。
        **多**（``__all__`` 里有、拿不到）：由上一条（都解析得了）覆盖。

        注意这条**不含**「``__all__`` 里的名字必须来自 ``policydsl`` 自己」——
        那条在 :class:`TestTheDoorHandsOutTheRealObjects` 里。
        """
        extra = sorted(public_namespace() - set(declared()))
        self.assertEqual(extra, [],
                         "这些名字绑在 `policydsl` 上却不在 `__all__` 里 —— "
                         "点得到但 `import *` 拿不到")

    def test_star_import_yields_exactly_all(self):
        """``from policydsl import *`` 带出来的，与 ``__all__`` 逐名相符。

        上一条比的是「命名空间 vs 名单」，这一条比的是「**import \* 的实际效果**
        vs 名单」—— 中间隔着 CPython 的解释，值得让机器自己走一遍，而不是由我们
        推断「按语言规则它应该相等」。
        """
        ns: dict = {}
        exec("from policydsl import *", ns)  # noqa: S102 — 被测的就是这条语句
        got = {k for k in ns if not k.startswith("__")}
        self.assertEqual(got, set(declared()),
                         "`import *` 的结果与 `__all__` 不符")


class TestTheDoorHandsOutTheRealObjects(unittest.TestCase):
    """门面递出来的是**子包里那一个**，不是同名的复制品。"""

    def test_each_export_is_the_same_object_as_in_a_submodule(self):
        """``policydsl.X`` 必须**就是**某个已加载子模块里同名的那个东西。

        只比名字不够：``Policy = SomeWrapper`` 这种也能「解析得了、名字对得上」，
        但语义已经换了。要求是**同一个对象**（可调用物）或**相等的值**（常量）——
        谁在门面上挂了个转发/别名/复制品，这条当场红。

        **扫描 ``sys.modules``，而不是在用例里抄一张「谁来自哪个模块」的表**：
        抄一份就等于把 ``__init__.py`` 的 import 语句写了两遍，搬家时必漏改一处。
        限定在 `import policydsl` 之后**已经加载**的那几个模块，也不去
        `walk_packages` 主动 import 别的子包 —— 那会把 ``adapters``（唯一允许带
        可选第三方依赖的子包）也拉进来，给一条门面用例引入它不需要的脆弱性。

        ⚠️ **可调用物这条是「存在同一个对象」，不是「所有同名者都是同一个对象」。**
        本仓**确实**有两个同名不同物的函数：门面的 ``verify_chain`` 来自
        ``policydsl.evidence.trace``（吃 ``ToolReceipt``/``ToolSeal`` 对象），
        ``adapters/langchain_adapter.py`` 里另有一个同名的是适配层自己的（吃原始
        dict 载荷）—— 两者都对，「同名」只是同一个领域词用在了两层。
        写成「所有同名模块必须一致」会在**别的用例把 adapters 也 import 进来之后**
        才红，红得还莫名其妙。（这是实测踩到的：单跑本文件时绿、跑全量时红。）

        常量则相反，**每个**定义了它的模块都要与门面一致：``SPEC_VERSION`` 这种
        在两个模块里取值不同，门面递的是哪一份就取决于 import 顺序 —— 那本身就是
        个该修的问题，不能放过。
        """
        loaded = {n: m for n, m in sys.modules.items()
                  if n.startswith("policydsl") and isinstance(m, types.ModuleType)}
        for name in declared():
            obj = getattr(policydsl, name)
            places = [m for m in loaded.values() if m is not policydsl and hasattr(m, name)]
            self.assertTrue(places,
                            f"`{name}` 在门面之外、任何一个已加载的 policydsl 子模块里"
                            "都没有 —— 它是在 `__init__.py` 里自造的")
            if inspect.isroutine(obj) or inspect.isclass(obj):
                same = [m for m in places if getattr(m, name) is obj]
                self.assertTrue(
                    same,
                    f"`{name}` 在已加载的子模块里找不到**同一个对象** —— 门面递出来的"
                    f"是复制品/别名。同名但不同的模块有：{[m.__name__ for m in places]}")
            else:
                for m in places:
                    self.assertEqual(getattr(m, name), obj,
                                     f"`{name}` 与 `{m.__name__}.{name}` 不等 —— "
                                     "门面递的是哪一份会取决于 import 顺序")

    def test_each_callable_export_is_defined_in_this_package(self):
        """可调用的出口符号，其**定义模块**必须在 ``policydsl`` 里。

        门面把**第三方**的东西转出去，等于让「本层只用标准库」这条对使用者的承诺
        失效 —— 他 ``import policydsl`` 就顺带依赖上了别的东西。

        只查可调用物：常量（本仓只有 ``SPEC_VERSION``）是普通的 ``str``，**没有
        ``__module__``**，``inspect.getmodule`` 对它返回 ``None``。这不是漏检 ——
        常量的口径由上面那条「与子模块里的同名值相等」覆盖，而「它来自哪个包」
        对一个字符串本来就不是个能问的问题。**别把这条改成对常量也成立的样子**：
        那要么需要一张硬编码的映射，要么要靠猜。
        """
        foreign = []
        for name in declared():
            obj = getattr(policydsl, name)
            if not (inspect.isroutine(obj) or inspect.isclass(obj)):
                continue
            mod = inspect.getmodule(obj)
            modname = getattr(mod, "__name__", "")
            if not (modname == "policydsl" or modname.startswith("policydsl.")):
                foreign.append((name, modname))
        self.assertEqual(foreign, [],
                         "门面里有不是本包定义的符号 —— 会把第三方依赖漏给使用者")


class TestSubpackagesAreReachable(unittest.TestCase):
    """模块 docstring 点名的六个子包**都要 import 得到**。

    门面只 re-export 了两个子包的符号（``core`` / ``evidence``），其余四个
    （``privacy`` / ``proofs`` / ``adapters`` / ``runtime``）是「按路径访问」的，
    不在 ``__all__`` 里 —— 这是**有意**的，不是遗漏。但既然 docstring 把它们
    列出来当门面的组成部分，就得有一条用例保证那六个名字**至少是真能 import 的**：
    docstring 是文档，这条是契约。
    """

    SUBPACKAGES = ("core", "privacy", "evidence", "proofs", "adapters", "runtime")

    def test_all_six_subpackages_import(self):
        import importlib

        for sub in self.SUBPACKAGES:
            with self.subTest(sub=sub):
                mod = importlib.import_module(f"policydsl.{sub}")
                self.assertIsNotNone(mod)

    def test_the_docstring_lists_them(self):
        """docstring 里点名的子包集合 == 上面那张表。

        防的是「加了第七个子包、docstring 忘了写」以及反过来的「docstring 里
        写着一个不存在的子包」—— 两者都只能靠人对齐，所以让机器来对。
        """
        doc = policydsl.__doc__ or ""
        for sub in self.SUBPACKAGES:
            with self.subTest(sub=sub):
                self.assertIn(f"policydsl.{sub}", doc,
                              f"`{sub}` 在用例里、却不在门面的 docstring 里")


if __name__ == "__main__":
    unittest.main()
