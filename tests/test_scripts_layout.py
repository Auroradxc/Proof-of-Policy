"""``scripts/`` 分组的**机械化**保障（不是靠人眼，也不是靠谁想起来跑 demo）。

这套用例的存在理由很具体：``scripts/`` 的每个脚本都自己写一行
``sys.path.insert(0, …/scripts)`` 再 ``from _bootstrap import …``，**这一行是
按层数写的**（``parents[1]``）。脚本再搬一次家，这一行就会静默指错 —— 而
「静默」正是最贵的：``policydsl/`` 拆包时，同一个毛病让 66 个用例一起红；
换成 ``scripts/`` 这侧，坏掉的是**跑 demo 才会走到的路径**，单测可能全绿。

所以这里把三件事钉死：

1. :class:`TestEveryScriptImports` —— 每个脚本都能被**导入**（不执行 ``main``），
   且它看到的 ``REPO`` 就是仓库根。搬家弄坏引导，这里当场红。
2. :class:`TestBootstrapSearchesMarkers` —— ``_bootstrap`` 是**按标记搜索**仓库根，
   不数层数：把它放进一个临时目录树的任意深度，仍能找到根。
3. :class:`TestGroupsAreCollisionFree` —— 5 个组目录会**并排**放进 ``sys.path``
   （见 ``scripts/_bootstrap.py`` 的设计说明），所以组内文件名不能重名。
   这条不变量是 ``bootstrap()`` 成立的前提，锁住它。
"""

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

#: 与 ``scripts/_bootstrap.py`` / ``policydsl/paths.py`` 相同的标记对
MARKERS = ("policydsl", "circuits")


def _script_modules():
    """``scripts/<组>/<X>.py`` → 点号模块名（``_bootstrap.py`` 自己不算脚本）。"""
    out = []
    for p in sorted(SCRIPTS.glob("*/*.py")):
        if p.name == "_bootstrap.py":
            continue
        out.append((p, ".".join(p.relative_to(REPO).with_suffix("").parts)))
    return out


class TestEveryScriptImports(unittest.TestCase):
    """每个脚本都能导入，且 ``REPO`` 指向仓库根。"""

    def test_at_least_one_script_and_five_groups(self):
        """先确认这套用例**真的在测东西** —— 别在空集合上全绿。"""
        mods = _script_modules()
        self.assertGreaterEqual(len(mods), 10, f"只发现 {len(mods)} 个脚本，太少了")
        groups = sorted({p.parent.name for p, _ in mods})
        self.assertEqual(groups, ["anchor", "demo", "ops", "prove", "verify"])

    def test_every_script_imports_and_agrees_on_repo_root(self):
        """逐个导入；脚本里若有 ``REPO``，必须等于仓库根。

        导入而**不执行** ``main``：脚本都把入口放在 ``if __name__ == "__main__"``
        里，所以这样跑没有副作用（实测每个 ≈0.04 s）。这也是**故意**不写
        ``--help`` 那种跑法 —— 万一某天有个脚本没接 argparse，``--help`` 会被它
        当普通参数照跑不误。
        """
        mods = _script_modules()
        for path, mod in mods:
            with self.subTest(script=mod):
                code = (
                    f"import json, sys, importlib\n"
                    f"sys.path.insert(0, {str(REPO)!r})\n"
                    f"m = importlib.import_module({mod!r})\n"
                    f"print(json.dumps({{'repo': str(getattr(m, 'REPO', ''))}}))\n"
                )
                r = subprocess.run([sys.executable, "-c", code], cwd=str(REPO),
                                   capture_output=True, text=True, timeout=120)
                self.assertEqual(
                    r.returncode, 0,
                    f"{mod} 导入失败（引导多半坏了）：\n{r.stderr}")
                got = json.loads(r.stdout.strip().splitlines()[-1])["repo"]
                self.assertTrue(got, f"{mod} 没有把 REPO 绑成模块级名字")
                self.assertEqual(Path(got), REPO,
                                 f"{mod} 看到的 REPO 不是仓库根")


class TestBootstrapSearchesMarkers(unittest.TestCase):
    """``_bootstrap`` 按标记搜索仓库根（深度无关），并在找不到时响亮报错。"""

    @staticmethod
    def _load_from(copy_at: Path):
        """把 ``_bootstrap.py`` 的副本当独立模块加载，返回该模块。"""
        spec = importlib.util.spec_from_file_location("_bootstrap_probe", copy_at)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    @staticmethod
    def _plant_tree(root: Path, with_scripts=True) -> Path:
        """在 ``root`` 下种一棵最小的仓库树，返回 ``scripts/`` 的位置。"""
        for m in MARKERS:
            (root / m).mkdir(parents=True, exist_ok=True)
        if not with_scripts:
            return root
        s = root / "scripts"
        s.mkdir(parents=True, exist_ok=True)
        shutil.copy(SCRIPTS / "_bootstrap.py", s / "_bootstrap.py")
        return s

    def test_finds_root_in_a_foreign_tree(self):
        """换一棵**陌生**的目录树，同样能找到根 —— 说明是搜出来的，不是写死的。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "proj"
            s = self._plant_tree(root)
            mod = self._load_from(s / "_bootstrap.py")
            self.assertEqual(mod.REPO, root)
            self.assertEqual(mod.SCRIPTS, s)

    def test_raises_loudly_when_markers_absent(self):
        """缺标记就抛 ``RuntimeError``，且错误信息说清找的是什么。"""
        with tempfile.TemporaryDirectory() as tmp:
            s = Path(tmp).resolve() / "scripts"
            s.mkdir(parents=True)
            shutil.copy(SCRIPTS / "_bootstrap.py", s / "_bootstrap.py")
            with self.assertRaises(RuntimeError) as cm:
                self._load_from(s / "_bootstrap.py")
            self.assertIn("policydsl", str(cm.exception))
            self.assertIn("circuits", str(cm.exception))

    def test_raises_when_scripts_is_not_at_the_root(self):
        """``_bootstrap.py`` 不在 ``<根>/scripts/`` 就报错，别静默接错树。

        这条守的是**嵌套 checkout** 那种事故：仓库里若又出现一份
        ``policydsl/`` + ``circuits/``，标记搜索会找到更外面那棵，于是
        ``sys.path`` 里混进一个陌生仓库。宁可响亮报错。
        """
        with tempfile.TemporaryDirectory() as tmp:
            outer = Path(tmp).resolve()
            self._plant_tree(outer, with_scripts=False)
            deep = outer / "a" / "scripts"
            deep.mkdir(parents=True)
            shutil.copy(SCRIPTS / "_bootstrap.py", deep / "_bootstrap.py")
            with self.assertRaises(RuntimeError) as cm:
                self._load_from(deep / "_bootstrap.py")
            self.assertIn("scripts/ 的位置不对", str(cm.exception))

    def test_bootstrap_is_idempotent_and_orders_repo_first(self):
        """连调两次不多塞路径；``REPO`` 排在脚本组前面。

        在**子进程**里、``cwd`` 是个临时空目录时做 —— 否则 unittest runner 早就
        把仓库根放进 ``sys.path`` 了，那条「顺序」断言会变成在测 runner 的行为。
        """
        with tempfile.TemporaryDirectory() as tmp:
            code = (
                "import sys, json\n"
                f"sys.path.append({str(SCRIPTS)!r})\n"
                "import _bootstrap as B\n"
                "B.bootstrap(); once = list(sys.path); B.bootstrap()\n"
                "print(json.dumps({'same': once == sys.path,\n"
                "                  'head': sys.path[:8],\n"
                "                  'repo': str(B.REPO),\n"
                "                  'groups': [str(B.SCRIPTS / g) for g in B.GROUPS]}))\n"
            )
            r = subprocess.run([sys.executable, "-c", code], cwd=tmp,
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            d = json.loads(r.stdout.strip().splitlines()[-1])
            self.assertTrue(d["same"], "bootstrap() 不幂等")
            head = d["head"]
            self.assertIn(d["repo"], head)
            for g in d["groups"]:
                self.assertIn(g, head)
            self.assertLess(head.index(d["repo"]), head.index(d["groups"][0]),
                            "REPO 必须排在脚本组前面，否则同名模块会被脚本遮住")


class TestGroupsAreCollisionFree(unittest.TestCase):
    """5 个组目录并排进 ``sys.path``，所以组间不能有同名文件。"""

    def test_no_duplicate_basenames_across_groups(self):
        seen = {}
        dupes = []
        for p in sorted(SCRIPTS.glob("*/*")):
            if not p.is_file():
                continue
            if p.name in seen:
                dupes.append(f"{p.name}：{seen[p.name]} 与 {p} 重名")
            else:
                seen[p.name] = p
        self.assertEqual(dupes, [], "组间重名会让 `import <name>` 结果取决于 "
                                    "sys.path 顺序（见 scripts/_bootstrap.py 的设计说明）")

    def test_scripts_root_holds_only_bootstrap_groups_and_examples(self):
        """``scripts/`` 根上只该有 ``_bootstrap.py`` + 5 个组 + ``examples/``。

        ``examples/`` 是**输入样本与 demo 产物**，不是脚本，故意不分组
        （见 docs/dev-plan.md §5.6.2）。多出来的东西要么是误提交的产物，
        要么是新加的东西没想清楚放哪。
        """
        allowed = {"_bootstrap.py", "__pycache__", "examples", "anchor", "demo",
                   "ops", "prove", "verify"}
        stray = sorted(p.name for p in SCRIPTS.iterdir()
                       if p.name not in allowed and not p.name.startswith("."))
        self.assertEqual(stray, [], f"scripts/ 根上出现了计划外的东西：{stray}")


if __name__ == "__main__":
    unittest.main()
