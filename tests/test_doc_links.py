"""文档里的**仓库内链接**必须指得到东西（R1 的第三条 CI 闸门）。

这个仓库把文档当交接面用：`docs/README.md` 是导航，`modules/*.md` 是各板块的
权威，`dev-plan.md` 是进度。链接一旦指空，读的人**不会**得到报错 —— 他要么以为
自己看错了路径，要么以为那份文件没写。这正是本仓反复讲的「不响的失败」，只不
过发生在文档层。而它发生得非常自然：重命名一个文件、把 `docs/x.md` 挪进
`docs/modules/`、删一节连同它的引用 —— 编辑器不会拦，review 也容易看漏。

**判据**（只查「看起来就是仓库内路径」的链接）：

1. 目标以 ``./`` / ``../`` / ``/`` 开头，或
2. 目标以已知文件后缀结尾（``.md`` / ``.py`` / ``.rs`` / …）。

``http(s)://``、``mailto:``、纯锚点 ``#…`` 一概跳过 —— 外链断不断不是这个仓库
能保证的事（也不该让 CI 去连网）。

**为什么要有 `test_detects_a_dangling_link` 这条自检**：前两条断言都是「没找到
坏链接」，而一个**正则写坏了**、或 `rglob` 没匹配到任何文件的检查器，也会全绿。
所以这里拿一份**已知含有坏链接**的合成文档喂给同一个检查函数，要求它**必须
报出来** —— 检查器本身也要能失败。
"""

import re
import tempfile
import unittest
from pathlib import Path
from typing import Iterable, Iterator, List, Tuple

REPO = Path(__file__).resolve().parents[1]

#: ``[文字](目标)`` 或 ``[文字](目标 "标题")``。``![...]``（图片）也一并覆盖 ——
#: 图片同样是仓库内文件，指空了同样没人报错。
_LINK = re.compile(r'!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)')

#: 「看起来就是仓库内文件」的后缀。没有后缀的裸路径（如 ``docs/README``）不查 ——
#: 判断它是不是路径要靠猜，而猜错会把检查器本身变成噪声源。
_SUFFIXES = (".md", ".py", ".rs", ".json", ".jsonl", ".txt", ".sh", ".yml", ".yaml",
             ".toml", ".pdf", ".png", ".svg", ".hex", ".bin", ".tex")

#: 非仓库内目标的前缀。
_SKIP_PREFIXES = ("http://", "https://", "mailto:", "#", "<", "data:")

#: 扫描范围：仓库里全部 Markdown。``.git/`` 与虚拟环境不在其内。
_SCAN_SKIP_DIRS = (".git", ".venv", "node_modules", "target", "out")


def _is_repo_path(target: str) -> bool:
    """这个链接目标看起来是不是「仓库内的某个文件」？"""
    if target.startswith(_SKIP_PREFIXES):
        return False
    base = target.split("#", 1)[0]          # 去掉 ``file.md#小节`` 的锚点
    if not base:
        return False                        # 纯锚点：同一文档内跳转
    return base.startswith(("./", "../", "/")) or base.endswith(_SUFFIXES)


def _iter_links(docs: Iterable[Tuple[Path, str]]) -> Iterator[Tuple[Path, str]]:
    """逐个产出 ``(文档路径, 链接目标)``，只含看起来是仓库内路径的那些。"""
    for path, text in docs:
        for m in _LINK.finditer(text):
            if _is_repo_path(m.group(1)):
                yield path, m.group(1)


def dangling_links(docs: Iterable[Tuple[Path, str]]) -> List[str]:
    """返回指空的链接（``文档 -> 目标`` 的可读描述），空列表表示全部指得到。

    以 ``/`` 开头的目标按**仓库根**解释（LaTeX 侧边注与少数文档用它指根），
    其余按**文档所在目录**解释 —— 即 Markdown 渲染器与 GitHub 的口径。
    """
    bad: List[str] = []
    for path, target in _iter_links(docs):
        base = target.split("#", 1)[0]
        resolved = (REPO / base.lstrip("/")) if base.startswith("/") else (path.parent / base)
        if not resolved.exists():
            try:
                shown = path.relative_to(REPO)
            except ValueError:
                shown = path
            bad.append(f"{shown} -> {target}")
    return bad


def _repo_docs() -> List[Tuple[Path, str]]:
    """仓库里全部 Markdown 文档的 ``(路径, 正文)``。"""
    docs = []
    for p in sorted(REPO.rglob("*.md")):
        rel = p.relative_to(REPO)
        if any(part in _SCAN_SKIP_DIRS for part in rel.parts):
            continue
        docs.append((p, p.read_text(encoding="utf-8", errors="replace")))
    return docs


class TestDocLinks(unittest.TestCase):
    """文档里的仓库内链接：全部指得到，且检查器本身不是空的。"""

    def test_no_dangling_repo_links(self):
        """任何一条指空的仓库内链接都算失败 —— 文档层没有别的闸门拦这个。"""
        bad = dangling_links(_repo_docs())
        self.assertEqual(
            [], bad,
            "这些文档链接指不到文件（改名/搬家/删节后没跟着更新）：\n  "
            + "\n  ".join(bad))

    def test_census_is_not_vacuous(self):
        """扫描确实覆盖了仓库，而不是「一份文档都没读、一条链接都没找到」。

        没有这一条，`rglob` 换个目录、或 `_LINK` 写错一个字符，前一条会照样全绿。
        阈值取实测值的**下界**（实测 47 份文档 / 274 条路径型链接，2026-09-17），
        留出余量：文档只增不减时它永远不会误报，而检查器一旦失效就会当场红。
        """
        docs = _repo_docs()
        self.assertGreaterEqual(len(docs), 40, "扫到的 Markdown 文档太少，扫描范围可能错了")
        n = sum(1 for _ in _iter_links(docs))
        self.assertGreaterEqual(n, 200, f"只找到 {n} 条路径型链接 —— 检查器可能失效了")

    def test_detects_a_dangling_link(self):
        """**检查器自己也要能失败**：喂一份已知含坏链接的合成文档，必须报出来。

        用临时目录里的真文件当「好链接」的靶子：只断言「坏链接被报出」，不断言
        好链接被放过 —— 后者由 `test_no_dangling_repo_links` 在真实文档上负责。
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "real.md").write_text("# 真的在\n", encoding="utf-8")
            doc = root / "doc.md"
            good, bad = "[好](./real.md)", "[坏](./not-here.md)"
            # 好链接在前、坏链接在后，两条都被扫描到（同一个正则、同一次遍历）。
            bad_found = dangling_links([(doc, f"{good}\n{bad}\n")])
        self.assertEqual(1, len(bad_found), f"应当恰有一条坏链接被报出，实际：{bad_found}")
        self.assertIn("not-here.md", bad_found[0])

    def test_external_and_anchor_links_are_skipped(self):
        """外链、锚点、纯文字不算「仓库内路径」—— 否则 CI 会去连网或误报。"""
        doc = Path("/tmp/whatever.md")
        skipped = ["https://example.com/x.md", "#某一节", "mailto:a@b.c",
                   "docs/README", "说明文字"]
        self.assertEqual([], dangling_links([(doc, " ".join(f"[t]({t})" for t in skipped))]))


if __name__ == "__main__":
    unittest.main()
