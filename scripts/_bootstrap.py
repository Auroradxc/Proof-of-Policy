"""脚本层的引导：定位仓库根，并把脚本目录装进 ``sys.path``。

**为什么需要它。** ``scripts/`` 下每个脚本原本都在开头自己写两行 ——

    REPO = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(REPO))

平铺时 ``parent.parent`` **恰好**等于仓库根；按用途分成 5 组之后，同一个式子算出来
是 ``scripts/``，16 个脚本会一起失灵。这与 ``policydsl/`` 拆包时撞到的是**同一个
巧合**（见 ``docs/dev-plan.md`` §5.6.7），修法也一样：把「仓库根在哪」收敛到一处，
并且**搜索而不是数层数**。

用法（脚本开头的三行）::

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/
    from _bootstrap import REPO, bootstrap  # noqa: E402

    bootstrap()

那第一行是**有意的取舍**：让 16 个文件各做一次标记搜索，等于把同一段定位逻辑抄 16 遍,
正是本模块要消除的东西。代偿是两条机械化保障 —— 本模块 :func:`bootstrap` 自查
``scripts/`` 的位置（静默失败变响亮失败），以及 ``tests/test_scripts_layout.py``
把每个脚本都跑一遍 ``--help``，搬家弄坏了当场红。
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final, Tuple

#: 5 个脚本组。组内文件名两两不同名，所以可以**并排**放进 ``sys.path`` ——
#: 这正是今天「平铺命名空间」的语义，只是物理上分了目录。
GROUPS: Final[Tuple[str, ...]] = ("demo", "prove", "verify", "anchor", "ops")

#: 仓库根的判定标记：这两个目录同时存在才算仓库根。
#: 与 ``policydsl/paths.py`` 用的是同一对标记，改一处要改两处。
_MARKERS: Final[Tuple[str, ...]] = ("policydsl", "circuits")

#: 本文件所在目录，即 ``<repo>/scripts``。
SCRIPTS: Final[Path] = Path(__file__).resolve().parent


def _find_repo(start: Path) -> Path:
    """从 ``start`` 向上找同时含 ``policydsl/`` 与 ``circuits/`` 的目录。"""
    for cand in (start, *start.parents):
        if all((cand / m).is_dir() for m in _MARKERS):
            return cand
    raise RuntimeError(
        "找不到仓库根：从 "
        f"{start} 向上遍历未发现同时含 "
        + " 与 ".join(f"`{m}/`" for m in _MARKERS)
        + " 的目录。scripts/_bootstrap.py 必须待在仓库内的 scripts/ 下；"
        "若你把 scripts/ 单独复制到了别处，请连同仓库一起使用。"
    )


#: 仓库根。由 :func:`_find_repo` **搜索**得出，不依赖本文件在目录树里的深度。
REPO: Final[Path] = _find_repo(SCRIPTS)

if SCRIPTS != REPO / "scripts":  # pragma: no cover —— 只在仓库被搬坏时触发
    raise RuntimeError(
        f"scripts/ 的位置不对：_bootstrap.py 在 {SCRIPTS}，但按标记找到的仓库根 "
        f"{REPO} 下的 scripts/ 不是它。这通常意味着仓库里出现了第二份 "
        "policydsl/ + circuits/ 组合（比如嵌套 checkout）。"
    )


def bootstrap() -> Path:
    """把 ``REPO``、``SCRIPTS`` 与 5 个组目录装进 ``sys.path``；**幂等**。

    顺序（从高到低优先级）：``REPO`` → ``SCRIPTS`` → 5 个组。
    ``REPO`` 在最前，是为了让 ``import policydsl``、``import bench_proofs`` 这类
    走仓库根的导入不被同名脚本遮住。

    :return: ``REPO``，方便调用点写成 ``REPO = bootstrap()``。
    """
    wanted = [REPO, SCRIPTS, *(SCRIPTS / g for g in GROUPS)]
    for p in reversed(wanted):
        s = str(p)
        if s not in sys.path:
            sys.path.insert(0, s)
    return REPO


__all__ = ["GROUPS", "REPO", "SCRIPTS", "bootstrap"]
