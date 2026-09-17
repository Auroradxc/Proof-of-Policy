"""仓库根的**唯一**出处。

## 为什么会有这个模块（一段真实的事故）

在 2026-09-17 把 `policydsl/` 拆成子包之前，有 **6 个模块各自**写着：

    REPO = Path(__file__).resolve().parent.parent

那在**平铺**布局下恰好等于仓库根，所以它能一直正常工作 —— 但那是**巧合，不是契约**。
文件一旦下沉一层（`policydsl/compose.py` → `policydsl/proofs/compose.py`），
`parent.parent` 就变成了 `policydsl/`，于是：

    POP_SCRIPT = policydsl/circuits/target/release/pop-script   ← 不存在

拆包那一步的验收闸门（667 个测试）把它炸了出来 —— **66 errors / 8 failures**，
报的是 `FileNotFoundError: .../policydsl/circuits/...`。修法不是给 6 处各补一层
`.parent`（下次再搬家还会错），而是把「仓库根在哪」收敛成**一处**、并且按**标记**
判断而不是数层数。

## 判据

只有**同时**含 `policydsl/` 与 `circuits/` 的目录才算仓库根。从本文件向上找，
第一个满足的即为答案。这样：

- 模块搬到任何深度都对；
- 别处复制一份单独的 `policydsl/` 而不带 `circuits/` 时，会**明确报错**而不是
  悄悄指向一个错误但存在的目录。
"""

from __future__ import annotations

from pathlib import Path

#: 同时出现才认定仓库根（单独一个都不够：`circuits/` 在纯 Rust 检出里也可能存在）
_MARKERS = ("policydsl", "circuits")


def find_repo(start: Path | str | None = None) -> Path:
    """从 ``start``（默认本文件）向上找仓库根，找不到就抛 ``RuntimeError``。"""
    here = Path(start or __file__).resolve()
    if here.is_file():
        here = here.parent
    for cand in (here, *here.parents):
        if all((cand / m).is_dir() for m in _MARKERS):
            return cand
    raise RuntimeError(
        "找不到仓库根：向上遍历未发现同时含 "
        + " 与 ".join(f"`{m}/`" for m in _MARKERS)
        + f" 的目录（起点 {here}）。若你把 policydsl/ 单独复制到了别处，"
        "请连同仓库一起使用，或显式传 start 指向仓库根。"
    )


#: 仓库根。**全仓唯一**，不要在别处再算一遍。
REPO: Path = find_repo()

__all__ = ["REPO", "find_repo"]
