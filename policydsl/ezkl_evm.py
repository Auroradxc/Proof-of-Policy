"""ezkl 的 EVM 验证器接口封装（T2 的解，见 ``docs/plan-p0p1p2.md`` §9 待办 T2）。

**ezkl 是可选依赖**：本模块不在导入期 import ezkl（``policydsl`` 的其余部分是纯
标准库），只有真正调用 :func:`run` / :func:`create_verifier` 时才去找它。

## 问题：一个极具误导性的报错

ezkl 23.0.5 的 ``create_evm_verifier()`` / ``create_evm_vka()`` **看起来**是同步
函数（pyo3 的 ``#[pyfunction]``，签名里全是 ``str``/``bool``，``__doc__`` 也只提
"you will need solc installed"），但在**没有运行中的事件循环**时调用它会抛：

    RuntimeError: no running event loop

这条报错和 ezkl 的前置条件毫无关系 —— 它既不缺 solc、也不缺任何组件。真因是这组
API 内部走 ``pyo3-async-runtimes``：调用时会**立刻**向 Python 事件循环注册回调并
返回一个 ``asyncio.Future``。没有循环时，pyo3-async-runtimes 的
``get_running_loop()`` 转发到 CPython 的 ``asyncio.get_running_loop()``，于是抛出
上面那句话。

> 顺带说明它为什么"看起来不像 ezkl 报的错"：``no running event loop`` 这个字符串
> **不在** ``ezkl.abi3.so`` 里（``strings | grep`` 为 0 命中），它来自 CPython 的
> asyncio。二进制里能查到的是 ``pyo3_async_runtimes::get_running_loop`` —— 真正的
> 调用点。

## 正确用法

必须在事件循环内调用并 **await 返回的 Future**：

    >>> import asyncio, ezkl
    >>> asyncio.run(ezkl.create_evm_verifier(...))        # ✗ asyncio.run 要的是协程
    >>> await ezkl.create_evm_verifier(...)               # ✓ 在协程里

本模块的 :func:`run` 让调用方**继续写同步代码**（也可直接 ``await``
:func:`create_verifier` 的异步版本，见下）：

    >>> from policydsl import ezkl_evm
    >>> ezkl_evm.run(ezkl.create_evm_verifier, "vk.key", "settings.json",
    ...              "verifier.sol", "verifier.abi", "kzg.srs", False)
    True

## 顺带纠正：这条路径**不需要 solc**

``create_evm_verifier`` 的 docstring 说 "you will need solc installed in your
environment"，但实测（ezkl 23.0.5，本机）**该路径不调用 solc**：它只是把 Halo2
验证器模板的常量填好并写出 ``.sol`` / ``.abi``（``reusable=True`` 亦然，另有
:func:`create_vka` 产出 VK artifact）。全程 ~0.1 s，且把 ``PATH`` 里的 solc 拿掉
一样通过。所以 T2 原先写的两条备选（"先试 ezkl 12.x" / "绕开该 API 手写 Solidity
verifier"）**都不需要** —— 原阻塞是**调用方式**，不是依赖缺失。
"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from typing import Any, Optional

__all__ = ["available", "run", "create_verifier", "create_vka"]


def available() -> bool:
    """ezkl 是否可用（未安装时返回 False，不抛异常）。"""
    try:
        import ezkl  # noqa: F401
    except Exception:  # pragma: no cover - 取决于环境
        return False
    return True


def run(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """在**新建的事件循环**里执行一个 ezkl 的 async-包装函数并等它完成。

    ``fn`` 返回 ``asyncio.Future``（当前实现）或普通值时都能正确处理 —— 后者对应
    「上游哪天改回真同步」，那时本函数退化成一次普通调用，调用方无需改代码。

    注意：不能在**已在运行**的事件循环里调用（``asyncio.run`` 会拒绝）；那种场景
    直接 ``await fn(...)`` 即可。
    """
    async def _call() -> Any:
        r = fn(*args, **kwargs)
        return await r if inspect.isawaitable(r) else r

    return asyncio.run(_call())


# --------------------------------------------------------------------------- #
# 便捷包装：把参数名写清楚，省得调用方去数位置（ezkl 的签名很长且顺序不直观）
# --------------------------------------------------------------------------- #

def create_verifier(vk_path: Path | str, settings_path: Path | str,
                    sol_path: Path | str, abi_path: Path | str,
                    srs_path: Optional[Path | str] = None,
                    reusable: bool = False) -> bool:
    """生成 EVM 验证器合约源码（``.sol``）与 ABI（``.abi``）。

    ``reusable=True`` 时生成可复用变体（VK 走 :func:`create_vka` 单独部署）。
    **不调用 solc**（见模块 docstring 末节）。
    """
    import ezkl

    return run(ezkl.create_evm_verifier, str(vk_path), str(settings_path),
               str(sol_path), str(abi_path),
               None if srs_path is None else str(srs_path), reusable)


def create_vka(vk_path: Path | str, settings_path: Path | str,
               vka_path: Path | str,
               srs_path: Optional[Path | str] = None) -> bool:
    """生成 VK artifact（``reusable=True`` 的验证器部署时要用）。"""
    import ezkl

    return run(ezkl.create_evm_vka, str(vk_path), str(settings_path),
               str(vka_path), None if srs_path is None else str(srs_path))
