"""语义规则的**模型契约**：模型指纹、路径口径、图的字符上限。

这一组函数原先住在 :mod:`policydsl.proofs.semantic` 里，而
:mod:`policydsl.core.compile` 与 :mod:`policydsl.core.evaluate` 为了取模型指纹
反过来 import 它 —— 那就是 ``core → proofs`` 的**分层倒置**：判定层去依赖出证
编排层，而两层的关系本该是反过来的。

搬过来的只是**纯契约**那部分：它们只读 ``semantic/`` 目录下的落盘产物
（``model.onnx`` / ``MODEL.sha256`` / ``training_report.json`` / ``artifacts/vk.ezkl``），
不 import ezkl、不 import torch，也不依赖 ``proofs`` 里的任何东西。ezkl 的出证与
验证逻辑**仍在** :mod:`policydsl.proofs.semantic` 里，由它反过来 re-import 本模块
—— 所以 ``semantic.model_manifest`` 这类调用（测试、``scripts/prove/ezkl_prove.py``、
``bench/``）拿到的是**同一个对象**，一个字都不用改。

## 硬约束：本模块不 import ``proofs``

本模块存在的全部理由就是让 ``core`` 不必 import ``proofs``。往这里加任何一条
``from policydsl.proofs import ...`` 都会把倒置原样搬回来。

## ``input_width`` 与顶层 ``semantic`` 包

:func:`input_width` 是本模块里唯一碰 ``policydsl`` **之外**东西的函数：它读
``semantic/features.py`` 的 ``MAX_CHARS``（图是定长的）。那个 import 是**函数级**的，
且 ``semantic/features.py`` 的模块级 import 是纯标准库（torch 只在真正构造网络时
延迟导入），所以本模块**导入期**不需要标准库之外的第三方依赖 —— 与这些函数原先
在 ``proofs/semantic.py`` 里的性质一致。
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

from policydsl.paths import REPO  # 仓库根的唯一出处（解析 semantic/ 目录用）
from policydsl.evidence.cert import sha256_file

__all__ = [
    "SemanticError", "SEMANTIC_VERSION", "ARTIFACT_NAMES", "model_dir",
    "onnx_sha256", "cached_onnx_sha256", "cached_file_sha256", "vk_path",
    "model_manifest", "input_width",
]



class SemanticError(ValueError):
    """语义规则的契约被违反（设置口径错、模型指纹不符、绑定对不上等）。"""


#: 语义规则的版本标签（进约束、进文档；语义一变就要改）。
SEMANTIC_VERSION = "pop-semantic-v1"


#: 落盘产物的文件名（``scripts/prove/ezkl_prove.py`` 与测试共用，避免两边写岔）。
#:
#: 说明：ezkl 对扩展名不作要求，这里刻意用 ``.ezkl`` 而不是 ``.key`` ——
#: ``.gitignore`` 里的 ``*.key`` 是给 P0-3 的 Ed25519 私钥用的，而 ``vk.ezkl``
#: **必须入库**（它是验证方唯一的凭据）。用 ``.key`` 会被那条规则静默吞掉。
ARTIFACT_NAMES: Dict[str, str] = {
    "settings": "settings.json",
    "compiled": "model.compiled",
    "srs": "kzg.srs",
    "vk": "vk.ezkl",
    "pk": "pk.ezkl",
    "proof": "proof.json",
    "manifest": "MANIFEST.json",
}


# --------------------------------------------------------------------------- #
# 模型指纹（信任边界 ① 的落地形式）
# --------------------------------------------------------------------------- #

def model_dir() -> Path:
    """``semantic/`` 目录（模型与产物的家）。"""
    return REPO / "semantic"


def onnx_sha256(path: Path | str | None = None) -> str:
    """``model.onnx`` 的 sha256（**现算**，不读 ``MODEL.sha256``）。

    现算是刻意的：约束里的 ``onnx_sha256`` 必须是对**文件字节**的承诺，而不是对
    另一个文本文件的转述 —— 后者可以被一起掉包。
    """
    p = Path(path) if path is not None else model_dir() / "model.onnx"
    if not p.exists():
        raise SemanticError(f"{p} 不存在 —— 先跑 python3 -m semantic.train 生成模型")
    return hashlib.sha256(p.read_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
# 指纹的进程内缓存 —— **只给热路径用**
#
# 为什么要有它：`evaluate.check` 每次判定都要为语义规则取一遍指纹，而指纹是
# 「读文件 + sha256」（`model.onnx` 156 KB + `vk.ezkl` 803 KB）。实测这占了
# `check()` 全部耗时的 **~76%**（581 µs 里的 ~440 µs），而 `check()` 是被
# `runtime/service.py` 逐请求调用的。指纹在这条路径上**不参与任何校验** ——
# 它只是填 `DelegatedConstraint` 的字段，真正的比对在 `verify_cert` 那侧
# （见 `evaluate.check` 里那段注释）。
#
# 边界划在哪，理由是什么：
#   * **热路径（本节的 cached_*）**：登记委托时取指纹，缓存。
#   * **校验路径（`onnx_sha256` / `model_manifest`）**：维持现算，一个字不改。
#     `model_manifest` 拿 `onnx_sha256` 与 `MODEL.sha256` 比对，是「模型有没有
#     被换过」的信任边界；按 mtime 命中缓存会漏掉「内容换了但 mtime/size 没变」
#     的调包。那条检查冷（编译/验证期各一次），不值得为它冒险。
#
# 缓存键带 `mtime_ns` 与 `size`，所以**进程内换了模型照样会被察觉**：文件一变，
# 键就变，缓存不命中，重新读盘。唯一的残留窗口是 stat 与 read 之间（TOCTOU），
# 影响面仅限上面说的那条非校验路径。
# --------------------------------------------------------------------------- #


def vk_path() -> Path:
    """``vk.ezkl``（ezkl 验证钥匙）的路径。

    路径口径收在这里：它原先只写在 ``compile._model_vkey`` 里，而判定路径也要用
    同一个文件 —— 两处各写一遍迟早写岔。
    """
    return model_dir() / "artifacts" / ARTIFACT_NAMES["vk"]


@lru_cache(maxsize=16)
def _sha256_of_file(path: str, mtime_ns: int, size: int) -> str:
    """按 ``(路径, mtime_ns, size)`` 缓存 :func:`cert.sha256_file` 的结果。

    **这里只做缓存，不做哈希** —— 摘要口径收在 ``policydsl.evidence.cert.sha256_file``
    一处（原先本函数自带一份分块实现，与另外 7 份逐字重复，见该函数的 docstring）。

    ``mtime_ns`` 与 ``size`` 是**缓存键**，不参与计算：文件换了就不认旧值。
    """
    return sha256_file(path)


def cached_file_sha256(path: Path | str) -> str:
    """:func:`_sha256_of_file` 的取指纹入口（stat 当前状态后查缓存）。"""
    p = Path(path)
    st = p.stat()
    return _sha256_of_file(str(p), st.st_mtime_ns, st.st_size)


def cached_onnx_sha256() -> str:
    """``model.onnx`` 指纹的**缓存版**（热路径用）。

    **不要在校验路径上用这个** —— 那边用 :func:`onnx_sha256`（现算）。
    两者的分工见本节开头的说明。缺文件时的报错与 :func:`onnx_sha256` 一致。
    """
    p = model_dir() / "model.onnx"
    if not p.exists():
        raise SemanticError(f"{p} 不存在 —— 先跑 python3 -m semantic.train 生成模型")
    return cached_file_sha256(p)


def model_manifest(directory: Path | str | None = None) -> Dict[str, Any]:
    """模型指纹清单：进约束、进产物、进测试。

    返回 ``onnx_sha256`` / ``head_sha256`` / ``feature_version`` / ``dims`` /
    ``max_chars`` / ``onnx_bytes``，并**当场核对** ``MODEL.sha256`` 与文件是否一致
    （不一致说明模型被换过或导出漂移了 —— 这是必须炸掉的情况）。

    ``semantic/`` 是模型侧，本函数只读它的落盘产物，不 import torch。
    """
    d = Path(directory) if directory is not None else model_dir()
    onnx_p = d / "model.onnx"
    head_p = d / "head.weights.json"
    rep_p = d / "training_report.json"
    sha_p = d / "MODEL.sha256"

    for p in (onnx_p, head_p, rep_p, sha_p):
        if not p.exists():
            raise SemanticError(f"{p} 不存在 —— 先跑 python3 -m semantic.train")

    got = onnx_sha256(onnx_p)
    want = sha_p.read_text(encoding="utf-8").strip()
    if got != want:
        raise SemanticError(
            f"model.onnx 的 sha256 与 MODEL.sha256 不符：\n  文件 {got}\n  记录 {want}\n"
            f"（模型被换过，或 ONNX 导出不再逐字节确定）")

    report = json.loads(rep_p.read_text(encoding="utf-8"))
    dims = report.get("dims") or {}
    return {
        "onnx_sha256": got,
        "onnx_bytes": onnx_p.stat().st_size,
        "head_sha256": hashlib.sha256(head_p.read_bytes()).hexdigest(),
        "feature_version": report.get("feature_version"),
        "semantic_version": SEMANTIC_VERSION,
        "max_chars": dims.get("max_chars"),
        "dim": dims.get("dim"),
        "hidden": dims.get("hidden"),
        "vocab": dims.get("vocab"),
        "num_rows": report.get("circuit_rows"),
    }


# --------------------------------------------------------------------------- #
# 图的字符上限（策略的 ``length_bound`` 必须对齐它）
# --------------------------------------------------------------------------- #


def input_width() -> int:
    """公开实例里**输入部分的长度**（= 图上限 ``MAX_CHARS``）。

    注意它**恒等于** ``MAX_CHARS``，与响应实际多长无关 —— :func:`encode_ids` 总会
    右补 PAD 到定长。所以「实例里前几个是输入」这句话里的「几个」是个常数，读
    ``len(encode(T))`` 去推它虽然碰巧也对，但会把「定长补位」这件事藏起来。
    """
    from semantic import features as F

    return int(F.MAX_CHARS)
