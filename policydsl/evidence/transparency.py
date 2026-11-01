"""签发完整性（定理 F2）的最小透明日志原型：**只追加 + 包含证明**。

本模块只做四件事，接口刻意小：

    log = TransparencyLog()
    idx = log.append(cert_digest)          # 追加一片叶子
    root = log.root()                      # 当前 Merkle 根
    proof = log.prove(idx)                 # 该叶子的包含证明
    verify_inclusion(cert_digest, proof)   # 验证包含

Merkle 原语**复用** :mod:`policydsl.proofs.session`（``MERKLE_NODE_DOMAIN`` 与 Rust
侧逐字节一致），本模块只加「日志条目 / 追加语义 / 检查点」这一层，不另写哈希。

## 与定理 F 的对应（不是无条件保证）

* 默认叶子 = ``cert_digest``，即 F2 里的 ``d = H(canonical(cert))``。
* :meth:`TransparencyLog.append` 接受可选 ``binding``（被交付的 ``T`` 的承诺、
  回执摘要等）。给了它，叶子 = ``H(domain ‖ d ‖ binding)``，日志条目就**绑定到
  被交付的工件**；不给则只绑定证书本身。这一区分对应证明债 **F-3**：
  只记 ``H(cert)`` 时，运营方可以记一张「另一条 ``T``」的证书。
* 追加本身**不是**「交付前必须追加」的外部义务（证明债 **F-1**）。本模块只提供
  机制；没有 F-O，定理 F1 的不可能性仍然适用。
* 本模块**不**实现 gossip / 一致性证明（证明债 **F-2**）。:meth:`checkpoint`
  给出 ``(size, root)``，调用方必须自己把它们**跨审计者/跨时间**比较，否则恶意
  日志可以给不同验证者看不同视图（split-view）。
* 本模块**不**强制「日志条目必须来自真实交付」（**F-4**）：抽样框若只抽日志，
  withholding 对手根本不进样本。见 ``bench/bench_issuance.py``。

## 只追加的边界

Python 对象可以被调用方改内部列表；本类不宣称是防篡改存储。它保证的是**协议层**
语义：``append`` 只增长、``prove`` 绑定的 ``(root, size, index)`` 在验证时被重算。
持久化/复制/公开可读属于部署问题，不在本原型内。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from policydsl.evidence import cert
from policydsl.proofs.session import (
    merkle_proof,
    merkle_root,
    verify_merkle_proof,
)

#: 叶子里「证书摘要 + 交付绑定」的域分隔前缀。只在给了 ``binding`` 时使用；
#: 默认叶仍等于 ``cert_digest``，以便与 F2 的 ``d = H(canonical(cert))`` 对上。
LEAF_BINDING_DOMAIN = b"pop-transparency-leaf-binding-v1"

#: 检查点 / 树头签名载荷的域标签（进 DSSE 载荷，便于人读）。
HEAD_DOMAIN = "pop-transparency-head-v1"


class TransparencyError(ValueError):
    """日志输入/证明形状不合法，或对空日志取根。"""


def _hex32(digest: str, what: str) -> str:
    """校验 32 字节十六进制摘要，返回规范化小写。"""
    if not isinstance(digest, str):
        raise TransparencyError(f"{what}必须是十六进制字符串，得到 {type(digest).__name__}")
    try:
        raw = bytes.fromhex(digest)
    except ValueError as exc:
        raise TransparencyError(f"{what}不是合法十六进制：{digest!r}") from exc
    if len(raw) != 32:
        raise TransparencyError(f"{what}不是 32 字节：{len(raw)} 字节")
    return raw.hex()


def entry_hash(cert_digest: str, binding: Optional[str] = None) -> str:
    """一片日志条目的叶子哈希。

    * ``binding is None`` → 叶子就是 ``cert_digest``（F2 的默认构造）；
    * 否则叶子 = ``SHA256(LEAF_BINDING_DOMAIN ‖ cert_digest ‖ binding)``。

    ``binding`` 用来把**被交付的工件**拴进日志（F-3）：它可以是
    ``response_binding``、交付回执摘要、或接收方签名的 ``H(T)``。具体取什么由
    部署决定；本原型只要求验证方能用**同一条**约定重算。
    """
    d = _hex32(cert_digest, "证书摘要")
    if binding is None:
        return d
    b = _hex32(binding, "交付绑定")
    return hashlib.sha256(LEAF_BINDING_DOMAIN + bytes.fromhex(d) + bytes.fromhex(b)).hexdigest()


@dataclass(frozen=True)
class Checkpoint:
    """某一时刻的日志视图：``size`` 片叶子、根 ``root``。

    **防 split-view 的起点，不是终点**：两个检查点只有在被跨审计者比较之后才有
    意义。本类不实现 gossip，也不实现一致性证明（F-2）。
    """

    size: int
    root: str

    def to_dict(self) -> Dict[str, Any]:
        return {"size": self.size, "root": self.root}


class TransparencyLog:
    """只追加 Merkle 日志的参考实现（每次 ``append`` 重算整棵树，Θ(n)）。

    参考实现的口径与 ``bench/results/baseline.md`` 的 Merkle 追加一致：**不是**
    RFC 6962 的增量 frontier。成本数字要按「重算根」读。
    """

    def __init__(self) -> None:
        self._entries: List[Dict[str, Any]] = []
        self._leaves: List[str] = []

    # -- 只读视图 --
    def __len__(self) -> int:
        return len(self._leaves)

    @property
    def size(self) -> int:
        return len(self._leaves)

    def root(self) -> str:
        """当前 Merkle 根。空日志**没有根**（不返回一个「空根」假值）。"""
        if not self._leaves:
            raise TransparencyError("空日志没有 Merkle 根；至少 append 一条再取根")
        return merkle_root(self._leaves)

    def checkpoint(self) -> Checkpoint:
        return Checkpoint(size=self.size, root=self.root())

    def entry(self, index: int) -> Dict[str, Any]:
        """第 ``index`` 条条目的**拷贝**（含 cert_digest / binding / leaf）。"""
        if not 0 <= index < len(self._entries):
            raise TransparencyError(f"条目下标越界：{index}（共 {len(self._entries)} 条）")
        return dict(self._entries[index])

    # -- 追加 --
    def append(self, cert_digest: str, *, binding: Optional[str] = None) -> int:
        """追加一条证书摘要，返回其下标（从 0 起）。

        重复追加同一个摘要**是允许的**：日志是「事件序列」，不是集合。两个下标
        对应两次交付；包含证明必须绑定到具体下标，不能互相重放（见
        :func:`verify_inclusion` 对 ``leaf`` 的检查）。
        """
        leaf = entry_hash(cert_digest, binding)
        index = len(self._leaves)
        self._entries.append({
            "index": index,
            "cert_digest": _hex32(cert_digest, "证书摘要"),
            "binding": None if binding is None else _hex32(binding, "交付绑定"),
            "leaf": leaf,
        })
        self._leaves.append(leaf)
        return index

    # -- 证明 --
    def prove(self, index: int) -> Dict[str, Any]:
        """第 ``index`` 条条目的包含证明。

        证明绑定的不只是叶子，还有**取证明时的** ``(root, size)``：验证方拿它
        与自己的检查点比较，才能发现「这是旧视图」或「这是另一棵树」。
        """
        if not 0 <= index < len(self._leaves):
            raise TransparencyError(f"叶子下标越界：{index}（共 {len(self._leaves)} 片）")
        path = merkle_proof(self._leaves, index)
        return {
            "index": index,
            "size": self.size,
            "root": self.root(),
            "leaf": self._leaves[index],
            "path": [[side, sib] for side, sib in path],
        }

    # -- 树头（可选签名；验签本身不在本模块的「最小接口」里） --
    def head(self, signer: Any = None, *, ts: Optional[str] = None) -> Dict[str, Any]:
        """树头 ``{size, root, sth?}``。

        给了 ``signer`` 就用 :func:`policydsl.evidence.cert.sign_payload` 签一个
        DSSE 信封（``HEAD_DOMAIN``），验证方用**日志公钥**验它（F-L 假设）。
        不给就返回未签名树头 —— 调用方不得把它当作「日志承诺」。
        """
        cp = self.checkpoint()
        head: Dict[str, Any] = {"domain": HEAD_DOMAIN, **cp.to_dict()}
        if signer is not None:
            head["sth"] = cert.sign_payload({
                "domain": HEAD_DOMAIN,
                "root": cp.root,
                "size": cp.size,
                "ts": ts or cert.utc_now(),
            }, signer)
        return head

    def to_dict(self) -> Dict[str, Any]:
        """完整日志的 JSON 视图（原型/测试用；不是公开证明）。"""
        return {"size": self.size,
                "root": self.root() if self.size else None,
                "entries": [dict(e) for e in self._entries]}


def verify_inclusion(cert_digest: str, proof: Dict[str, Any], *,
                     binding: Optional[str] = None,
                     expected_root: Optional[str] = None,
                     expected_size: Optional[int] = None) -> bool:
    """验证 ``cert_digest`` 在 ``proof`` 所绑定的树里。

    检查四件事，缺一不可：

    1. ``proof["leaf"]`` 必须等于用 ``(cert_digest, binding)`` 重算的叶子 ——
       防止把**另一条证书**的证明拿来重放；
    2. Merkle 路径必须能到达 ``proof["root"]``；
    3. 若给了 ``expected_root``，``proof["root"]`` 必须等于它 —— 防止旧视图/
       另一棵树的证明；
    4. 若给了 ``expected_size``，``proof["size"]`` 必须相等 —— 把「根相同但
       size 不同」的歧义挡掉。

    任何形状错误一律返回 ``False``（验证函数不因坏输入抛异常）。
    """
    try:
        if not isinstance(proof, dict):
            return False
        index = proof.get("index")
        size = proof.get("size")
        root = proof.get("root")
        leaf = proof.get("leaf")
        path = proof.get("path")
        if not isinstance(index, int) or not isinstance(size, int) or size <= 0:
            return False
        if not 0 <= index < size:
            return False
        if not isinstance(leaf, str) or not isinstance(root, str):
            return False
        want_leaf = entry_hash(cert_digest, binding)
        if leaf.lower() != want_leaf:
            return False
        if expected_root is not None and root.lower() != _hex32(expected_root, "期望根"):
            return False
        if expected_size is not None and size != expected_size:
            return False
        if not isinstance(path, list):
            return False
        pairs: List[Tuple[str, str]] = []
        for item in path:
            if (not isinstance(item, (list, tuple)) or len(item) != 2
                    or item[0] not in ("left", "right")):
                return False
            pairs.append((item[0], item[1]))
        return bool(verify_merkle_proof(leaf, pairs, root))
    except (TransparencyError, ValueError, TypeError):
        return False


def verify_head(head: Dict[str, Any], keyring: Any) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """验证带签名的树头。返回 ``(ok, 载荷)``；未签名头一律 ``False``。

    只验**签名**，不验「这个根是否在此前根之后」（一致性证明不在本原型内，F-2）。
    """
    if not isinstance(head, dict) or "sth" not in head:
        return False, None
    ok, body = cert.verify_envelope(head["sth"], keyring)
    if not ok or body is None:
        return False, None
    if (body.get("domain") != HEAD_DOMAIN
            or body.get("root") != head.get("root")
            or body.get("size") != head.get("size")):
        return False, body
    return True, body


__all__ = [
    "LEAF_BINDING_DOMAIN", "HEAD_DOMAIN", "TransparencyError",
    "Checkpoint", "TransparencyLog", "entry_hash",
    "verify_inclusion", "verify_head",
]
