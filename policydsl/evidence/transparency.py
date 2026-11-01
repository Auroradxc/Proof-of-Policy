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
* 本模块实现了 **RFC6962 风格的一致性证明**
  （:meth:`TransparencyLog.consistency_proof` / :func:`verify_consistency`）和一个
  最小的 **gossip 消息**接口（:meth:`TransparencyLog.gossip_message` /
  :func:`verify_gossip`）：审计者可以拿自己见过的旧树头，向日志要一条
  「新树头是旧树头的只追加延伸」的路径，并**独立验证**它。
  这只关闭 F-2 的**密码学内核**，不是 F-2 的全部：真实的网络 gossip、审计者之间
  的协作与告警、树头的持续公开记录仍是**外部义务**。没有那些通道，恶意日志照样
  可以给两个审计者看两套话；本模块给的是「任何一方拿到两份树头后**能证明**
  它们在撒谎」的机制。详见 ``docs/design-transparency-consistency.md``。
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
    MERKLE_NODE_DOMAIN,
    merkle_proof,
    merkle_root,
    verify_merkle_proof,
)

#: 叶子里「证书摘要 + 交付绑定」的域分隔前缀。只在给了 ``binding`` 时使用；
#: 默认叶仍等于 ``cert_digest``，以便与 F2 的 ``d = H(canonical(cert))`` 对上。
LEAF_BINDING_DOMAIN = b"pop-transparency-leaf-binding-v1"

#: 检查点 / 树头签名载荷的域标签（进 DSSE 载荷，便于人读）。
HEAD_DOMAIN = "pop-transparency-head-v1"

#: gossip 消息的域标签。与树头签名载荷分开，防止把 gossip 信封当树头重放。
GOSSIP_DOMAIN = "pop-transparency-gossip-v1"


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


def _largest_power_of_two_below(n: int) -> int:
    """严格小于 ``n`` 的最大 2 的幂（``n >= 2``）。

    这正是 RFC 6962 §2.1 的 ``k``：把 ``D[n]`` 切成 ``D[0:k]`` 与
    ``D[k:n]``。本仓库的 Merkle 构造（奇数末位**提升**，不复制）与 RFC 6962
    的 ``MTH`` 在任意 ``n`` 上逐字节一致，因此这里可以直接用递归切分。
    """
    return 1 << ((n - 1).bit_length() - 1)


def _node_hash(left: str, right: str) -> str:
    """内部节点哈希；与 :mod:`policydsl.proofs.session` 同一域分隔。"""
    return hashlib.sha256(
        MERKLE_NODE_DOMAIN + bytes.fromhex(left) + bytes.fromhex(right)
    ).hexdigest()


def _same_root(a: Any, b: Any) -> bool:
    """两个「根」是否相同；``None``/空串表示空树（没有根）。"""
    if a in (None, "") or b in (None, ""):
        return a in (None, "") and b in (None, "")
    try:
        return _hex32(a, "根") == _hex32(b, "根")
    except TransparencyError:
        return False


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

    **防 split-view 的起点**：两个检查点本身只是两个孤立的断言；把它们变成
    「后者是前者的只追加延伸」的是 :meth:`TransparencyLog.consistency_proof` +
    :func:`verify_consistency`。但**跨审计者的比较通道**（gossip）仍是外部义务，
    本类不提供网络。
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

    # -- 一致性证明（RFC 6962 §2.1.2） --
    def _subtree_root(self, lo: int, hi: int) -> str:
        """叶子区间 ``[lo, hi)`` 的 Merkle 根（等于 RFC 6962 的 ``MTH(D[lo:hi])``）。"""
        return merkle_root(self._leaves[lo:hi])

    def _consistency_path(self, m: int, lo: int, hi: int,
                          complete: bool) -> List[str]:
        """RFC 6962 的 ``SUBPROOF``：返回重建两个根所需的兄弟哈希（自底向上）。

        参数 ``m`` 是「旧树在本区间里的前缀长度」；``complete`` 表示该前缀是否
        **恰好覆盖**旧树（顶层调用为 ``True``）。递归与 RFC 6962 §2.1.2 一一对应：

        * ``m == hi - lo``：整段都是旧的 —— ``complete`` 时为 ``{}``，否则把这一
          整棵子树的根交出去（它是旧树的一部分，验证方无法自己算）；
        * ``m <= k``：旧前缀在左子树里，递归后附上右子树根；
        * ``m > k``：旧前缀跨过左子树，递归右子树（``complete=False``）后附上左
          子树根。

        切分点 ``k`` 是严格小于区间长度的最大 2 的幂。因为 ``k < m <= n < 2k``
        时 ``k`` 也是 ``m`` 的切分点，所以旧根可以用同样两段重算。
        """
        n = hi - lo
        if m == n:
            return [] if complete else [self._subtree_root(lo, hi)]
        k = _largest_power_of_two_below(n)
        if m <= k:
            return (self._consistency_path(m, lo, lo + k, complete)
                    + [self._subtree_root(lo + k, hi)])
        return (self._consistency_path(m - k, lo + k, hi, False)
                + [self._subtree_root(lo, lo + k)])

    def consistency_proof(self, old_size: int, new_size: int) -> Dict[str, Any]:
        """从旧树头 ``(old_size, root(old_size))`` 到当前树头的只追加证明。

        返回 ``{old_size, new_size, old_root, new_root, path}``；``path`` 是
        RFC 6962 风格的一致性证明（自底向上的兄弟哈希列表）。``old_size ==
        new_size`` 或 ``old_size == 0`` 时 ``path`` 为空（前者要求两根相等，后者是
        「空树是任何树的前缀」）。空树没有根，``old_root`` 为 ``None``。

        与 :meth:`prove` 不同，本方法**不**返回签名；树头签名见 :meth:`head`。
        """
        if (not isinstance(old_size, int) or not isinstance(new_size, int)
                or isinstance(old_size, bool) or isinstance(new_size, bool)):
            raise TransparencyError("old_size/new_size 必须是整数")
        if old_size < 0 or new_size < 0:
            raise TransparencyError(f"树大小不能为负：old={old_size} new={new_size}")
        if old_size > new_size:
            raise TransparencyError(
                f"旧树比新树大：old={old_size} new={new_size}（不是只追加）")
        if new_size > self.size:
            raise TransparencyError(
                f"new_size 超过日志当前大小：{new_size} > {self.size}")
        old_root = None if old_size == 0 else self._subtree_root(0, old_size)
        new_root = None if new_size == 0 else self._subtree_root(0, new_size)
        if old_size == 0 or old_size == new_size:
            path: List[str] = []
        else:
            path = self._consistency_path(old_size, 0, new_size, True)
        return {
            "old_size": old_size,
            "new_size": new_size,
            "old_root": old_root,
            "new_root": new_root,
            "path": path,
        }

    # -- gossip（最小接口；网络传输不在本模块内） --
    def gossip_message(self, previous_head: Dict[str, Any], *, signer: Any = None,
                       ts: Optional[str] = None) -> Dict[str, Any]:
        """把「``previous_head`` → 当前视图」打包成一条可转发的 gossip 消息。

        ``previous_head`` 是调用方**曾经见过**的树头（``{size, root, sth?}``）。
        消息里带一条 :meth:`consistency_proof` 生成的路径，任何拿到它的审计者都
        可以调 :func:`verify_gossip` 自行判断「当前树头是不是旧树头的延伸」。

        若 ``previous_head`` 的根与本日志在同一 ``size`` 的历史根不一致，说明调用方
        看到的是**另一棵树**：本方法抛 :class:`TransparencyError`，而不是伪造一条
        证明（诚实日志的行为）。
        """
        prev = _normalize_head(previous_head, "旧树头")
        if prev is None:
            raise TransparencyError("旧树头形状不合法：需要 {size, root[, sth]}")
        if prev["size"] > self.size:
            raise TransparencyError(
                f"旧树头比当前日志还大：{prev['size']} > {self.size}")
        if prev["size"] > 0:
            local_root = self._subtree_root(0, prev["size"])
            if not _same_root(prev["root"], local_root):
                raise TransparencyError(
                    "旧树头不属于本日志的历史：同 size 的根与本地不一致")
        current = self.head(signer, ts=ts)
        return gossip_message(prev, current,
                              self.consistency_proof(prev["size"], self.size))

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


def _proof_path(proof: Any) -> Optional[List[str]]:
    """从 ``{..., \"path\": [...]}`` 或裸列表里取出规范化的一致性路径。"""
    if isinstance(proof, dict):
        raw = proof.get("path")
    elif isinstance(proof, (list, tuple)):
        raw = proof
    else:
        return None
    if not isinstance(raw, (list, tuple)):
        return None
    out: List[str] = []
    for item in raw:
        if not isinstance(item, str):
            return None
        try:
            out.append(_hex32(item, "一致性证明元素"))
        except TransparencyError:
            return None
    return out


def verify_consistency(old_root: Optional[str], old_size: int,
                       new_root: Optional[str], new_size: int,
                       proof: Union[Dict[str, Any], Sequence[str], None]) -> bool:
    """验证「``new_root`` 是 ``old_root`` 的**只追加**延伸」（RFC 6962 §2.1.3）。

    ``proof`` 可以是 :meth:`TransparencyLog.consistency_proof` 返回的字典（推荐；
    会额外核对内嵌的 ``old_size`` / ``new_size`` / 两个根），也可以直接是
    ``path`` 列表。

    语义按 RFC 6962 的递归重算两个根：

    * 空树（``old_size == 0``）是任何树的前缀，``path`` 必须为空；
    * ``old_size == new_size`` 时两根必须相等且 ``path`` 为空；
    * 否则 ``path`` 必须非空、每个元素是 32 字节十六进制，且用它们重算出的
      **旧根与新根同时**与入参一致 —— 只重算新根是不够的，那样任何一棵更大的树
      （包括分叉）都能「通过」。

    这里证明的是「两棵树共享前 ``old_size`` 片叶子」；在碰撞抗性假设下，恶意日志
    无法为回滚、改写或分叉的树给出这样一条路径。**任何**形状错误返回 ``False``
    （验证函数不因坏输入抛异常）。
    """
    try:
        if (not isinstance(old_size, int) or not isinstance(new_size, int)
                or isinstance(old_size, bool) or isinstance(new_size, bool)):
            return False
        if old_size < 0 or new_size < 0 or old_size > new_size:
            return False
        path = _proof_path(proof)
        if path is None:
            return False
        if isinstance(proof, dict):
            # 证明里自带的元数据必须与调用方的树头一致，防止「拿 A 对的证明去验 B」。
            if "old_size" in proof and proof["old_size"] != old_size:
                return False
            if "new_size" in proof and proof["new_size"] != new_size:
                return False
            if "old_root" in proof and not _same_root(proof["old_root"], old_root):
                return False
            if "new_root" in proof and not _same_root(proof["new_root"], new_root):
                return False

        # 空树：没有根，是任何树的前缀。
        if old_size == 0:
            if path or not _same_root(old_root, None):
                return False
            if new_size == 0:
                return _same_root(new_root, None)
            if new_root is None or new_root == "":
                return False
            _hex32(new_root, "新根")
            return True

        if old_size == new_size:
            if path or old_root is None or new_root is None:
                return False
            return _hex32(old_root, "旧根") == _hex32(new_root, "新根")

        # 0 < old_size < new_size：两棵树都必须从证明里重算出来。
        if old_root is None or new_root is None or not path:
            return False
        old_norm = _hex32(old_root, "旧根")
        new_norm = _hex32(new_root, "新根")
        ptr = 0

        def take() -> str:
            nonlocal ptr
            if ptr >= len(path):
                raise TransparencyError("一致性证明太短，重算所需的兄弟哈希不够")
            h = path[ptr]
            ptr += 1
            return h

        def rebuild(m: int, n: int, complete: bool) -> Tuple[str, str]:
            """返回 ``(旧树前缀根, 本子树新根)``；``m/n`` 是区间内的长度。"""
            if m == n:
                if complete:
                    # 前缀恰好覆盖整棵旧树：两根都是调用方给的旧根。
                    return old_norm, old_norm
                h = take()
                return h, h
            k = _largest_power_of_two_below(n)
            if m <= k:
                old_left, new_left = rebuild(m, k, complete)
                return old_left, _node_hash(new_left, take())
            # 旧前缀跨过左子树：旧根 = H(左子树根, 右子树内旧前缀根)。
            # 注意这里不能只返回 ``old_right`` —— 那是**本子树内**的前缀根，
            # 只有在 ``m <= k`` 的分支里它才同时是整颗旧树在该节点的根。
            old_right, new_right = rebuild(m - k, n - k, False)
            left = take()
            return _node_hash(left, old_right), _node_hash(left, new_right)

        old_calc, new_calc = rebuild(old_size, new_size, True)
        if ptr != len(path):
            return False
        return old_calc == old_norm and new_calc == new_norm
    except (TransparencyError, ValueError, TypeError, RecursionError):
        return False


def _normalize_head(head: Any, what: str) -> Optional[Dict[str, Any]]:
    """校验并规范化树头 ``{size, root[, sth]}``；空树根为 ``None``。"""
    if not isinstance(head, dict):
        return None
    size = head.get("size")
    root = head.get("root")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return None
    out: Dict[str, Any] = {"size": size}
    if size == 0:
        if root not in (None, ""):
            return None
        out["root"] = None
    else:
        if not isinstance(root, str):
            return None
        try:
            out["root"] = _hex32(root, what)
        except TransparencyError:
            return None
    if "sth" in head:
        out["sth"] = head["sth"]
    if "domain" in head:
        out["domain"] = head["domain"]
    return out


def gossip_message(older_head: Dict[str, Any], newer_head: Dict[str, Any],
                   proof: Union[Dict[str, Any], Sequence[str]]) -> Dict[str, Any]:
    """把「旧树头 → 新树头 + 一致性证明」打包成一条可转发的 gossip 消息。

    本函数只**打包**，不生成证明（证明需要日志的叶子）。生产方通常是
    :meth:`TransparencyLog.gossip_message`。消息结构::

        {"domain": GOSSIP_DOMAIN,
         "older": {size, root[, sth]},
         "newer": {size, root[, sth]},
         "consistency": <consistency_proof 的返回值>}

    ``domain`` 与树头签名载荷的 ``HEAD_DOMAIN`` 分开：gossip 信封不能被当成树头
    承诺重放。**网络传输、重试、对端选择都不在本模块内。**
    """
    older = _normalize_head(older_head, "旧树头")
    newer = _normalize_head(newer_head, "新树头")
    if older is None or newer is None:
        raise TransparencyError("gossip 端点的树头形状不合法")
    return {"domain": GOSSIP_DOMAIN, "older": older, "newer": newer,
            "consistency": proof}


def verify_gossip(message: Dict[str, Any],
                  keyring: Any = None) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """验证一条 gossip 消息：「``newer`` 是 ``older`` 的只追加延伸」。

    检查三件事：

    1. ``message`` 形状与 ``GOSSIP_DOMAIN`` 域标签；
    2. :func:`verify_consistency` 对新旧树头与内嵌证明成立；
    3. 若给了 ``keyring``，**两个**树头都必须带 ``sth`` 且验签通过（F-L 假设）。

    返回 ``(ok, detail)``。不给 ``keyring`` 时**不验签**，``detail`` 里的
    ``signatures_checked`` 为 ``False`` —— 调用方不得把「一致性通过」当成
    「树头来自真日志」。真实 gossip 还需要传输层与审计者协作（见设计文档）。
    """
    if not isinstance(message, dict) or message.get("domain") != GOSSIP_DOMAIN:
        return False, None
    older = _normalize_head(message.get("older"), "旧树头")
    newer = _normalize_head(message.get("newer"), "新树头")
    if older is None or newer is None:
        return False, None
    detail: Dict[str, Any] = {
        "older": older,
        "newer": newer,
        "signatures_checked": keyring is not None,
    }
    if not verify_consistency(older.get("root"), older["size"],
                              newer.get("root"), newer["size"],
                              message.get("consistency")):
        return False, detail
    if keyring is not None:
        for head in (older, newer):
            if "sth" not in head:
                return False, detail
            ok, _ = verify_head(head, keyring)
            if not ok:
                return False, detail
    return True, detail


def verify_head(head: Dict[str, Any], keyring: Any) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """验证带签名的树头。返回 ``(ok, 载荷)``；未签名头一律 ``False``。

    只验**签名**，不验「这个根是否在此前根之后」；后者用
    :func:`verify_consistency`（把旧树头与新树头连起来）。
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
    "LEAF_BINDING_DOMAIN", "HEAD_DOMAIN", "GOSSIP_DOMAIN", "TransparencyError",
    "Checkpoint", "TransparencyLog", "entry_hash",
    "verify_inclusion", "verify_consistency", "verify_head",
    "gossip_message", "verify_gossip",
]
