"""P0-2 挑战（challenge / nonce）的生成、编解码与证书块构造。

**协议里谁在什么时候用它**：

```
客户端/验证者                     证明方（agent 运行时）            验证者
     │                                  │                           │
     │ 1. nonce = new_nonce()           │                           │
     ├──────────── nonce ──────────────►│                           │
     │                                  │ 2. 电路承诺                │
     │                                  │    response_binding =     │
     │                                  │    SHA256(domain‖n‖T)     │
     │                                  │                           │
     │ 3. 收到送达的 T′ ◄───────────────┤ 连同证书（含 challenge 块）│
     │                                  │                           │
     │ 4. commit.verify_binding(nonce, T′, cert.challenge.response_binding)
     │    → True 才说明「被证明的 T」就是「送达的 T′」
```

**一次性**由协议使用方保证：`new_nonce()` 每次都从 CSPRNG 取新值，验证方
应当记录已用过的 nonce 并拒绝重复（否则一条绑定了 nonce 的合法证书可以被
原样重放 —— 重放本身不会让伪造的 T′ 通过，但会让「一次会话」变成「多次」）。
本模块提供 `NonceStore` 这一个最小的「已用 nonce」记录器，供不想自己造
轮子的调用方使用；不需要持久化的场景可以直接跳过它。

**为什么 nonce 长度是固定的**：`commit.response_binding` 里带了长度前缀，
所以任意长度的 nonce 都不会产生歧义；固定 32 字节只是让「一次性」这件事更容易
审计（也给重放窗口一个明确的上限）。
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Dict, List, Optional, Union

from .commit import BIND_SCHEME, response_binding, verify_binding

#: nonce 的字节长度（256 bit CSPRNG 输出）。
NONCE_BYTES = 32


def new_nonce(n: int = NONCE_BYTES) -> bytes:
    """生成一个一次性挑战值（``secrets.token_bytes``，密码学安全）。"""
    return secrets.token_bytes(n)


def nonce_hex(nonce: bytes) -> str:
    """nonce 的十六进制表示（证书与 CLI 里用的都是这个形式）。"""
    return nonce.hex()


def parse_nonce(text: str) -> bytes:
    """把十六进制字符串解析回 nonce 字节；非法输入抛 ``ValueError``。

    只接受偶数长度的十六进制 —— 拒绝其它编码是刻意的：nonce 会参与哈希，
    两种写法指向同一个字节串就会变成两个「不同」的挑战值。
    """
    t = text.strip()
    if len(t) % 2 != 0:
        raise ValueError(f"nonce 必须是偶数长度的十六进制串，得到 {len(t)} 个字符")
    try:
        return bytes.fromhex(t)
    except ValueError as exc:
        raise ValueError(f"nonce 不是合法的十六进制串: {exc}") from exc


def challenge_block(nonce: bytes, binding: str) -> Dict[str, str]:
    """构造证书里的 ``challenge`` 块（声明方案、挑战值、以及证明承诺的绑定）。

    方案名一并写进载荷：将来换绑定算法时，验证方能直接从证书看出该用哪套，
    而不是猜。本块整体进 ``cert_digest``，因此也受签名与锚定保护。
    """
    return {"scheme": BIND_SCHEME, "nonce": nonce_hex(nonce), "response_binding": binding}


def check_challenge(payload: Dict, response: str) -> bool:
    """用证书自带的 ``challenge`` 块与一条候选响应做**离线**核对。

    这是「持 T′ 与 nonce 的一方」最省事的一条路径：不需要证明、不需要网络，
    只要证书在手。返回 False 涵盖所有「对不上」的情形（缺块、方案不认识、
    绑定不匹配）—— 调用方不该从这里区分攻击与损坏，两者都必须拒绝。
    """
    ch = payload.get("challenge") or {}
    if ch.get("scheme") != BIND_SCHEME:
        return False
    try:
        nonce = parse_nonce(ch.get("nonce") or "")
    except ValueError:
        return False
    binding = ch.get("response_binding")
    if not isinstance(binding, str):
        return False
    return verify_binding(nonce, response, binding)


class NonceStore:
    """已用 nonce 的追加式记录（重放防护的最小实现）。

    一份纯文本文件，每行一个十六进制 nonce。``consume`` 是**先查后写**的
    原子操作（在同一进程内），重复使用会抛 ``ValueError``。

    这刻意做得很小：真实的部署会把它换成数据库里的一行、或链上的一次调用。
    这里只提供一个「语义正确、离线可跑」的参考，让重放防护不是一句空话。
    """

    def __init__(self, path: Optional[Union[str, Path]] = None):
        self.path = Path(path) if path is not None else None
        self._used: set = set()
        if self.path is not None and self.path.exists():
            self._used = {ln.strip() for ln in self.path.read_text(encoding="utf-8").splitlines()
                          if ln.strip()}

    def seen(self, nonce: bytes) -> bool:
        """该 nonce 是否已被用过。"""
        return nonce_hex(nonce) in self._used

    def consume(self, nonce: bytes) -> None:
        """登记一个 nonce；重复使用抛 ``ValueError``。"""
        h = nonce_hex(nonce)
        if h in self._used:
            raise ValueError(f"nonce 已被使用过（重放）: {h[:16]}…")
        self._used.add(h)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(h + "\n")

    def used(self) -> List[str]:
        """已用 nonce 的十六进制列表（已排序，便于比对/展示）。"""
        return sorted(self._used)
