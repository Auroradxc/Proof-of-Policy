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

接收方 nonce：verifier vs end-user（P1-07）
==========================================

nonce 由**谁**出，决定了它回答哪个问题：

=================  ====================  ==========================
`issuer`           出 nonce 的一方        回答的问题
=================  ====================  ==========================
`verifier`         V（第三方/审计者）     「被证明的 T 就是 V 手上的 T′」
`end-user`         U（收件人）            「送到 U 的 T′ 就是被证明的 T」
=================  ====================  ==========================

两者用**不同的绑定域**：

* verifier：`pop-bind-v1`，字段 `response_binding`（与电路公开值一致）；
* end-user：`pop-bind-enduser-v1`，字段 `end_user_binding`（**新增**）。

证书 `challenge` 块用 `"issuer": "verifier" | "end-user"` 声明是哪一种。
**旧块没有 `issuer` 字段，按 `verifier` 解释**（向后兼容）；出现任何其它
取值一律 fail closed。end-user 块同时保留 verifier 域的 `response_binding`
（那是电路的公开值，必须能继续与证明比对），并附加 `end_user_binding`。
U 只需 `(nonce, T′)` 重算后者即可判断「送达的是不是被证明的那条」。

**为什么电路不改**：C1 的硬边界是不改 SP1 电路、不重建 vkey。因此电路仍只
计算 verifier 域；end-user 域是证书层的附加承诺，不进入公开值。见
`docs/blockers/C1.md`。
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Dict, List, Optional, Union

from policydsl.privacy.commit import (
    BIND_DOMAIN, BIND_SCHEME, END_USER_BIND_DOMAIN, END_USER_BIND_SCHEME,
    end_user_response_binding, response_binding, verify_binding,
    verify_end_user_binding)

#: nonce 的字节长度（256 bit CSPRNG 输出）。
NONCE_BYTES = 32

#: `challenge.issuer` 的合法取值。
ISSUER_VERIFIER = "verifier"
ISSUER_END_USER = "end-user"
ISSUERS = (ISSUER_VERIFIER, ISSUER_END_USER)

#: `challenge` 块里的签发者字段名。
ISSUER_FIELD = "issuer"
#: end-user 块里的附加绑定字段名。
END_USER_BINDING_FIELD = "end_user_binding"


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


def normalize_issuer(issuer: Optional[str]) -> str:
    """把 ``issuer`` 规范化；``None`` 按 verifier（旧块兼容），未知值抛错。"""
    if issuer is None:
        return ISSUER_VERIFIER
    if not isinstance(issuer, str):
        raise ValueError(f"challenge issuer must be a string, got {type(issuer).__name__}")
    got = issuer.lower()
    if got not in ISSUERS:
        raise ValueError(
            f"unknown challenge issuer {issuer!r} (expected {', '.join(ISSUERS)})")
    return got


def challenge_issuer(ch: Dict) -> str:
    """读 ``challenge`` 块的签发者；**缺字段 = verifier**（P1-07 之前的老块）。"""
    if not isinstance(ch, dict):
        raise ValueError("challenge block must be an object")
    return normalize_issuer(ch.get(ISSUER_FIELD))


def scheme_for_issuer(issuer: str) -> str:
    """该 issuer 使用的绑定方案名。"""
    issuer = normalize_issuer(issuer)
    return BIND_SCHEME if issuer == ISSUER_VERIFIER else END_USER_BIND_SCHEME


def binding_for_issuer(issuer: str, nonce: bytes, response: str) -> str:
    """按 issuer 选择绑定域并计算 ``(nonce, T) -> binding``。"""
    issuer = normalize_issuer(issuer)
    if issuer == ISSUER_VERIFIER:
        return response_binding(nonce, response)
    return end_user_response_binding(nonce, response)


def challenge_block(nonce: bytes, binding: str,
                    issuer: str = ISSUER_VERIFIER,
                    end_user_binding: Optional[str] = None) -> Dict[str, str]:
    """构造证书里的 ``challenge`` 块（方案、issuer、挑战值、绑定）。

    * ``issuer="verifier"``（缺省）：``{"scheme": pop-bind-v1, "issuer":
      "verifier", "nonce": ..., "response_binding": ...}``；
    * ``issuer="end-user"``：方案为 ``pop-bind-enduser-v1``，并**必须**给
      ``end_user_binding``（用 :func:`bind_end_user` 或
      :func:`end_user_challenge_block` 算），块里同时保留 verifier 域的
      ``response_binding``（电路公开值）。

    本块整体进 ``cert_digest``，受签名与锚定保护。``issuer`` 字段是新的；
    P1-07 之前签发的块没有它，验证方按 verifier 解释。
    """
    issuer = normalize_issuer(issuer)
    block: Dict[str, str] = {
        "scheme": scheme_for_issuer(issuer),
        ISSUER_FIELD: issuer,
        "nonce": nonce_hex(nonce),
        "response_binding": binding,
    }
    if issuer == ISSUER_END_USER:
        if not isinstance(end_user_binding, str) or not end_user_binding:
            raise ValueError("end-user challenge requires a non-empty end_user_binding")
        block[END_USER_BINDING_FIELD] = end_user_binding
    return block


def bind_end_user(nonce: bytes, response: str) -> str:
    """``end_user_binding = SHA256(pop-bind-enduser-v1 ‖ len(n) ‖ n ‖ T)``。"""
    return end_user_response_binding(nonce, response)


def end_user_challenge_block(nonce: bytes, response_binding_value: str,
                             response: str) -> Dict[str, str]:
    """便利构造：U 出 nonce，O 用被证明的 T 生成完整的 end-user 挑战块。"""
    return challenge_block(nonce, response_binding_value,
                           issuer=ISSUER_END_USER,
                           end_user_binding=bind_end_user(nonce, response))


def validate_challenge_block(ch: Dict) -> Dict[str, object]:
    """结构校验：issuer/scheme/nonce/绑定字段是否齐全且自洽。

    返回一个摘要 dict（``issuer`` / ``scheme`` / ``nonce``）；不合法抛
    ``ValueError``。它**不**重算绑定（没有 T′ 时做不到），只保证「按 issuer
    该有的字段都在」—— 这也是 ``verify_session.py`` 能做的那一层。
    """
    issuer = challenge_issuer(ch)
    expected_scheme = scheme_for_issuer(issuer)
    if ch.get("scheme") != expected_scheme:
        raise ValueError(
            f"challenge scheme {ch.get('scheme')!r} does not match issuer "
            f"{issuer!r} (expected {expected_scheme!r})")
    nonce = parse_nonce(ch.get("nonce") or "")
    if not isinstance(ch.get("response_binding"), str) or not ch["response_binding"]:
        raise ValueError("challenge.response_binding is missing")
    if issuer == ISSUER_END_USER:
        eb = ch.get(END_USER_BINDING_FIELD)
        if not isinstance(eb, str) or len(eb) != 64:
            raise ValueError("end-user challenge requires a 64-hex end_user_binding")
        try:
            bytes.fromhex(eb)
        except ValueError as exc:
            raise ValueError(f"end_user_binding is not hex: {exc}") from exc
    return {"issuer": issuer, "scheme": expected_scheme, "nonce": nonce}


def check_challenge(payload: Dict, response: str,
                    issuer: Optional[str] = None) -> bool:
    """用证书自带的 ``challenge`` 块与一条候选响应做**离线**核对。

    * verifier 块：核对 ``response_binding``（``pop-bind-v1``）；
    * end-user 块：核对 ``end_user_binding``（``pop-bind-enduser-v1``）；
    * 旧块没有 ``issuer``：按 verifier 处理（向后兼容）；
    * ``issuer`` 参数用于**强制**期望角色（例如 U 只接受 end-user 块）。

    返回 False 涵盖所有「对不上」的情形（缺块、issuer/scheme 不认识、字段
    缺失、绑定不匹配）—— 调用方不该从这里区分攻击与损坏，两者都必须拒绝。
    """
    ch = payload.get("challenge") or {}
    try:
        got = challenge_issuer(ch)
        if issuer is not None and got != normalize_issuer(issuer):
            return False
        expected_scheme = scheme_for_issuer(got)
        if ch.get("scheme") != expected_scheme:
            return False
        nonce = parse_nonce(ch.get("nonce") or "")
        if got == ISSUER_VERIFIER:
            binding = ch.get("response_binding")
            if not isinstance(binding, str):
                return False
            return verify_binding(nonce, response, binding)
        binding = ch.get(END_USER_BINDING_FIELD)
        if not isinstance(binding, str):
            return False
        return verify_end_user_binding(nonce, response, binding)
    except (ValueError, TypeError):
        return False


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
