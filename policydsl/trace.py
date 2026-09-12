"""工具回执链（P1-5）——把「证明者的声明」变成「可验证的事实」。

## 问题

在 P1-5 之前，``tool_calls`` 与 ``token_count`` 是 ``ProofRequest`` 里由**证明者
自己填写**的私有输入。``tool_arg_guard``/``budget_bound`` 因此**语义上不健全**：
电路只能证明「如果轨迹是我说的这样，那么策略通过」——而轨迹本身没有任何东西
把它拴到真实发生过的调用上。证明者想通过 ``tool_arg_guard``，把 ``tool_calls``
填成空列表即可。

## 设计：回执由**网关**签发，agent 只能转发

``ToolReceipt`` 由**工具网关**（真正执行工具的那一方）在每次调用后签发，
agent（连同它要证明的响应）只能把这些回执**原样转发**。回执里带：

- ``seq``：序号（从 0 起）；
- ``tool``/``args``：工具名与**明文参数**（电路要据此判 ``forbidden_fields``）；
- ``result_digest``：执行结果的承诺（结果可能很长，且没有任何规则去读它）；
- ``ts``：网关时间戳；
- ``prev``：前一条回执的 ``receipt_digest``（首条为 ``"genesis"``）——链；
- ``keyid``/``sig``：网关签名与密钥标识。

**为什么参数是明文而不是摘要**：计划稿里写的是 ``args_digest``，但摘要**没法**
支撑 ``tool_arg_guard`` —— 电路拿 ``SHA256(canonical(args))`` 无从判断某次调用
的参数里有没有 ``password`` 这个键。要么规则改判一个证明者同样能自由编造的
字段（自欺），要么把参数放进回执让电路直接判。回执是证明的**私有输入**、
不进公开值，所以放明文不额外泄露什么；真正保证它没被篡改的是**网关签名**。

## 三层各自保证什么（必须如实陈述的边界）

| 层 | 保证 | 本文件/电路的哪一部分 |
|---|---|---|
| 电路内 | 链**结构**自洽：``seq`` 连续、``prev`` 逐条咬合、每条回执的摘要由**它自己的内容**重算 | ``chain_ok`` ↔ ``pop_types::verify_receipt_chain`` |
| 链下 | 每条回执确实由**网关**签发（Ed25519 验签） | ``verify_chain``（Python）/ 验证方离线执行 |
| 公开值 | ``trace_root``（链尾摘要）随证明一起承诺，验证方拿**网关侧收到的回执**重算即可比对 | ``ProofOutput::trace_root`` |
| 链下 + 证书 | 这条链**没有被截尾**：网关在会话末端签发的 ``ToolSeal{count, trace_root}``（P1-5b） | ``verify_seal`` / ``ToolGateway.seal`` |

**电路内不验 Ed25519**（zkVM 内验签代价高，见 `docs/plan-p0p1p2.md` §P1-5 的
取舍说明），所以「回执链可信」这一步依赖**链下验签 + 公开值里的 ``trace_root``**。
论文 §4.2 如实标注了这一点，不宣称电路内完成了签名验证。

## 截尾与 ``ToolSeal``（P1-5b）

上面三层都拦不住一种攻击：把链尾那条**违规**回执**整条删掉**。剩下的仍是一条
结构自洽、逐条签名有效的**真链**，只是短了；而任何只基于**交付链本身**的检查都
无从知道「后面还有没有」—— ``trace_root`` 比对也一样（攻击者让证书与检材同时
是那条截断的链）。

补法只有一条：让网关对**会话末端**做一次承诺。:meth:`ToolGateway.seal` 在会话
结束时签一条 :class:`ToolSeal`：``{count, trace_root, ts, keyid, sig}``。验证方
拿到它（它随证书一起走，载荷顶层的 ``trace_seal`` 字段）后核对：

1. ``sig`` 由网关钥签过（**链下**，与回执验签同一道关）；
2. ``seal.trace_root == 证书/证明承诺的 trace_root``；
3. 手上若真有链（``--receipts``）：``len(chain) == seal.count`` 且
   ``trace_root(chain) == seal.trace_root``。

截尾的攻击者要么拿原始 seal（``count`` 对不上 ⇒ 拒），要么为截断的链伪造一条
seal（网关签名伪造不了 ⇒ 拒）。**这一步不需要改电路**：链尾摘要本来就已经在
电路内计算并进公开值了，「这条证明绑的是哪条链」已有电路保证；seal 要补的是
「网关说这条链到此为止」，那是一个签名问题，按本项目「结构入电路、签名在链下」
的既有分工放在链下。这偏离了计划稿里「+ 电路内对 seal 的结构校验」的设想，
理由与代价见 `docs/plan-p0p1p2.md` 待办 T4。

## 确定性分词（``token_count`` 语义变更）

``budget_bound(unit="tokens")`` 此前读的是证明者自填的 ``token_count``。现在改为
**电路内自算**：把响应 UTF-8 字节按固定空白集合切成 run，数 run 的个数。空白集合
取死为 ``SPACE, TAB, LF, VT, FF, CR``（六个字节），**不**跟随时下流行的分词器，
也**不**依赖 Unicode White_Space —— 两边实现必须逐字节一致，语义必须能一句话说清。
见 `paper/proof-of-policy.md` §4.2。

## 与旧路径的关系

``tool_calls`` / ``token_count`` 这两个字段**已被移除**，且 ``ProofRequest`` 标了
``deny_unknown_fields``：拿旧向量去出证会**解析失败**（guest panic ⇒ 产不出证明），
而不是「静默当成零次调用」——后者会让 P1-5 看起来像生效了，实际一提就破。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import cert

#: 回执摘要与签名的域分隔前缀（对应 ``pop_types::TRACE_DOMAIN``）。
TRACE_DOMAIN = b"pop-trace-v1"
#: 会话末端承诺（seal）的域分隔前缀 —— 与回执的域**不同**，所以一条 seal 的
#: 签名不可能被当成一条回执的签名用（反之亦然）。
SEAL_DOMAIN = b"pop-trace-seal-v1"
#: 空链的链尾（对应 ``pop_types::TRACE_GENESIS``）。
GENESIS = "genesis"

#: 分词用的空白字节集合 —— **取死**，与 `pop_types::is_token_space` 逐字节一致。
#: 刻意不用 Unicode White_Space：那份定义会随 Unicode 版本漂移，而电路与
#: 参考实现必须永远给出同一个数。
TOKEN_SPACE = frozenset(b" \t\n\x0b\x0c\r")

#: 允许出现在回执 ``keyid`` 里的方案前缀（与 `cert.ED25519_SCHEME` 同源）。
#: 其它前缀（含历史的 ``demo-hmac-sha256``）**结构性被拒** —— ring 里就算放了
#: 对应密钥也没用，和 P0-3 对信封的处理保持一致。
_ALLOWED_SCHEMES = (cert.ED25519_SCHEME, cert.HMAC_TEST_SCHEME)


# --------------------------------------------------------------------------- #
# 工具回执
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ToolReceipt:
    """工具网关对**一次工具调用**签发的回执。

    ``args`` 的值一律是字符串（电路侧是 ``BTreeMap<String, String>``）；
    非字符串值请用 :func:`arg_str` 统一字符串化后再放进回执，否则两边可能
    对同一份语义算出不同的字节。
    """

    seq: int
    tool: str
    args: Dict[str, str] = field(default_factory=dict)
    result_digest: str = ""
    ts: str = ""
    prev: str = GENESIS
    keyid: str = ""
    #: 网关签名的十六进制（**不**参与摘要计算 —— 否则自指）。
    sig: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转成可 JSON 化的字典（字段名与 ``pop_types::ToolReceipt`` 一致）。"""
        return {
            "seq": self.seq,
            "tool": self.tool,
            "args": dict(self.args),
            "result_digest": self.result_digest,
            "ts": self.ts,
            "prev": self.prev,
            "keyid": self.keyid,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ToolReceipt":
        """从字典还原（缺字段给缺省值，与 serde 的 ``#[serde(default)]`` 一致）。"""
        return cls(
            seq=int(d["seq"]),
            tool=str(d["tool"]),
            args={str(k): arg_str(v) for k, v in (d.get("args") or {}).items()},
            result_digest=str(d.get("result_digest", "")),
            ts=str(d.get("ts", "")),
            prev=str(d.get("prev", GENESIS)),
            keyid=str(d.get("keyid", "")),
            sig=str(d.get("sig", "")),
        )


@dataclass(frozen=True)
class ToolSeal:
    """网关对**一次会话的整条链**签发的末端承诺（P1-5b）。

    它只承诺两件事，而这两件事恰好是「截尾」攻击必须破坏的：

    - ``count``：这条链一共几条回执（= 真实发生过的工具调用次数）；
    - ``trace_root``：链尾摘要（与 :func:`trace_root` 同一算法）。

    验证方核对 ``count``/``trace_root`` 与手上的链是否一致、``sig`` 是否由网关
    签出，即可判断「我拿到的链是不是完整的那条」。**没有它，删掉链尾的一条违规
    回执是无法被发现的**（见模块 docstring 的「截尾与 ToolSeal」一节）。
    """

    #: 链的回执条数（可以为 0：一次工具都没调用也是一次合法的会话）。
    count: int
    #: 链尾摘要（空链为 ``"genesis"``）。
    trace_root: str
    ts: str = ""
    keyid: str = ""
    #: 网关签名的十六进制（不参与摘要计算）。
    sig: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """转成可 JSON 化的字典（随证书载荷顶层的 ``trace_seal`` 一起走）。"""
        return {
            "count": self.count,
            "trace_root": self.trace_root,
            "ts": self.ts,
            "keyid": self.keyid,
            "sig": self.sig,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ToolSeal":
        """从字典还原（缺字段给缺省值）。"""
        return cls(
            count=int(d["count"]),
            trace_root=str(d["trace_root"]),
            ts=str(d.get("ts", "")),
            keyid=str(d.get("keyid", "")),
            sig=str(d.get("sig", "")),
        )


def canonical_seal_bytes(s: ToolSeal) -> bytes:
    """seal 的规范字节编码（**签名的唯一原像**）。

    编码 = ``SEAL_DOMAIN ‖ u32_be(count) ‖ lp(trace_root) ‖ lp(ts) ‖ lp(keyid)``。
    与 :func:`canonical_receipt_bytes` 同构（长度前缀、字段顺序写死、不用 JSON），
    且带上 ``keyid`` —— 换钥匙就要换签名。
    """
    return b"".join([
        SEAL_DOMAIN,
        int(s.count).to_bytes(4, "big"),
        _lp_str(s.trace_root),
        _lp_str(s.ts),
        _lp_str(s.keyid),
    ])


def seal_digest(s: ToolSeal) -> str:
    """seal 的摘要（十六进制）—— 需要把「用的是哪条 seal」压成一个值时用它。"""
    return hashlib.sha256(canonical_seal_bytes(s)).hexdigest()


def seal_for(receipts: Sequence[ToolReceipt], gateway: "ToolGateway",
             ts: Optional[str] = None) -> ToolSeal:
    """用 ``gateway`` 给一条**已经签好的链**补一条 seal（便捷函数）。

    正常路径是 :meth:`ToolGateway.seal`（网关自己知道自己的链）；这个函数是给
    「链与网关分离」的调用方（测试、离线复算）用的。
    """
    return gateway.seal(receipts=receipts, ts=ts)


def verify_seal(seal: Optional[ToolSeal], keyring: Any = None,
                receipts: Optional[Sequence[ToolReceipt]] = None) -> Tuple[bool, str]:
    """seal 的三项核对：链长、链尾摘要、（给了钥匙时）签名。

    三项各自回答一个不同的问题，缺一项结论就不完整 —— 与 :func:`verify_chain`
    一样返回 ``(是否成立, 说明)``，说明会原样进证书/CLI 输出：

    - ``receipts`` 不为 None：核对 ``count`` 与 ``len(receipts)``、
      ``trace_root`` 与 :func:`trace_root`\\ (receipts)——**这两项是截尾的检测点**；
    - ``keyring`` 不为 None：核对方案前缀、``keyid`` 在 ring 里、``sig`` 验签通过
      ——**这一项是「seal 是不是网关签的」**，没有它，前两项只说明检材自洽
      （攻击者可以给截断的链配一条自己造的 seal）。

    ``keyring is None`` 时会**如实说明签名未验**，但结构/一致性能核的先核 ——
    这与 ``verify_cert.py`` 里「只给 --receipts 不给 --gateway-key」的处理一致。
    """
    if seal is None:
        return False, "证书没有 trace_seal（会话末端未被网关承诺）—— 无法排除截尾"
    if receipts is not None:
        if int(seal.count) != len(receipts):
            return False, (f"seal.count={seal.count} != 交付链长 {len(receipts)}"
                           "（链被截尾或换了另一条链）")
        root = trace_root(list(receipts))
        if seal.trace_root != root:
            return False, (f"seal.trace_root={_short(seal.trace_root)} != 交付链链尾"
                           f" {_short(root)}（链被截尾或换了另一条链）")
    if keyring is None:
        return True, "只核对了 count/trace_root；未给网关公钥，seal 签名未验"
    scheme = seal.keyid.split(":", 1)[0]
    if scheme not in _ALLOWED_SCHEMES:
        return False, f"不接受的 keyid 方案 '{scheme}'"
    ring = cert._normalize_keyring(keyring)
    verifier = ring.get(seal.keyid)
    if verifier is None:
        return False, f"keyid 不在 keyring 里（{seal.keyid}）"
    try:
        sig = bytes.fromhex(seal.sig)
    except ValueError:
        return False, "seal 签名不是合法十六进制"
    data = canonical_seal_bytes(seal)
    try:
        good = bool(cert._ed25519_verify(verifier, data, sig)
                    if isinstance(verifier, cert.Ed25519PublicKey)
                    else verifier.verify(data, sig))
    except Exception:
        good = False
    if not good:
        return False, "seal 签名验证失败"
    return True, f"seal 已由 {seal.keyid} 签出（count={seal.count}）"


def _short(digest: str, n: int = 12) -> str:
    """摘要截断显示（只在**说明文字**里用，不参与任何判定）。"""
    return digest if len(digest) <= n else digest[:n] + "…"


def seal_to_json(seal: Optional[ToolSeal]) -> Optional[Dict[str, Any]]:
    """seal → 证书载荷顶层 ``trace_seal`` 的 JSON 形状（None 原样透传）。"""
    return None if seal is None else seal.to_dict()


def seal_from_json(d: Any) -> Optional[ToolSeal]:
    """证书载荷顶层 ``trace_seal`` → seal（``None``/缺失 → ``None``）。"""
    return None if not d else ToolSeal.from_dict(d)


def arg_str(value: Any) -> str:
    """把参数值统一成字符串（与电路侧 ``String`` 对齐）。

    字符串原样返回；其余类型用**紧凑且键有序**的 JSON 表示 —— 这样
    ``{"a": 1}`` 与 ``{"a": 1.0}`` 这类「同一个 Python 对象的不同写法」不会
    在两侧算出不同字节。注意：一旦字符串化，就只能在向量 JSON 里传这个**结果**，
    传原始对象会与已签名的字节不符。
    """
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def extract_result_text(result: Any) -> str:
    """从 MCP CallToolResult / content 列表 / 普通值里尽力提取文本。

    网关签回执时只对**这段文本**求摘要，所以它必须对同一个返回值给出确定的
    结果（不依赖 dict 迭代顺序之外的东西 —— ``json.dumps`` 在这里开了
    ``sort_keys``？没有：保留工具的原始字段顺序更贴近「它到底返回了什么」，
    且同一进程内同一对象的序列化是确定的）。
    """
    content = getattr(result, "content", None)
    if content is None and isinstance(result, dict):
        content = result.get("content")
    if content is not None:
        parts: List[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text" and isinstance(item.get("text"), str):
                    parts.append(item["text"])
            else:
                text = getattr(item, "text", None)
                if isinstance(text, str):
                    parts.append(text)
        if parts:
            return "".join(parts)
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception:
        return str(result)


def _lp(data: bytes) -> bytes:
    """长度前缀：``u32_be(len) ‖ data``。

    与 P0-2 的绑定公式同一个理由 —— 没有长度前缀，「拼起来」就有歧义
    （``("ab","cd")`` 与 ``("abcd","")`` 会编码成同一串字节）。
    """
    return len(data).to_bytes(4, "big") + data


def _lp_str(s: str) -> bytes:
    return _lp(s.encode("utf-8"))


def canonical_receipt_bytes(r: ToolReceipt) -> bytes:
    """回执的规范字节编码（**签名与摘要的共同原像**）。

    编码 = ``TRACE_DOMAIN ‖ u32_be(seq) ‖ lp(tool) ‖ u32_be(len(args)) ‖
    [lp(k) ‖ lp(v)]_按键升序 ‖ lp(result_digest) ‖ lp(ts) ‖ lp(prev) ‖ lp(keyid)``。

    刻意**不用 JSON**：JSON 的规范化（键序、数字格式、转义、空白）是个永远
    聊不完的话题，而这里只需要一串**唯一**的字节。字段齐全、顺序写死、长度
    前缀防歧义 —— 与 ``pop_types::canonical_receipt_bytes`` 必须逐字节一致
    （``tests/test_trace.py`` 逐长度核对）。

    摘要与签名都覆盖 ``keyid``：把 ``keyid`` 换掉（比如换成 ring 里另一把
    可用的钥匙）会改变被签的字节，从而验签失败。
    """
    parts: List[bytes] = [
        TRACE_DOMAIN,
        int(r.seq).to_bytes(4, "big"),
        _lp_str(r.tool),
        len(r.args).to_bytes(4, "big"),
    ]
    for k in sorted(r.args):
        parts.append(_lp_str(k))
        parts.append(_lp_str(r.args[k]))
    parts.append(_lp_str(r.result_digest))
    parts.append(_lp_str(r.ts))
    parts.append(_lp_str(r.prev))
    parts.append(_lp_str(r.keyid))
    return b"".join(parts)


def receipt_digest(r: ToolReceipt) -> str:
    """单条回执的摘要（十六进制）—— 下一条回执的 ``prev`` 就是它。"""
    return hashlib.sha256(canonical_receipt_bytes(r)).hexdigest()


def trace_root(receipts: Sequence[ToolReceipt]) -> str:
    """链尾摘要（空链 → ``"genesis"``）—— 随证明一起进公开值。

    公开值里放**链尾摘要**而不是整条链：链可能很长，而验证方并不需要从这里
    读回它（它自己手上有网关发的回执）。放摘要的意义是让「这份证明绑定的是
    哪条链」可被离线核对 —— 与 ``response_binding`` 之于响应的作用完全对称。
    """
    return receipt_digest(receipts[-1]) if receipts else GENESIS


def chain_ok(receipts: Sequence[ToolReceipt]) -> Tuple[bool, str]:
    """**结构**检查：``seq`` 必须等于下标、``prev`` 必须逐条咬合。

    这是电路内做的那一层（见 ``pop_types::verify_receipt_chain``）：它只保证
    链自身自洽，**不**保证内容属实 —— 后者靠签名，由 :func:`verify_chain`
    在链下完成。返回 ``(是否成立, 失败原因)``，原因会作为违规证据进证书。

    空链是**合法**的（一次工具都没调用）：恒返回 ``(True, "")``。
    """
    for i, r in enumerate(receipts):
        if int(r.seq) != i:
            return False, f"receipt {i}: seq={r.seq} != {i}"
        expected = GENESIS if i == 0 else receipt_digest(receipts[i - 1])
        if r.prev != expected:
            return False, f"receipt {i}: prev mismatch"
    return True, ""


def chain_digest(receipts: Sequence[ToolReceipt]) -> str:
    """``trace_root`` 的别名（计划稿里的名字；语义完全相同）。"""
    return trace_root(receipts)


def verify_chain(receipts: Sequence[ToolReceipt],
                 keyring: Any = None) -> Tuple[bool, str]:
    """结构 + **签名**：每条回执都必须由 keyring 里对应 ``keyid`` 的钥匙签过。

    验签对象是 :func:`canonical_receipt_bytes` 的原始字节 —— 与签名时**同一段**，
    所以 ``sig``/``keyid`` 自身也在被保护的内容里（改 ``sig`` 会让验签失败，
    改 ``keyid`` 会换掉原像）。

    返回 ``(是否成立, 失败原因)``，与 :func:`chain_ok` 同形，便于调用方拼接
    两级检查而不必分叉。
    """
    ok, why = chain_ok(receipts)
    if not ok:
        return False, why
    ring = cert._normalize_keyring(keyring)
    for i, r in enumerate(receipts):
        scheme = r.keyid.split(":", 1)[0]
        if scheme not in _ALLOWED_SCHEMES:
            return False, f"receipt {i}: 不接受的 keyid 方案 '{scheme}'"
        verifier = ring.get(r.keyid)
        if verifier is None:
            return False, f"receipt {i}: keyid 不在 keyring 里（{r.keyid}）"
        try:
            sig = bytes.fromhex(r.sig)
        except ValueError:
            return False, f"receipt {i}: 签名不是合法十六进制"
        data = canonical_receipt_bytes(r)
        try:
            good = bool(cert._ed25519_verify(verifier, data, sig)
                        if isinstance(verifier, cert.Ed25519PublicKey)
                        else verifier.verify(data, sig))
        except Exception:
            good = False
        if not good:
            return False, f"receipt {i}: 签名验证失败"
    return True, ""


# --------------------------------------------------------------------------- #
# 确定性分词
# --------------------------------------------------------------------------- #

def token_count(text: str) -> int:
    """响应按**固定空白集合**切分后的 run 数（与电路内自算逐字节一致）。

    定义：把 ``text`` 的 UTF-8 字节里属于 ``TOKEN_SPACE`` 的字节当作分隔符，
    数「非空白字节的最大连续段」的个数。空串 → 0。

    这不是任何真实 LLM 的分词器 —— 它**不假装是**。选它的理由只有一条：
    电路内能廉价、确定地算出来，从而 ``budget_bound(unit="tokens")`` 的输入
    不再是证明者的一面之词。真实分词表若要入电路，那是另一个量级的工程
    （见 `docs/plan-p0p1p2.md` §P1-6）。
    """
    n = 0
    in_run = False
    for b in text.encode("utf-8"):
        if b in TOKEN_SPACE:
            in_run = False
        elif not in_run:
            in_run = True
            n += 1
    return n


# --------------------------------------------------------------------------- #
# 工具网关
# --------------------------------------------------------------------------- #

def utc_now() -> str:
    """当前 UTC 时间（秒精度，ISO-8601）。网关回执用，不参与判定。"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class ToolGateway:
    """签发工具回执的网关。

    它是**唯一**持有回执签名钥的一方：``MCPGuard`` 在每次工具调用**执行后**
    让它签一条回执，agent 侧的证明请求再把这些回执原样带上。这样
    ``tool_arg_guard``/``budget_bound`` 判的就不再是 agent 的自述。

    用法::

        gw = ToolGateway()                       # 进程内临时 Ed25519 钥
        gw.issue("search_kb", {"query": "x"}, result="...")
        root = gw.trace_root                     # 随证明一起承诺

    ``signer`` 缺省是进程内临时 Ed25519 密钥（与 ``AgentMonitor`` 同一套约定）：
    要跨进程验证，请显式传入 ``keys.load_or_create()`` 得到的签名器，并把
    ``gateway.public_key`` 交给验证方。
    """

    def __init__(self, signer: Optional["cert.Signer"] = None,
                 ts: Optional[str] = None):
        """``ts`` 给定一个固定值时，所有回执用它 —— 便于测试可复现。"""
        from . import keys  # 局部导入：避免模块级循环依赖

        self.signer = signer if signer is not None else keys.ephemeral_signer()
        self._fixed_ts = ts
        self._receipts: List[ToolReceipt] = []

    # -- 状态 --
    @property
    def receipts(self) -> List[ToolReceipt]:
        """已签发的回执（按签发顺序的**拷贝**，改它不会影响链）。"""
        return list(self._receipts)

    @property
    def trace_root(self) -> str:
        return trace_root(self._receipts)

    @property
    def public_key(self) -> Any:
        """验签所需的公钥（``ed25519`` 签名器上可直接取到）。"""
        return getattr(self.signer, "public_key", None)

    def keyring(self) -> Dict[str, Any]:
        """``{keyid: 公钥}`` —— 直接喂给 :func:`verify_chain`。"""
        pub = self.public_key
        if pub is None:
            return {self.signer.keyid: self.signer}
        return cert.keyring(pub)

    def reset(self) -> None:
        """清空链（下一次会话从头开始）。"""
        self._receipts = []

    # -- 签发 --
    def preview(self, tool: str, args: Optional[Dict[str, Any]] = None,
                ts: Optional[str] = None) -> ToolReceipt:
        """造一条**未签名、未入链**的预览回执（飞行前筛查用）。

        工具名、参数、``seq``、``prev`` 与真正要执行的那次**逐字节相同**，
        只有 ``result_digest`` 还是空的（结果还没发生）且 ``sig`` 未签。
        它**不进** :attr:`receipts`：一次被策略拦下的调用不该在链上留下痕迹，
        而被放行的调用会在执行后用 :meth:`issue` 签出真回执。
        """
        return ToolReceipt(
            seq=len(self._receipts),
            tool=str(tool),
            args={str(k): arg_str(v) for k, v in (args or {}).items()},
            result_digest="",
            ts=ts or self._fixed_ts or utc_now(),
            prev=trace_root(self._receipts),
            keyid=self.signer.keyid,
        )

    def issue(self, tool: str, args: Optional[Dict[str, Any]] = None,
              result: Optional[str] = None,
              result_digest: Optional[str] = None,
              ts: Optional[str] = None) -> ToolReceipt:
        """签发一条回执并接到链尾。

        ``result`` 是执行结果原文（取其 SHA-256 作为 ``result_digest``）；
        已经算好摘要的调用方可以直接给 ``result_digest``。二者都给时以
        ``result_digest`` 为准。
        """
        if result_digest is None:
            result_digest = hashlib.sha256(
                (result or "").encode("utf-8")).hexdigest()
        unsigned = ToolReceipt(
            seq=len(self._receipts),
            tool=str(tool),
            args={str(k): arg_str(v) for k, v in (args or {}).items()},
            result_digest=result_digest,
            ts=ts or self._fixed_ts or utc_now(),
            prev=trace_root(self._receipts),
            keyid=self.signer.keyid,
        )
        sig = self.signer.sign(canonical_receipt_bytes(unsigned))
        receipt = replace(unsigned, sig=sig.hex())
        self._receipts.append(receipt)
        return receipt

    def seal(self, receipts: Optional[Sequence[ToolReceipt]] = None,
             ts: Optional[str] = None) -> ToolSeal:
        """对**会话末端**做一次承诺（P1-5b）—— 让截尾可被发现。

        缺省对当前链（:attr:`receipts`）签发；``receipts`` 可以让调用方指定
        另一条链（离线复算用）。返回的对象应随证书一起走
        （载荷顶层 ``trace_seal``），验证方拿它核对链长与链尾。

        签名是**确定性**的（Ed25519 无随机化），所以对同一条链重复调用会得到
        逐字节相同的 seal —— 调用方不必缓存它。

        ⚠️ 会话中途再调 :meth:`issue` 会让之前那条 seal 的 ``count``/``trace_root``
        对不上（这正是想要的：seal 说的是「到此为止」）。要出证请在**最后一次
        工具调用之后**取 seal。
        """
        chain = list(self._receipts if receipts is None else receipts)
        unsigned = ToolSeal(
            count=len(chain),
            trace_root=trace_root(chain),
            ts=ts or self._fixed_ts or utc_now(),
            keyid=self.signer.keyid,
        )
        return replace(unsigned,
                       sig=self.signer.sign(canonical_seal_bytes(unsigned)).hex())


def make_chain(entries: Sequence[Sequence[Any]],
               gateway: Optional[ToolGateway] = None,
               ts: str = "2026-01-01T00:00:00+00:00") -> List[ToolReceipt]:
    """由 ``[(tool, args, result?), ...]`` 造一条**已签名**的链（测试/示例用）。

    默认用进程内临时网关钥与固定时间戳 —— 调用方要跨进程验证就把自己的
    网关传进来。
    """
    gw = gateway if gateway is not None else ToolGateway(ts=ts)
    out: List[ToolReceipt] = []
    for entry in entries:
        tool, args = entry[0], entry[1]
        result = entry[2] if len(entry) > 2 else ""
        out.append(gw.issue(tool, args, result=result))
    return out


def receipts_to_json(receipts: Sequence[ToolReceipt]) -> List[Dict[str, Any]]:
    """回执链 → 向量 JSON 里的 ``receipts`` 字段。"""
    return [r.to_dict() for r in receipts]


def receipts_from_json(items: Any) -> List[ToolReceipt]:
    """向量 JSON 的 ``receipts`` 字段 → 回执链。"""
    return [ToolReceipt.from_dict(d) for d in (items or [])]
