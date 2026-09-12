"""Proof-of-Policy 的合规证书（compliance certificate）。

一张证书为「一次 agent 响应 / 工具调用」绑定以下信息：

    策略（id/version）+ policy_hash（ConstraintSpec 的 sha256）
    + 承诺的判定结果（ProofOutput / PrivateOutput）
    + 程序 vkey 哈希、证明工件（proof）哈希、**证明模式与它的隐藏程度**
    + 时间戳，以及 EU AI Act 第 12/13 条的声明

``binding.proof_mode`` 是**诚实标注**（P0-4）：``core``/``compressed`` STARK 是
**非零知识**的，只有 ``groth16``/``plonk`` 的「内部证明作 gnark 电路私有见证」
才在包装器层面隐藏 —— 见 :data:`PROOF_MODE_HIDING` 与 ``docs/sp1-zk-audit.md``。
把这一档写进证书，是为了让「有证明」不被默认读成「零知识」。

证书被包在一个 **类 DSSE 信封**（payloadType + base64 载荷 + 签名）里。
签名算法由信封的 ``keyid`` **方案前缀**（``keyid`` 冒号前的部分）决定，验签
时按前缀分发到 keyring —— 见 ``verify_envelope``。

支持的方案：

===================  ================================  ==================
方案前缀             实现                              用途
===================  ================================  ==================
``ed25519``          :class:`Ed25519Signer`            **生产**（不可否认）
``test-hmac-sha256`` :class:`HmacSigner`               仅测试/演示
===================  ================================  ==================

> ⚠️ **历史遗留**：P0-3 之前，本模块用一把**硬编码的公开密钥** ``DEMO_KEY``
> 做 HMAC（``keyid = "demo-hmac-sha256"``）。HMAC 是**对称**的 —— 验证方持有
> 同一把密钥，因此它**不提供不可否认性**：任何能验签的人也能伪造签名。
> 现在该方案**不在任何默认 keyring 里**，``verify_envelope`` 遇到它一律拒绝
> （方案未知），即旧证书**不再被接受**。``DEMO_KEY``/``DEFAULT_KEYID`` 保留
> 仅为兼容引用与负例测试，**不要在新代码里使用**。

由于载荷是确定性的（规范 JSON），证书能哈希出一个稳定的 ``cert_digest``，
用于锚定（见 ``policydsl.anchor``）。``keyid`` 只出现在信封（不参与
``cert_digest``），所以更换密钥**不会**让已有锚定失效。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

try:  # pragma: no cover - 导入失败时给出可读错误，而不是 ImportError 栈
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTOGRAPHY = False

CERT_VERSION = "v1"
PAYLOAD_TYPE = "application/vnd.proof-of-policy+json"

#: 生产方案前缀（Ed25519）。
ED25519_SCHEME = "ed25519"
#: 仅测试使用的 HMAC 方案前缀。**故意**与历史的 ``demo-hmac-sha256`` 不同。
HMAC_TEST_SCHEME = "test-hmac-sha256"

#: 「未附证明」的 ``proof_mode`` 取值（与 ``vkey_hash="unproven"`` 同义）。
PROOF_MODE_UNPROVEN = "unproven"

#: 「未附证明」的 ``vkey_hash`` 取值 —— **故意**与 :data:`PROOF_MODE_UNPROVEN`
#: 同一个字符串，因为二者说的是同一件事。
#:
#: ``binding.vkey_hash`` 的语义是「**哪块电路**判定了它」：它指向
#: `pop-program` / `pop-infer` / `pop-session` 三块 guest ELF 各自派生出的
#: 验证密钥，验证方拿它核对「证明确实来自声明的那块电路」。而**宿主判定**
#: （Python 参考评估器在进程内判的 stream/llm/tool 三类证书）根本没有电路
#: 参与 —— 没有证明，就没有验证密钥可指，唯一诚实的取值只能是这个。
#:
#: 这个常量存在的理由是一条**曾经不成立的**不变量：``proof_mode`` 有诚实性
#: 校验（``verify_cert.py`` 的 2b 卡 + ``verify_session.py`` 的
#: ``certificates_proof_mode``），``vkey_hash`` 却一条都没有，于是
#: ``demo_e2e.py`` 写的魔法值 ``"demo"`` 可以**全绿通过验证** ——
#: 验证方只比对「证书 vs 证明」，从不问这个值本身是否可能是真的。
#: 不变量与 ``proof_mode`` 同构：**没有工件 ⟺ 取值为此常量**。
VKEY_HASH_UNPROVEN = PROOF_MODE_UNPROVEN

#: 证明模式 → **证明工件对见证的隐藏程度**。
#:
#: 这张表是 P0-4 审计结论的落地（见 ``docs/sp1-zk-audit.md`` §2）：它把「私有模式」
#: 的口径钉死在「**公开值**不泄露明文」上，而不是「**证明工件**不泄露见证」。
#: 证书里标注 ``proof_mode`` 让验证方一眼看到自己拿到的到底是哪一档，而不是默认
#: 把「有证明」当成「零知识」。
#:
#: * ``none`` —— STARK（core/compressed）**非零知识**：``main_commitment`` 与
#:   ``opened_values`` 在证明工件里明文可见，且源头审计未见任何盲化；
#: * ``wrapper-only`` —— groth16/plonk 把内部 STARK 证明当作 gnark 电路的**私有
#:   见证**，公开输入只剩 5 个。但这是**包装器层面的构造性声明**：未被任何审计
#:   评估、非后量子、且本机 12 GB 出不了证；
#: * ``n/a`` —— 没有证明工件。
PROOF_MODE_HIDING = {
    PROOF_MODE_UNPROVEN: "n/a",
    "core": "none",
    "compressed": "none",
    "groth16": "wrapper-only",
    "plonk": "wrapper-only",
}


def proof_hiding(proof_mode: Optional[str]) -> str:
    """该证明模式对见证的隐藏程度；**未知/未标注一律返回 ``"unknown"``**。

    刻意不做「未知即安全」的默认 —— 那正是这张表要防的错误。
    """
    if not proof_mode:
        return "unknown"
    return PROOF_MODE_HIDING.get(proof_mode, "unknown")


# --- 历史遗留（P0-3 之前）：对称 HMAC，保留仅供负例测试与旧文档引用 ---
#: 旧 demo 信封的 keyid。``verify_envelope`` 现在**不认**这个方案。
DEFAULT_KEYID = "demo-hmac-sha256"
#: 旧的硬编码公开演示密钥。**不具备任何安全性**，勿用于新代码。
DEMO_KEY = b"proof-of-policy-demo-key"


def canonical(obj: Any) -> bytes:
    """规范 JSON 字节（键排序、紧凑分隔符、UTF-8）。

    规范序列化是证书可被「独立重算哈希」的基础。
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """对字节求 SHA-256 并返回十六进制字符串。"""
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    """当前 UTC 时间的 ISO 格式字符串（证书时间戳）。"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ai_act_claims(mode: str, challenge_bound: bool = False) -> Dict[str, Any]:
    """证书携带的 EU AI Act 关联声明。

    Art.12（记录留存）：每张证书都是一条防篡改、按调用的审计记录（已锚定）。
    Art.13（透明度）：policy hash + mode + outcome 使系统声明的行为可被第三方核验。

    ``challenge_bound`` 如实反映这张证书是否带 ``challenge`` 块（P0-2）——
    没有它，证书只说明「某条 T 通过了」，说不出是哪条。这是个实质性区别，
    不能默认成 True。
    """
    return {
        "art12_record_keeping": {
            "per_call_record": True,
            "policy_hash_bound": True,
            "response_bound": challenge_bound,
            "anchored": True,
        },
        "art13_transparency": {
            "policy_disclosed": True,
            "mode": mode,  # "public"（响应公开） | "private"（仅承诺）
            "outcome_disclosed": True,
        },
    }


def build_payload(policy_id: str, policy_version: str, spec: Dict, mode: str,
                  outcome: Dict, vkey_hash: str,
                  proof_sha256: Optional[str] = None,
                  ts: Optional[str] = None,
                  extra: Optional[Dict[str, Any]] = None,
                  public_values_sha256: Optional[str] = None,
                  challenge: Optional[Dict[str, str]] = None,
                  proof_mode: Optional[str] = None,
                  trace_seal: Optional[Dict[str, Any]] = None,
                  semantic: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """组装证书载荷（给定输入 + ts 后即为确定性结构）。

    ``extra`` 携带可选注解，例如 ``{"streaming": {"partial": true, "tokens": N}}``
    用于流式（增量）证书（在流中间为前缀签发）。
    ``public_values_sha256`` 绑定承诺的公开值，供 verifier-only（``pop-verify``）
    校验使用。
    ``proof_mode`` 是 ``binding`` 里的**诚实标注**：这张证书的证据是哪种证明
    （``core``/``compressed``/``groth16``/``plonk``/``unproven``）。缺省按
    ``proof_sha256`` 推断 —— 没有证明工件就记 ``"unproven"``，有工件却没说
    模式则记 ``None``（验证方会显示 ``unknown``，**不会**替出证方假设成安全的那档）。
    隐藏程度由 :func:`proof_hiding` 给出（见 ``PROOF_MODE_HIDING``）。
    ``challenge`` 是 P0-2 的挑战块（见 ``policydsl.challenge.challenge_block``）：
    它公开 nonce 与证明承诺的 ``response_binding``，让持 T′ 的一方能离线确认
    「被证明的 T」就是「送达的 T′」。**nonce 是公开的**（它必须公开，否则没人
    能核对）；它的一次性由协议使用方保证，不是秘密。

    ``trace_seal`` 是 P1-5b 的会话末端承诺（``ToolGateway.seal()``）：网关签的
    ``{count, trace_root}``，用来说明「这条回执链到此为止」。它放在**载荷顶层**
    而不是 ``outcome`` 里 —— ``outcome`` 是**证明公开值的镜像**（验证方会逐字段
    比对，见 ``scripts/verify_cert.py`` 的 ``proof_outcome`` 卡），而电路里没有
    seal 这个东西：它是链下网关签的，与 ``challenge`` 块同属「主机层随证书附上
    的旁证」。放进 ``outcome`` 的后果是**每一张带真实证明的证书都对不上**
    （公开值里没有这个字段）。见 ``policydsl/trace.py`` 的「截尾与 ToolSeal」。

    ``semantic`` 是 P2-9 的**语义规则陪伴证明**块（同样在载荷**顶层**，理由与
    ``trace_seal`` 完全相同）：

        {"companions": [{"rule", "system", "vk_sha256", "onnx_sha256",
                         "threshold_bp", "direction", "proof_file",
                         "proof_sha256"}, ...]}

    它**不是**可有可无的装饰。SP1 公开值里的 ``outcome.delegated`` 非空时，语义
    规则**没有被那份证明判定**；这一块携带的 ezkl 陪伴证明才是判定它的东西。
    验证方必须对 ``delegated`` 里每一条都找到匹配的 companion 并逐字段核验
    （``policydsl.semantic.verify_companion``），**一条都不能少** —— 少了就是
    「看起来验过了」而实际没验。``delegated`` 非空而本块缺失/不全时，
    ``verify_cert.py`` 一律判 FAIL（fail closed）。
    """
    if proof_mode is None and proof_sha256 is None:
        proof_mode = PROOF_MODE_UNPROVEN      # 没有工件 → 只能自称「未证明」
    payload = {
        "cert_version": CERT_VERSION,
        "policy": {"id": policy_id, "version": policy_version},
        "policy_hash": spec["sha256"],
        "mode": mode,
        "outcome": outcome,
        "binding": {"vkey_hash": vkey_hash, "proof_sha256": proof_sha256,
                    "public_values_sha256": public_values_sha256,
                    "proof_mode": proof_mode},
        "ai_act": ai_act_claims(mode, challenge_bound=challenge is not None),
        "ts": ts or utc_now(),
    }
    if challenge is not None:
        payload["challenge"] = challenge
    if trace_seal is not None:
        payload["trace_seal"] = trace_seal
    if semantic is not None:
        payload["semantic"] = semantic
    if extra:
        payload.update(extra)
    return payload


def cert_digest(payload: Dict[str, Any]) -> str:
    """载荷的稳定摘要（即锚定值）。"""
    return sha256_hex(canonical(payload))


# --------------------------------------------------------------------------
# 签名器
# --------------------------------------------------------------------------

class Signer:
    """签名器接口（鸭子类型；无需继承）。

    三个成员：``keyid``（含**方案前缀**，如 ``"ed25519:ab12…"``）、
    ``sign(data) -> bytes``、``verify(data, sig) -> bool``。
    """

    keyid: str

    def sign(self, data: bytes) -> bytes:  # pragma: no cover - 接口声明
        raise NotImplementedError

    def verify(self, data: bytes, sig: bytes) -> bool:  # pragma: no cover
        raise NotImplementedError


def public_fingerprint(raw_public: bytes) -> str:
    """公钥指纹 = ``SHA256(原始公钥字节)`` 的十六进制。"""
    return hashlib.sha256(raw_public).hexdigest()


def ed25519_keyid(public_key: "Ed25519PublicKey") -> str:
    """由 Ed25519 公钥导出 ``keyid``（``ed25519:<指纹>``）。"""
    return ED25519_SCHEME + ":" + public_fingerprint(raw_public_bytes(public_key))


def raw_public_bytes(public_key: "Ed25519PublicKey") -> bytes:
    """Ed25519 公钥的 32 字节原始表示（指纹与传输都用它）。"""
    return public_key.public_bytes(serialization.Encoding.Raw,
                                   serialization.PublicFormat.Raw)


class Ed25519Signer:
    """生产签名器：Ed25519（**非对称**，提供不可否认性）。

    验证方只需公钥，因此**无法**伪造签名 —— 这正是它相对 HMAC 的意义。
    消息（载荷字节）按 Ed25519 规范内部哈希，故对任意长度都只需一次
    64 字节签名的开销，不必预哈希。
    """

    scheme = ED25519_SCHEME

    def __init__(self, private_key: "Ed25519PrivateKey"):
        if not _HAVE_CRYPTOGRAPHY:  # pragma: no cover
            raise RuntimeError("需要 cryptography：pip install cryptography")
        self._private = private_key

    # -- 构造 --
    @classmethod
    def generate(cls) -> "Ed25519Signer":
        """生成一把新的 Ed25519 私钥。"""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "Ed25519Signer":
        """从 32 字节种子构造。"""
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    # -- 属性 --
    @property
    def private_key(self) -> "Ed25519PrivateKey":
        return self._private

    @property
    def public_key(self) -> "Ed25519PublicKey":
        return self._private.public_key()

    @property
    def public_bytes(self) -> bytes:
        """原始 32 字节公钥（便于写进会话文件/十六进制传递）。"""
        return raw_public_bytes(self.public_key)

    @property
    def public_hex(self) -> str:
        return self.public_bytes.hex()

    @property
    def keyid(self) -> str:
        return ed25519_keyid(self.public_key)

    # -- 签名 --
    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    def verify(self, data: bytes, sig: bytes) -> bool:
        return _ed25519_verify(self.public_key, data, sig)


class HmacSigner:
    """**仅测试/演示**的对称 HMAC-SHA256 签名器。

    ``keyid`` 前缀固定为 ``test-hmac-sha256`` —— 与历史的
    ``demo-hmac-sha256`` 不同，后者不被任何默认 keyring 接受。
    对称密钥**不提供不可否认性**，生产请用 :class:`Ed25519Signer`。
    """

    scheme = HMAC_TEST_SCHEME

    def __init__(self, key: bytes, keyid: Optional[str] = None):
        if not key:
            raise ValueError("HMAC 密钥不能为空")
        self._key = bytes(key)
        self.keyid = keyid or (HMAC_TEST_SCHEME + ":" +
                               public_fingerprint(self._key)[:32])

    def sign(self, data: bytes) -> bytes:
        return hmac.new(self._key, data, hashlib.sha256).digest()

    def verify(self, data: bytes, sig: bytes) -> bool:
        return hmac.compare_digest(self.sign(data), sig)  # 常量时间


def _ed25519_verify(public_key: "Ed25519PublicKey", data: bytes, sig: bytes) -> bool:
    """Ed25519 验签：任何异常/长度不符都收敛为 False（绝不抛给调用方）。"""
    try:
        public_key.verify(sig, data)
        return True
    except Exception:
        return False


def public_signer(public_key: "Ed25519PublicKey") -> "Ed25519PublicKey":
    """把公钥包成可放进 keyring 的「只能验签」对象。

    Ed25519 公钥本身就有 ``verify``，直接放进 keyring 即可；本函数只是
    给调用方一个显式的意图表达。
    """
    return public_key


# --------------------------------------------------------------------------
# keyring：按 keyid 分发
# --------------------------------------------------------------------------

#: keyid → 验签器（``Signer`` 或裸 ``Ed25519PublicKey``）。
Keyring = Dict[str, Any]


def keyring(*signers: Any) -> Keyring:
    """由若干签名器/公钥构造 keyring（键为各自的 ``keyid``）。

    ``ed25519`` 的公钥会自动推导 keyid，因此
    ``keyring(signer.public_key)`` 与 ``keyring(signer)`` 等价。
    """
    kr: Keyring = {}
    for s in signers:
        kr[_signer_keyid(s)] = s
    return kr


def _signer_keyid(obj: Any) -> str:
    """取任意验签对象的 keyid（Signer 用其属性，裸公钥现算）。"""
    if isinstance(obj, Ed25519PublicKey):
        return ed25519_keyid(obj)
    kid = getattr(obj, "keyid", None)
    if not isinstance(kid, str) or not kid:
        raise ValueError(f"对象没有可用的 keyid：{type(obj).__name__}")
    return kid


def _normalize_keyring(obj: Any) -> Keyring:
    """把用户传入的「keyring」参数收敛成 ``{keyid: 验签器}``。

    接受：``None``（空 ring）、dict、单个 ``Signer``/公钥、``bytes``（旧式
    HMAC 密钥 → 包成 :class:`HmacSigner`，keyid 为 ``test-hmac-sha256:…``）。
    """
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return dict(obj)
    if isinstance(obj, (bytes, bytearray)):
        s = HmacSigner(bytes(obj))
        return {s.keyid: s}
    if isinstance(obj, Ed25519PublicKey) or hasattr(obj, "sign") or hasattr(obj, "verify"):
        return {_signer_keyid(obj): obj}
    raise TypeError(f"无法解释为 keyring：{type(obj).__name__}")


def sign_payload(payload: Dict[str, Any], signer: Any,
                 keyid: Optional[str] = None) -> Dict[str, Any]:
    """把载荷包进类 DSSE 信封并签名。

    ``signer`` 可以是任意 :class:`Signer`（推荐 :class:`Ed25519Signer`），
    也可以是 ``bytes``（旧式 HMAC 密钥 —— 等价于 :class:`HmacSigner`，
    仅供测试；产出的信封 keyid 前缀是 ``test-hmac-sha256``，**不是**旧
    ``demo-hmac-sha256``）。

    ``keyid`` 仅在对 ``bytes`` 场景下用于覆盖默认 keyid。
    """
    if isinstance(signer, (bytes, bytearray)):
        signer = HmacSigner(bytes(signer), keyid)
    payload_bytes = canonical(payload)
    sig = signer.sign(payload_bytes)
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [{"keyid": signer.keyid,
                        "sig": base64.b64encode(sig).decode("ascii")}],
    }


def envelope_keyid(env: Dict[str, Any]) -> Optional[str]:
    """返回信封第一个签名的 keyid（若无签名则返回 None）。"""
    sigs = env.get("signatures") or []
    return sigs[0].get("keyid") if sigs else None


def envelope_scheme(env: Dict[str, Any]) -> str:
    """返回信封签名的**方案前缀**（``keyid`` 冒号前的部分）；无签名则空串。"""
    kid = envelope_keyid(env) or ""
    return kid.split(":", 1)[0]


def envelope_payload(env: Dict[str, Any]) -> Dict[str, Any]:
    """从信封里解码出载荷字典（**不验证签名**，调用方自己负责）。"""
    return json.loads(base64.b64decode(env["payload"]).decode("utf-8"))


def verify_envelope(env: Dict[str, Any], keyring: Any) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """校验信封签名；返回 ``(ok, payload)``。

    分发规则（按信封 ``keyid`` 的**方案前缀**）：

    * ``ed25519`` → 从 keyring 里取**同名 keyid** 的验签器；不在 ring 里 ⇒ 拒。
    * ``test-hmac-sha256`` → 同上（仅测试用）。
    * 其它任何前缀（含历史的 ``demo-hmac-sha256``）⇒ **直接拒绝**：
      keyring 里就算放了对应密钥也没用，方案本身不被接受。

    因此「默认 keyring 不含 HMAC」这件事是**结构性**的，不是配置疏漏 ——
    P0-3 之前用 ``DEMO_KEY`` 签出的旧信封不可能再通过。

    **失败时返回 ``(False, None)``**（不返回未经签名验证的载荷），
    调用方必须先判 ``ok`` 再用 payload。
    """
    try:
        payload_bytes = base64.b64decode(env["payload"])
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (KeyError, TypeError, ValueError):
        return False, None

    sigs = env.get("signatures") or []
    if not sigs:
        return False, None
    sig = sigs[0]
    kid = sig.get("keyid") or ""
    scheme = kid.split(":", 1)[0]

    if scheme not in (ED25519_SCHEME, HMAC_TEST_SCHEME):
        return False, None  # 未知/已废弃方案（如 demo-hmac-sha256）

    verifier = _normalize_keyring(keyring).get(kid)
    if verifier is None:
        return False, None  # 方案认得，但这把 keyid 不在 ring 里

    try:
        got = base64.b64decode(sig["sig"])
    except (KeyError, TypeError, ValueError):
        return False, None

    ok = bool(_ed25519_verify(verifier, payload_bytes, got)
              if isinstance(verifier, Ed25519PublicKey)
              else verifier.verify(payload_bytes, got))
    return (True, payload) if ok else (False, None)
