"""策略签发前置条件（P-PP）：权威签发带盐策略清单，验证方据此核对证书。

**问题。** 私有策略模式下，``policy_hash`` 本身是**惰性**的：运营方对**任意**
策略 π′ 都能出一张自洽的证书，只要把 ``SHA256(π′)`` 写进 ``policy_hash``。
证明系统证明的是「**某个**哈希为 H 的策略通过了」，而不是「监管方签发的**那条**
策略通过了」。密码学补不上这个缺口 —— 要补就得让验证方看到 π，而那正是私有
模式要藏的东西。唯一能补的是一次**签发行为**（见 ``docs/security-model.md``
§4.6 的前提 P-PP）。

**本模块给出的东西。** 一个最小的证书层原型：

    manifest = {
        "manifest_version": "v1",
        "policy_id":       "agent-content-v1",
        "policy_version":  "0.1.0",
        "policy_hash":     SHA256(canonical(π) ‖ policy_nonce),   # 带盐承诺
        "issued_at":       "2026-11-01T00:00:00Z",
        "authority_keyid": "ed25519:<sha256(公钥)>",
        "sig":             base64(Ed25519(canonical_manifest_bytes(manifest))),
    }

签发权威（规范方 R）用 Ed25519 私钥签这份清单；第三方 V 只持权威**公钥**，
先验清单签名，再确认证书里的 ``policy_hash`` 出现在清单里。于是 V 得到的是：

    「这张证书声称的哈希，是一份**被签发过**的策略的哈希」

而不是「运营方自己挑的一个数」。

**清单里刻意不出现什么。** ``policy_nonce`` 与策略正文（``rules`` 等）**都不进**
manifest。盐留在权威/运营方手里，审计时由运营方主动开示 ``(π, nonce)``；第三方
只看到 ``policy_hash`` 与 ``policy_id/version``。否则「验证方不可枚举策略」这条
带盐承诺的意义就被清单本身抵消了。

**与证书的关系（只读，不改证书）。** 本模块**不**参与 ``cert.build_payload`` /
``cert.sign_payload``，也**不**改证书字节。它只是在证书之外，给验证方一条
「这个 ``policy_hash`` 是谁签发的」的旁路。证书里的 ``policy_hash`` 仍由现有
签发路径写入；``verify_cert_policy`` 读载荷、查清单、验签名。

**边界（不要 overclaim，详见 ``docs/design-policy-pp.md``）：**

* 它证明「哈希对应一份被权威签发的策略」，**不**证明策略内容对第三方可见；
* 它依赖权威诚实（A4 类信任假设），权威签错策略时本层无能为力；
* 它**不**关闭证明工件（``core`` trap/opened values）或 ``delegated`` 的泄露通道；
* 清单本身若可被替换，P-PP 就退化成「运营方自签」—— 权威公钥的**带外分发**
  是这套机制成立的前提，不在本模块内。
"""

from __future__ import annotations

import base64
import copy
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union

from policydsl.core.model import Policy
from policydsl.evidence import cert
from policydsl.privacy.policy_commit import policy_commitment

try:  # pragma: no cover - 与 cert.py 同一套可选依赖
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    _HAVE_CRYPTOGRAPHY = False

#: 清单版本。换承诺方案/字段语义时改这里；旧清单会被明确拒绝，不会静默兼容。
MANIFEST_VERSION = "v1"

#: 签发记录文件的版本。
REGISTRY_VERSION = "v1"

#: 清单必须同名的字段（缺一即拒）。``sig`` 不参与规范字节，但必须存在。
MANIFEST_FIELDS: Tuple[str, ...] = (
    "manifest_version", "policy_id", "policy_version", "policy_hash",
    "issued_at", "authority_keyid", "sig",
)

#: 不允许出现在清单里的字段：盐与策略正文。出现即拒 —— 清单是**公开分发**的，
#: 把 nonce/正文放进去等于把带盐承诺和私有策略模式一起作废。
FORBIDDEN_MANIFEST_FIELDS: Tuple[str, ...] = (
    "policy_nonce", "rules", "policy", "pack", "spec",
)

#: 权威签名方案前缀（与 ``cert.ED25519_SCHEME`` 同口径）。
AUTHORITY_SCHEME = cert.ED25519_SCHEME

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_KEYID = re.compile(r"^ed25519:[0-9a-f]{64}$")

#: 一份清单就是一个纯 dict（便于 JSON 往返）；别名只用于类型提示。
Manifest = Dict[str, Any]


# --------------------------------------------------------------------------
# 规范字节与签发
# --------------------------------------------------------------------------

def canonical_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    """清单的规范字节：键排序、紧凑分隔符、UTF-8，**排除 ``sig``**。

    签名的对象就是这串字节。排除 ``sig`` 是因为签名不能覆盖自身；其余字段
    （包括 ``authority_keyid`` 与 ``issued_at``）全部被签，任何改动都会验签失败。
    """
    if not isinstance(manifest, Mapping):
        raise TypeError("manifest 必须是映射（dict）")
    body = {k: v for k, v in manifest.items() if k != "sig"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _signer_keyid(signer: Any) -> str:
    """取签发器 keyid，并强制它是 Ed25519 方案（P-PP 需要非对称不可否认）。"""
    kid = getattr(signer, "keyid", None)
    if not isinstance(kid, str) or not kid:
        raise ValueError("签发器没有可用 keyid")
    if not kid.startswith(AUTHORITY_SCHEME + ":"):
        raise ValueError(
            f"P-PP 只接受 {AUTHORITY_SCHEME} 签发器，得到 {kid.split(':', 1)[0]!r}")
    if not _KEYID.match(kid):
        raise ValueError(f"keyid 形状不合法：{kid}")
    return kid


def issue_manifest(pack: Dict[str, Any], signer: Any,
                   issued_at: Optional[str] = None) -> Manifest:
    """为策略包签发一份清单（返回纯 dict，不落盘）。

    ``policy_hash`` 由 :func:`policydsl.privacy.policy_commit.policy_commitment`
    计算 —— 也就是证书里那个**带盐**的承诺。调用方若希望隐藏策略，应先用
    :func:`policydsl.privacy.policy_commit.attach_nonce` 加盐；本函数不会偷偷
    替你加盐（否则同一 pack 两次签发会得到不同哈希，破坏可复现性）。

    ``signer`` 需提供 ``keyid`` 与 ``sign(bytes) -> bytes``（如
    :class:`policydsl.evidence.cert.Ed25519Signer`）。
    """
    if not hasattr(signer, "sign"):
        raise TypeError("signer 必须提供 sign(bytes) -> bytes")
    keyid = _signer_keyid(signer)

    policy = Policy.from_dict(pack)
    policy.validate()                      # id/version 必填，缺了当场报错
    manifest: Manifest = {
        "manifest_version": MANIFEST_VERSION,
        "policy_id": policy.id,
        "policy_version": policy.version,
        "policy_hash": policy_commitment(pack),
        "issued_at": issued_at or cert.utc_now(),
        "authority_keyid": keyid,
    }
    sig = signer.sign(canonical_manifest_bytes(manifest))
    manifest["sig"] = base64.b64encode(sig).decode("ascii")
    return manifest


# --------------------------------------------------------------------------
# 校验
# --------------------------------------------------------------------------

def _structure_problem(manifest: Any) -> Optional[str]:
    """只查形状/字段完整性（**不验签**）。返回问题描述，``None`` 表示通过。"""
    if not isinstance(manifest, Mapping):
        return f"manifest 必须是映射，得到 {type(manifest).__name__}"
    missing = [f for f in MANIFEST_FIELDS if f not in manifest]
    if missing:
        return "缺少字段：" + ", ".join(missing)
    forbidden = [f for f in FORBIDDEN_MANIFEST_FIELDS if f in manifest]
    if forbidden:
        return ("manifest 不得包含 " + ", ".join(forbidden)
                + "（盐/策略正文只能由权威在审计时开示）")
    if manifest["manifest_version"] != MANIFEST_VERSION:
        return (f"不支持的 manifest_version：{manifest['manifest_version']!r}"
                f"（期望 {MANIFEST_VERSION!r}）")
    for field in ("policy_id", "policy_version", "issued_at"):
        value = manifest[field]
        if not isinstance(value, str) or not value:
            return f"{field} 必须是非空字符串"
    if not isinstance(manifest["policy_hash"], str) or not _HEX64.match(manifest["policy_hash"]):
        return "policy_hash 必须是 64 位小写十六进制"
    if not isinstance(manifest["authority_keyid"], str) or not _KEYID.match(manifest["authority_keyid"]):
        return "authority_keyid 必须是 'ed25519:<64 位小写十六进制>'"
    sig = manifest["sig"]
    if not isinstance(sig, str) or not sig:
        return "sig 必须是非空的 base64 字符串"
    try:
        raw_sig = base64.b64decode(sig, validate=True)
    except (ValueError, TypeError):
        return "sig 不是合法 base64"
    if len(raw_sig) != 64:
        return f"Ed25519 签名应为 64 字节，得到 {len(raw_sig)}"
    return None


def _as_public_key(public_key: Any) -> "Ed25519PublicKey":
    """接受公钥对象 / 带 ``.public_key`` 的签名器 / 十六进制或 PEM 文本。"""
    if not _HAVE_CRYPTOGRAPHY:  # pragma: no cover
        raise RuntimeError("需要 cryptography：pip install cryptography")
    if isinstance(public_key, Ed25519PublicKey):
        return public_key
    inner = getattr(public_key, "public_key", None)
    if isinstance(inner, Ed25519PublicKey):
        return inner
    if isinstance(public_key, (bytes, bytearray)):
        raw = bytes(public_key)
        if len(raw) != 32:
            raise ValueError(f"Ed25519 公钥应为 32 字节，得到 {len(raw)}")
        return Ed25519PublicKey.from_public_bytes(raw)
    if isinstance(public_key, str):
        text = public_key.strip()
        if text.startswith("-----BEGIN"):
            from policydsl.evidence import keys  # 延迟导入，避免模块级循环
            return keys.read_public_text(text)
        clean = "".join(text.split()).removeprefix("0x").removeprefix("0X")
        try:
            raw = bytes.fromhex(clean)
        except ValueError as exc:
            raise ValueError("公钥不是合法十六进制") from exc
        if len(raw) != 32:
            raise ValueError(f"Ed25519 公钥应为 32 字节，得到 {len(raw)}")
        return Ed25519PublicKey.from_public_bytes(raw)
    raise TypeError(f"无法解释为 Ed25519 公钥：{type(public_key).__name__}")


def manifest_problem(manifest: Any, public_key: Any) -> Optional[str]:
    """返回第一个问题（``None`` 表示**完整且验签通过**）。

    检查顺序：字段完整性 → 公钥可解析 → ``authority_keyid`` 与公钥一致 →
    Ed25519 验签。``verify_manifest`` 是它的布尔包装。
    """
    problem = _structure_problem(manifest)
    if problem is not None:
        return problem
    try:
        pub = _as_public_key(public_key)
    except (TypeError, ValueError) as exc:
        return f"公钥无法解析：{exc}"
    expected = cert.ed25519_keyid(pub)
    if manifest["authority_keyid"] != expected:
        return (f"authority_keyid 与公钥不符：清单声称 "
                f"{manifest['authority_keyid']}，公钥是 {expected}")
    raw_sig = base64.b64decode(manifest["sig"])
    try:
        pub.verify(raw_sig, canonical_manifest_bytes(manifest))
    except InvalidSignature:
        return "清单签名无效（字段被篡改，或不是这把权威私钥签的）"
    except Exception as exc:  # pragma: no cover - 长度/格式等边缘错误
        return f"清单验签失败：{exc}"
    return None


def verify_manifest(manifest: Any, public_key: Any) -> bool:
    """字段完整性 + ``authority_keyid`` 绑定 + Ed25519 验签，全部通过才 True。"""
    return manifest_problem(manifest, public_key) is None


# --------------------------------------------------------------------------
# 签发记录（registry）
# --------------------------------------------------------------------------

class PolicyRegistry:
    """一份可被第三方读取的**签发记录**：``policy_hash -> manifest``。

    只做「按哈希查清单」与 JSON 往返。**不**在这里决定信任谁 —— 验签需要
    权威公钥，由调用方（``verify_cert_policy``）显式传入。``add`` 只做结构检查，
    因为 registry 可能由第三方（不带权威公钥）转存。
    """

    def __init__(self, manifests: Iterable[Manifest] = ()):
        self._by_hash: Dict[str, Manifest] = {}
        for m in manifests:
            self.add(m)

    # -- 写入 --
    def add(self, manifest: Manifest) -> str:
        """登记一份清单，返回其 ``policy_hash``。

        同一哈希重复登记**同内容**是幂等的；同哈希但**不同内容**一律拒绝 ——
        那要么是权威重签（应由权威显式替换），要么是两份互相矛盾的签发记录。
        """
        problem = _structure_problem(manifest)
        if problem is not None:
            raise ValueError(problem)
        h = manifest["policy_hash"]
        if h in self._by_hash:
            if canonical_manifest_bytes(self._by_hash[h]) != canonical_manifest_bytes(manifest):
                raise ValueError(
                    f"policy_hash {h} 已有内容不同的签发记录（拒绝静默覆盖）")
            return h
        self._by_hash[h] = copy.deepcopy(dict(manifest))
        return h

    # -- 读取 --
    def get(self, policy_hash: str) -> Optional[Manifest]:
        """按哈希取清单的副本；不存在返回 ``None``。"""
        m = self._by_hash.get(policy_hash)
        return copy.deepcopy(m) if m is not None else None

    def contains(self, policy_hash: str) -> bool:
        return policy_hash in self._by_hash

    def hashes(self) -> List[str]:
        return sorted(self._by_hash)

    def manifests(self) -> List[Manifest]:
        return [self.get(h) for h in self.hashes()]

    def __len__(self) -> int:
        return len(self._by_hash)

    def __contains__(self, policy_hash: object) -> bool:
        return isinstance(policy_hash, str) and policy_hash in self._by_hash

    def __iter__(self):
        return iter(self.hashes())

    # -- 落盘 --
    def save(self, path: Union[str, Path]) -> Path:
        """写成确定性 JSON（按哈希排序），便于 diff/分发。"""
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = {"registry_version": REGISTRY_VERSION, "manifests": self.manifests()}
        path.write_text(
            json.dumps(doc, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Union[str, Path]) -> "PolicyRegistry":
        """读回 :meth:`save` 写出的 JSON。

        也接受裸清单列表（``[manifest, …]``）—— 某些分发渠道只保留数组。
        缺文件抛 ``FileNotFoundError``，坏 JSON / 坏结构抛 ``ValueError``。
        """
        path = Path(path).expanduser()
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"签发记录不是合法 JSON：{path}") from exc
        if isinstance(doc, dict):
            version = doc.get("registry_version", REGISTRY_VERSION)
            if version != REGISTRY_VERSION:
                raise ValueError(
                    f"不支持的 registry_version：{version!r}（期望 {REGISTRY_VERSION!r}）")
            items = doc.get("manifests")
        else:
            items = doc
        if not isinstance(items, list):
            raise ValueError("签发记录里 manifests 必须是数组")
        return cls(items)


# --------------------------------------------------------------------------
# 证书 × 清单
# --------------------------------------------------------------------------

def verify_cert_policy(payload: Mapping[str, Any], registry: Any,
                       public_key: Any) -> Tuple[bool, str]:
    """确认证书载荷里的 ``policy_hash`` 是一份**被权威签发**的策略。

    参数
    ----
    payload : 证书**载荷**（``cert.envelope_payload(env)`` 的结果，不是信封）。
    registry : :class:`PolicyRegistry`，或 ``{policy_hash: manifest}`` 映射。
    public_key : 权威公钥（对象 / 十六进制 / PEM）。

    检查链：

    1. 载荷里有 ``policy_hash``；
    2. 该哈希在签发记录里；
    3. 对应清单字段完整、``authority_keyid`` 与公钥一致、Ed25519 验签通过；
    4. 若载荷带 ``policy.{id,version}``，必须与清单一致 —— 否则运营方可以拿
       一条被签发策略的哈希去冒充另一条策略的 id/version。

    返回 ``(ok, detail)``。``detail`` 在成功时说明命中的策略，失败时说明断点。
    """
    if not isinstance(payload, Mapping):
        return False, "证书载荷必须是映射"
    h = payload.get("policy_hash")
    if not isinstance(h, str) or not h:
        return False, "证书载荷缺少 policy_hash"

    if isinstance(registry, PolicyRegistry):
        manifest = registry.get(h)
    elif isinstance(registry, Mapping):
        manifest = registry.get(h)
    else:
        return False, f"registry 类型不支持：{type(registry).__name__}"
    if manifest is None:
        return False, f"policy_hash {h} 不在签发记录中（不是被签发的策略）"
    # 防御：调用方可能传裸 dict 而非 PolicyRegistry。Key 必须与清单自带的
    # policy_hash 一致，否则「按 A 查、拿 B 的签名」就能通过。
    if not isinstance(manifest, Mapping) or manifest.get("policy_hash") != h:
        return False, "签发记录条目与查询哈希不一致"

    problem = manifest_problem(manifest, public_key)
    if problem is not None:
        return False, f"签发清单校验失败：{problem}"

    policy = payload.get("policy")
    if isinstance(policy, Mapping):
        cid, cver = policy.get("id"), policy.get("version")
        if cid not in (None, manifest["policy_id"]):
            return False, (f"证书策略 id 与签发记录不符：证书 {cid!r} ≠ "
                           f"清单 {manifest['policy_id']!r}")
        if cver not in (None, manifest["policy_version"]):
            return False, (f"证书策略版本与签发记录不符：证书 {cver!r} ≠ "
                           f"清单 {manifest['policy_version']!r}")

    return True, (f"policy_hash {h[:16]}… 对应已签发策略 "
                  f"{manifest['policy_id']}@{manifest['policy_version']}"
                  f"（权威 {manifest['authority_keyid']}）")
