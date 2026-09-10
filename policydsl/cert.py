"""Proof-of-Policy 的合规证书（compliance certificate）。

一张证书为「一次 agent 响应 / 工具调用」绑定以下信息：

    策略（id/version）+ policy_hash（ConstraintSpec 的 sha256）
    + 承诺的判定结果（ProofOutput / PrivateOutput）
    + 程序 vkey 哈希与证明工件（proof）哈希
    + 时间戳，以及 EU AI Act 第 12/13 条的声明

证书被包在一个 **类 DSSE 信封**（payloadType + base64 载荷 + 签名）里。默认
签名器是 HMAC-SHA256（`demo-hmac-sha256`）—— 仅用标准库的占位实现；部署时
应换成 Ed25519（信封结构保持不变）。

由于载荷是确定性的（规范 JSON），证书能哈希出一个稳定的 ``cert_digest``，
用于锚定（见 ``policydsl.anchor``）。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

CERT_VERSION = "v1"
PAYLOAD_TYPE = "application/vnd.proof-of-policy+json"
DEFAULT_KEYID = "demo-hmac-sha256"
# 共享的 demo 签名密钥（标准库 HMAC）。部署时替换为真实密钥/Ed25519。
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


def ai_act_claims(mode: str) -> Dict[str, Any]:
    """证书携带的 EU AI Act 关联声明。

    Art.12（记录留存）：每张证书都是一条防篡改、按调用的审计记录（已锚定）。
    Art.13（透明度）：policy hash + mode + outcome 使系统声明的行为可被第三方核验。
    """
    return {
        "art12_record_keeping": {
            "per_call_record": True,
            "policy_hash_bound": True,
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
                  public_values_sha256: Optional[str] = None) -> Dict[str, Any]:
    """组装证书载荷（给定输入 + ts 后即为确定性结构）。

    ``extra`` 携带可选注解，例如 ``{"streaming": {"partial": true, "tokens": N}}``
    用于流式（增量）证书（在流中间为前缀签发）。
    ``public_values_sha256`` 绑定承诺的公开值，供 verifier-only（``pop-verify``）
    校验使用。
    """
    payload = {
        "cert_version": CERT_VERSION,
        "policy": {"id": policy_id, "version": policy_version},
        "policy_hash": spec["sha256"],
        "mode": mode,
        "outcome": outcome,
        "binding": {"vkey_hash": vkey_hash, "proof_sha256": proof_sha256,
                    "public_values_sha256": public_values_sha256},
        "ai_act": ai_act_claims(mode),
        "ts": ts or utc_now(),
    }
    if extra:
        payload.update(extra)
    return payload


def cert_digest(payload: Dict[str, Any]) -> str:
    """载荷的稳定摘要（即锚定值）。"""
    return sha256_hex(canonical(payload))


def sign_payload(payload: Dict[str, Any], key: bytes,
                 keyid: str = DEFAULT_KEYID) -> Dict[str, Any]:
    """把载荷包进一个用 HMAC-SHA256 签名的类 DSSE 信封。"""
    payload_bytes = canonical(payload)
    sig = hmac.new(key, payload_bytes, hashlib.sha256).digest()
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode("ascii")}],
    }


def envelope_keyid(env: Dict[str, Any]) -> Optional[str]:
    """返回信封第一个签名的 keyid（若无签名则返回 None）。"""
    sigs = env.get("signatures") or []
    return sigs[0].get("keyid") if sigs else None


def envelope_payload(env: Dict[str, Any]) -> Dict[str, Any]:
    """从信封里解码出载荷字典。"""
    return json.loads(base64.b64decode(env["payload"]).decode("utf-8"))


def verify_envelope(env: Dict[str, Any], key: bytes) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """校验信封签名；返回 (ok, payload)。

    用 ``hmac.compare_digest`` 做常量时间比较，避免时序侧信道。
    """
    try:
        payload_bytes = base64.b64decode(env["payload"])
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (KeyError, ValueError):
        return False, None
    sigs = env.get("signatures") or []
    if not sigs:
        return False, None
    expected = hmac.new(key, payload_bytes, hashlib.sha256).digest()
    got = base64.b64decode(sigs[0]["sig"])
    return hmac.compare_digest(expected, got), payload
