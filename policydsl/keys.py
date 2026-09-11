"""签名密钥的加载、生成与保管（P0-3）。

P0-3 之前，证书用一把**硬编码在源码里的公开密钥**做 HMAC 签名
（``cert.DEMO_KEY``）。对称密钥的根本问题是**不提供不可否认性**：验证方持有
同一把密钥，所以任何能验签的人也能伪造签名 —— 而「记录不可否认」正是审计
证书的全部意义。现在改用 Ed25519：私钥签名、公钥验证，验证方无法伪造。

本模块只做三件事：

1. **定位**私钥文件（``POP_SIGNING_KEY`` 环境变量 → 缺省 ``.pop-keys/signing.key``）；
2. **读/写** PKCS#8 PEM（``load_or_create`` 在没有时生成一把新的）；
3. 把公钥导出成便于传递的形式（原始 32 字节十六进制 / PEM / ``keyid``）。

验证方那侧只需 :func:`load_keyring`：喂给它 ``key.json``、``session.json`` 或
一段公钥十六进制，得到 ``{keyid: 验签器}`` 交给 ``cert.verify_envelope``。
**从头到尾不需要私钥** —— 这正是非对称签名相对 HMAC 的意义。

> **私钥文件权限**：``save_private`` 以 ``0600`` 写入，并且**不会**覆盖已存在的
> 文件（要轮换密钥请显式删除或换路径）。``.pop-keys/`` 已在 ``.gitignore`` 中。
>
> **口令**：设 ``POP_SIGNING_KEY_PASSPHRASE`` 则私钥以 BestAvailableEncryption
> 落盘；不设则明文 PKCS#8（依赖文件系统权限）。生产应使用口令或 HSM。

公钥被刻意设计成**可公开分发**的（它是 ``keyid`` 的来源）：验证方拿到公钥即可
独立验签，这正是把「证书给第三方审计」这件事变得可行的前提。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from . import cert

REPO = Path(__file__).resolve().parent.parent

#: 私钥路径的环境变量名。
ENV_KEY_PATH = "POP_SIGNING_KEY"
#: 私钥口令的环境变量名（可选）。
ENV_PASSPHRASE = "POP_SIGNING_KEY_PASSPHRASE"
#: 缺省私钥文件（仓库根下的隐藏目录；已被 .gitignore 忽略）。
DEFAULT_KEY_PATH = REPO / ".pop-keys" / "signing.key"


def key_path(path: Optional[Union[str, Path]] = None) -> Path:
    """解析私钥路径：显式参数 > ``POP_SIGNING_KEY`` > 缺省值。"""
    if path is not None:
        return Path(path).expanduser()
    env = os.environ.get(ENV_KEY_PATH)
    if env:
        return Path(env).expanduser()
    return DEFAULT_KEY_PATH


def _passphrase() -> Optional[bytes]:
    p = os.environ.get(ENV_PASSPHRASE)
    return p.encode("utf-8") if p else None


# --------------------------------------------------------------------------
# 读写
# --------------------------------------------------------------------------

def save_private(private_key: Ed25519PrivateKey, path: Union[str, Path],
                 passphrase: Optional[bytes] = None) -> Path:
    """把私钥写成 PKCS#8 PEM（``0600``）。

    **已存在则不覆盖** —— 静默替换签名密钥会让「谁签的」这件事无从追溯。
    """
    path = Path(path).expanduser()
    if path.exists():
        raise FileExistsError(f"私钥已存在，拒绝覆盖：{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    enc = (serialization.BestAvailableEncryption(passphrase)
           if passphrase else serialization.NoEncryption())
    pem = private_key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8, enc)
    # 先以 0600 创建再写入，避免出现「短暂的 0644 明文私钥」窗口。
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return path


def load_private(path: Union[str, Path],
                 passphrase: Optional[bytes] = None) -> Ed25519PrivateKey:
    """从 PEM 读私钥（带口令时须提供同一口令）。"""
    pem = Path(path).expanduser().read_bytes()
    key = serialization.load_pem_private_key(pem, password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"不是 Ed25519 私钥：{path}")
    return key


def load_or_create(path: Optional[Union[str, Path]] = None,
                   passphrase: Optional[bytes] = None) -> Ed25519PrivateKey:
    """读私钥；不存在则**生成一把新的并落盘**。

    ``passphrase`` 缺省取 ``POP_SIGNING_KEY_PASSPHRASE``。注意：口令只用于
    新建/读取**同一个**文件；如果文件已存在而口令不对，会抛 ``ValueError``。
    """
    p = key_path(path)
    pw = passphrase if passphrase is not None else _passphrase()
    if p.exists():
        return load_private(p, pw)
    key = Ed25519PrivateKey.generate()
    save_private(key, p, pw)
    return key


def signer_from_env(path: Optional[Union[str, Path]] = None,
                    passphrase: Optional[bytes] = None) -> "cert.Ed25519Signer":
    """便捷入口：``load_or_create`` + 包成 :class:`cert.Ed25519Signer`。"""
    return cert.Ed25519Signer(load_or_create(path, passphrase))


def ephemeral_signer() -> "cert.Ed25519Signer":
    """生成一把**不落盘**的临时签名器（demo/测试用，进程结束即消失）。

    用它签出的证书只在该进程内可验证；要跨进程/跨方验证，请把
    :attr:`cert.Ed25519Signer.public_hex` 一起交出去。
    """
    return cert.Ed25519Signer.generate()


# --------------------------------------------------------------------------
# 公钥导出 / 导入
# --------------------------------------------------------------------------

def public_hex(public_key: Ed25519PublicKey) -> str:
    """原始 32 字节公钥的十六进制（``keyid`` 的输入、也是传输格式）。"""
    return cert.raw_public_bytes(public_key).hex()


def public_from_hex(text: str) -> Ed25519PublicKey:
    """从十六进制还原公钥（接受 ``0x`` 前缀、空白与大小写混写）。"""
    clean = "".join(text.split()).removeprefix("0x").removeprefix("0X")
    try:
        raw = bytes.fromhex(clean)
    except ValueError as exc:
        raise ValueError("公钥不是合法十六进制") from exc
    if len(raw) != 32:
        raise ValueError(f"Ed25519 公钥应为 32 字节，得到 {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def public_pem(public_key: Ed25519PublicKey) -> str:
    """公钥的 PEM 文本（便于贴进邮件/工单/仓库）。"""
    return public_key.public_bytes(serialization.Encoding.PEM,
                                   serialization.PublicFormat.SubjectPublicKeyInfo
                                   ).decode("ascii")


def keyid(public_key: Ed25519PublicKey) -> str:
    """公钥的 ``keyid``（``ed25519:<sha256(原始公钥)>``）。"""
    return cert.ed25519_keyid(public_key)


def read_public_text(text: str) -> Ed25519PublicKey:
    """从「十六进制 **或** PEM」文本解析公钥（类型由内容判断）。"""
    stripped = text.strip()
    if stripped.startswith("-----BEGIN"):
        key = serialization.load_pem_public_key(stripped.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("不是 Ed25519 公钥")
        return key
    return public_from_hex(stripped)


def load_public(path_or_text: Union[str, Path]) -> Ed25519PublicKey:
    """从文件读公钥；参数含 ``-----BEGIN`` 时按文本解析，否则当路径。"""
    s = str(path_or_text)
    if s.strip().startswith("-----BEGIN"):
        return read_public_text(s)
    return read_public_text(Path(s).expanduser().read_text())


# --------------------------------------------------------------------------
# keyring 装配（验证方入口）
# --------------------------------------------------------------------------

def public_record(public_key: Ed25519PublicKey) -> Dict[str, str]:
    """公钥的可分发记录：``{"keyid": …, "public_hex": …}``。

    ``issue_cert.py`` 把这条写进 ``key.json``，``demo_e2e.py`` 把它写进
    ``session.json`` 的 ``signers`` 列表 —— 验证方据此独立构造 keyring，
    全程不需要私钥。
    """
    return {"keyid": keyid(public_key), "public_hex": public_hex(public_key)}


def _ring_from_records(records: Any) -> Dict[str, Any]:
    """把若干 ``{"keyid", "public_hex"}`` 记录（或单个 dict）装成 keyring。"""
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        raise TypeError(f"无法解释为公钥记录：{type(records).__name__}")
    out: Dict[str, Any] = {}
    for rec in records:
        if not isinstance(rec, dict) or "public_hex" not in rec:
            raise ValueError("公钥记录缺少 public_hex 字段")
        pub = public_from_hex(rec["public_hex"])
        kid = rec.get("keyid") or keyid(pub)
        # 记录里自称的 keyid 必须与公钥推导的一致，否则「按 keyid 选密钥」就失效
        if kid != keyid(pub):
            raise ValueError(f"keyid 与公钥不符：{kid} ≠ {keyid(pub)}")
        out[kid] = pub
    return out


def load_keyring(source: Any) -> Dict[str, Any]:
    """把各种「公钥来源」统一读成 ``{keyid: 验签器}``。

    接受：

    * ``None`` → 空 keyring；**不存在的 ``Path``** 同样返回空（那是「探测式」
      回退路径，缺文件是正常情况）；``str`` 则严格解析，拼错了会报错
      —— 看着像路径（``…/``、``*.json``/``*.hex``/``*.pem``/``*.txt``）却读不到时
      明确报「找不到文件」，而不会退回成「不是合法十六进制」那种把人带偏的提示；
    * ``{"keyid", "public_hex"}`` 或这类记录的 list（``key.json`` 解析结果、
      ``session.json`` 的 ``signers`` 字段）；
    * **文件路径**：``key.json`` / ``session.json`` / ``*.pub.hex`` / ``*.pub.pem``；
    * **公钥文本**：十六进制或 PEM。

    私钥**永远不参与**——验证方只需要公钥。
    """
    if source is None:
        return {}
    if isinstance(source, (dict, list)):
        return _ring_from_records(source)
    if isinstance(source, Path):
        # 探测式回退：调用方常把「可能存在的 key.json」直接丢进来
        return load_keyring(source.read_text(encoding="utf-8")) if source.exists() else {}

    s = str(source)
    path = Path(s).expanduser()
    text = s if (s.lstrip().startswith(("{", "[")) or "-----BEGIN" in s) else None
    if text is None and path.exists():
        text = path.read_text(encoding="utf-8")
    if text is None and path.suffix.lower() in (".json", ".hex", ".pem", ".txt"):
        # 路径拼错是最常见的手误：此时把它当公钥文本解析只会得到
        # 「公钥不是合法十六进制」，与真正的原因（文件不存在）南辕北辙。
        raise FileNotFoundError(
            f"找不到公钥文件：{path}（要直接传公钥文本，请给十六进制或 PEM）")
    if text is None:
        text = s  # 既不是 JSON、也不是已存在的文件 → 当公钥文本（hex/PEM）
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if parsed is not None:
        # key.json 是单条记录；session.json 把记录放在 "signers" 里
        if isinstance(parsed, dict) and "signers" in parsed:
            parsed = parsed["signers"]
        return _ring_from_records(parsed)
    return _ring_from_records([public_record(read_public_text(text))])


def merge_keyrings(*rings: Any) -> Dict[str, Any]:
    """合并若干 keyring 来源（后者覆盖同 keyid 的前者）。"""
    out: Dict[str, Any] = {}
    for r in rings:
        out.update(load_keyring(r))
    return out
