"""带盐策略承诺（BHV 框架定理 D 的最小落地）。

**问题。** 旧实现里的 ``policy_hash = SHA256(canonical(π))`` 是**公开、可离线
重算**的 ``π`` 的函数。策略空间不大（8 类规则、参数范围有限、3–8 条规则），
于是验证者可以枚举候选策略、逐个编译、比对哈希 —— 这和响应侧的
``response_binding`` 是同一个数学对象：一个公开可重算的秘密函数。

> 关闭的是**策略文本**（它确实是 witness），不是**策略哈希**。

**构造。** 给策略包加一个高熵盐，并让它进入规范字节：

```
policy_nonce  ← {0,1}^128
policy_hash   = SHA256(canonical(π) ‖ policy_nonce)
```

- 盐由签发权威生成（P-PP），随策略包发行，**不进证书载荷**的
  ``policy.id/version``；验证者看到 ``policy_hash``，但枚举空间乘以 ``2^128``。
- 审计时权威开示 ``(π, policy_nonce)``；验证者重算哈希即可确认「跑的就是签发的
  那条策略」。
- 空盐 = 旧行为，**现有 7 个策略包的 ``policy_hash`` 逐字节不变**。

**两个通道要分开说（不要 overclaim）：**

1. **公开值通道**：``policy_hash`` 本身可枚举 —— 本模块关闭它。
2. **证明工件通道**：SP1 ``core`` 的证明工件不隐藏见证，``π`` 仍可能从 trace
   泄露 —— 本模块**不**关闭它；需要 ``groth16/plonk`` 的 witness-hiding
   （见 ``docs/certificate-binding-framework.md`` §7.3 与 ``docs/sp1-zk-audit.md``）。

第三个通道是**披露层级**（规则名 / ``delegated``），由 E4 的 L0/L1/L2 处理。
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import secrets
from typing import Any, Dict, Optional

from policydsl.core.compile import canonical_spec_bytes, compile_policy
from policydsl.core.model import Policy

#: 盐的字节数。128 bit 是「即便策略在候选集里，猜中盐的概率也 ≤ 2^-128」的
#: 常用下限；与 ``response_binding`` 用 nonce 的思路同构。
POLICY_NONCE_BYTES = 16

#: 盐的十六进制长度（必须与 :data:`POLICY_NONCE_BYTES` 一致）。
POLICY_NONCE_HEX_LEN = POLICY_NONCE_BYTES * 2

#: 域分隔前缀。将来换承诺方案（如 Pedersen）时改这里，旧证书不会互相冒充。
POLICY_COMMIT_DOMAIN = b"pop-policy-commit-v1"


def new_policy_nonce(nbytes: int = POLICY_NONCE_BYTES) -> str:
    """生成一个高熵盐（小写十六进制）。默认 16 字节 = 128 bit。"""
    if nbytes < 16:
        raise ValueError("policy_nonce must be at least 16 bytes (128 bits)")
    return secrets.token_hex(nbytes)


def attach_nonce(pack: Dict[str, Any], nonce: Optional[str] = None) -> Dict[str, Any]:
    """返回**复制**的策略包，带 ``policy_nonce``（缺省现场生成）。

    不修改入参：策略包在测试/脚本/服务里可能被多处共享，原地加盐会让
    「同一份 pack 在不同调用里算出不同哈希」—— 那正是 R7 那类事故的变种。
    """
    out = copy.deepcopy(pack)
    out["policy_nonce"] = (nonce or new_policy_nonce()).lower()
    return out


def policy_commitment(pack: Dict[str, Any]) -> str:
    """把策略包编译成 ``ConstraintSpec``，返回带盐的 ``policy_hash``。

    这是提交给证书/公开值的那个值。它已经包含 ``policy_nonce``（若 pack 里有）。
    """
    policy = Policy.from_dict(pack)
    policy.validate()
    return compile_policy(policy)["sha256"]


def verify_commitment(pack: Dict[str, Any], commitment: str) -> bool:
    """``pack`` 配上它自带的盐，能否打开 ``commitment``（常量时间比较）。

    审计路径：权威开示 ``pack``（含盐）→ 验证者调本函数 → 与自己手里的
    ``policy_hash`` 比对。验证者**没有**盐时打不开，这正是隐藏性的来源。
    """
    return hmac.compare_digest(policy_commitment(pack), commitment)


def commitment_bytes(pack: Dict[str, Any]) -> bytes:
    """暴露规范字节，便于实验/调试（盐在字节里可见）。"""
    policy = Policy.from_dict(pack)
    policy.validate()
    return canonical_spec_bytes(compile_policy(policy))


def commitment_digest(pack: Dict[str, Any]) -> str:
    """域分隔后的强承诺：``SHA256(domain ‖ canonical(π) ‖ salt)``。

    与 :func:`policy_commitment` 的区别：后者就是证书里现有的
    ``policy_hash``（对规范字节求哈希，未加域分隔）。本函数给需要独立域
    的实验/未来方案用；两者都包含盐，但**不要混用**。
    """
    policy = Policy.from_dict(pack)
    policy.validate()
    spec = compile_policy(policy)
    raw = canonical_spec_bytes(spec)
    h = hashlib.sha256()
    h.update(POLICY_COMMIT_DOMAIN)
    h.update(b"\x00")
    h.update(raw)
    return h.hexdigest()
