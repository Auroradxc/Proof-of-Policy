"""verifier-only 路径的选择逻辑（免构造证明器）。

`pop-script --proof-out` 会给**所有**模式写一份 `<proof>.verify.json` 边车
（内含 `proof_mode`），但只有 compressed / groth16 / plonk 能被免证明器的
`pop-verify`（只依赖 `sp1-verifier`）验证；**core 证明没有可供第三方核验的
递归工件**，必须用 `pop-script --verify` 重新验证（需要证明器环境）。

因此「走快路径」的判定必须**同时**满足：二进制存在 + 边车存在 + 边车里的
`proof_mode` 属于 verifier-only 可验证模式。只看边车是否存在会把 core 证明
误判为快路径（`pop-verify` 会以 exit 3 拒绝）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: 可以被 `pop-verify` 独立验证的证明模式（core 不在其中）
VERIFIER_ONLY_MODES = ("compressed", "groth16", "plonk")


def sidecar_path(proof: Path) -> Path:
    """证明工件对应的边车路径。"""
    return Path(str(proof) + ".verify.json")


def sidecar_proof_mode(sidecar: Path) -> Optional[str]:
    """读取边车里的 `proof_mode`；读不到返回 None。"""
    try:
        return json.loads(Path(sidecar).read_text(encoding="utf-8")).get("proof_mode")
    except (OSError, ValueError):
        return None


def prefer_verifier_only(proof: Path, pop_verify: Path) -> bool:
    """是否用 `pop-verify`（免构造证明器）验证这份证明。

    需要二进制存在、边车存在，且边车声明的模式属于 `VERIFIER_ONLY_MODES`。
    """
    sidecar = sidecar_path(proof)
    if not (Path(pop_verify).exists() and sidecar.exists()):
        return False
    return sidecar_proof_mode(sidecar) in VERIFIER_ONLY_MODES


# --------------------------------------------------------------------------- #
# 策略绑定（P0-1）：三方比对
#
# 证书里有**两处**各自独立声称 policy_hash 的字段（载荷顶层的 `policy_hash`
# 与 `outcome.policy_hash`），验证方还会**自己重编译**策略包得到第三个值，
# 而证明的公开值里还有电路承诺的第四个值。这些值必须全部相等。
#
# 为什么不能只比其中两个：P0-1 的教训是「被哈希的东西」与「被使用的东西」
# 必须是同一份。同理，这里任何一个来源都可能与另外几个脱钩 —— 只比
# 「证书声称 == 重编译」会漏掉「证明其实是对另一个策略做的」，只比
# 「证书声称 == 证明承诺」则漏掉「证书声称的策略根本不是这个策略包」。
# --------------------------------------------------------------------------- #

#: 绑定比对里来源标签 → 说明（用于失败时的可读诊断）
_SOURCE_LABELS = {
    "cert": "证书载荷声明的 policy_hash",
    "cert.outcome": "证书 outcome 内嵌的 policy_hash",
    "recompiled": "由策略包现场重编译得到的 sha256",
    "proof": "证明公开值承诺的 policy_hash",
    "cert.challenge": "证书 challenge 块声明的 response_binding",
    "response": "由送达的响应 T′ 与 nonce 现场重算的 response_binding",
}


def _committed_field(proof_result: Dict[str, Any], field: str) -> Optional[str]:
    """从验证器输出里取出证明公开值承诺的某个字符串字段；取不到返回 None。"""
    outcome = proof_result.get("outcome")
    if isinstance(outcome, dict):
        v = outcome.get(field)
        if isinstance(v, str):
            return v
    return None


def committed_policy_hash(proof_result: Dict[str, Any]) -> Optional[str]:
    """从 `pop-verify` / `pop-script --verify` 的结果里取出**证明承诺的**策略哈希。

    取不到返回 None —— 调用方必须把它当作「这一路来源缺失」处理，而不是
    「检查通过」：把缺失当成通过正是 P0-1 那个漏洞的形态。
    """
    return _committed_field(proof_result, "policy_hash")


def committed_response_binding(proof_result: Dict[str, Any]) -> Optional[str]:
    """从验证器输出里取出**证明承诺的**响应绑定（P0-2）。

    与 :func:`committed_policy_hash` 同样处理缺失：None 表示这一路来源不可用，
    绝不是「通过」。
    """
    return _committed_field(proof_result, "response_binding")


def check_agreement(sources: Sequence[Tuple[str, Optional[str]]],
                    what: str = "policy_hash") -> Tuple[bool, str]:
    """比对若干来源声称的同一个值：**非 None 的来源必须全部相等**。

    ``sources`` 是 ``[(label, value_or_None), ...]``；``label`` 用于诊断，
    取值见 :data:`_SOURCE_LABELS`。返回 ``(ok, detail)``。``what`` 只用于措辞。

    只要**至少两个**来源参与比对才算通过：只有一个来源时「全部相等」是空洞的，
    那等于没有任何约束。缺失的来源会被如实列进 detail，避免报告读起来像是
    做过完整的三方比对。
    """
    present = [(lbl, h) for lbl, h in sources if h is not None]
    missing = [lbl for lbl, h in sources if h is None]
    uniq = {h for _, h in present}
    ok = len(present) >= 2 and len(uniq) == 1
    if len(present) < 2:
        return False, ("only {} source(s) available ({}) — binding uncheckable"
                       .format(len(present), ", ".join(lbl for lbl, _ in present) or "none"))
    detail = " == ".join(f"{short_hash(h)}[{lbl}]" for lbl, h in present)
    if not ok:
        detail = "MISMATCH: " + detail
    if missing:
        detail += " (absent: " + ", ".join(missing) + ")"
    return ok, detail


def check_policy_binding(sources: Sequence[Tuple[str, Optional[str]]]) -> Tuple[bool, str]:
    """策略绑定的比对（P0-1）：见 :func:`check_agreement`。"""
    return check_agreement(sources, what="policy_hash")


def check_response_binding(sources: Sequence[Tuple[str, Optional[str]]]) -> Tuple[bool, str]:
    """响应绑定的比对（P0-2）：见 :func:`check_agreement`。

    与策略绑定**同构**，理由也一样：证书的 challenge 块、outcome 内嵌值、
    证明公开值、以及由送达响应 T′ 现场重算的值，四者必须全部相等。少比任何
    一路都会留盲区 —— 只比「证书自称 == 重算」会漏掉「证明其实承诺的是另一条
    响应」，只比「证书自称 == 证明承诺」则漏掉「送达的 T′ 根本不是被证明的 T」。
    """
    return check_agreement(sources, what="response_binding")


def short_hash(h: str, n: int = 8) -> str:
    """把长哈希截断成便于打印的形式（仅用于诊断输出）。"""
    return f"{h[:n]}…" if len(h) > n + 1 else h


def outcome_without_meta(proof_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """把验证结果里的 outcome 去掉展示元信息（``name``/``mode``）后的副本。

    证书载荷里的 ``outcome`` 是签发时以同样方式剥掉这两个字段存的，因此
    验证方要用相同的剥法才能逐字段比对。取不到 outcome 时返回 None。
    """
    outcome = proof_result.get("outcome")
    if not isinstance(outcome, dict):
        return None
    return {k: v for k, v in outcome.items() if k not in ("name", "mode")}
