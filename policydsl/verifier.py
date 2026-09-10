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
from typing import Optional

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
