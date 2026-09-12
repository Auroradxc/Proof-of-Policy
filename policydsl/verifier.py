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
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO = Path(__file__).resolve().parent.parent
#: 出证/宿主校验驱动。
POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
#: 免证明器快路径验证二进制。
POP_VERIFY = REPO / "circuits" / "target" / "release" / "pop-verify"

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


def _str_field(obj: Any, key: str) -> Optional[str]:
    """取一个非空字符串字段；缺失/类型不符一律返回 None。"""
    v = obj.get(key) if isinstance(obj, dict) else None
    return v if isinstance(v, str) and v else None


def artifact_proof_modes(proof: Path,
                         proof_result: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """一份证明工件**自报的**证明模式，按来源汇总（P0-4 标注核对用）。

    三个来源，谁在就收谁：

      - ``verifier``：``pop-verify`` 的验证输出（它会把边车里的模式带出来）；
        ``pop-script --verify`` 的输出**没有**这个字段。
      - ``sidecar``：``<proof>.verify.json``（生成时由 pop-script 写下）。
      - ``meta``：``<proof>.meta.json``（同样由 pop-script 写下）。

    **不做优先级取舍**：这些来源本就该一致，不一致本身就是发现 —— 这正是
    P0-1 的教训（单一来源的「一致」是空洞的，多来源才有约束力）。
    """
    out: Dict[str, str] = {}
    m = _str_field(proof_result or {}, "proof_mode")
    if m:
        out["verifier"] = m
    m = sidecar_proof_mode(sidecar_path(proof))
    if m:
        out["sidecar"] = m
    try:
        meta = json.loads(Path(f"{proof}.meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = None
    m = _str_field(meta or {}, "proof_mode")
    if m:
        out["meta"] = m
    return out


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


def committed_trace_root(proof_result: Dict[str, Any]) -> Optional[str]:
    """从验证器输出里取出**证明承诺的**链尾摘要（P1-5）。

    与另两个 ``committed_*`` 同样处理缺失：None 表示这一路来源不可用，绝不是
    「通过」。空链的合法值是字面量 ``"genesis"`` —— 它是一个**正常取值**，
    不是缺失。
    """
    return _committed_field(proof_result, "trace_root")


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


def check_trace_binding(sources: Sequence[Tuple[str, Optional[str]]]) -> Tuple[bool, str]:
    """轨迹绑定的比对（P1-5）：见 :func:`check_agreement`。

    来源：证书 outcome 内嵌的 `trace_root`、证明公开值承诺的 `trace_root`、
    以及验证方拿**网关侧回执**现场重算的链尾。三者相等 ⇒ 这份证明绑的正是
    **验证方自己手上那条链**，而不是出证方转述的另一条。

    **本函数只比对摘要，不验签**：链尾摘要能对上，说明链的内容一致；「这条链
    是不是网关真的签过」是另一件事，由 :func:`policydsl.trace.verify_chain`
    独立完成（`verify_cert.py --gateway-key` 会把两步都跑）。
    """
    return check_agreement(sources, what="trace_root")


def run_cmd(cmd: Sequence[str],
            env_extra: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    """在仓库根目录跑一条外部命令（cwd 固定，避免相对路径随调用方漂移）。"""
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(list(cmd), cwd=str(REPO), capture_output=True, text=True, env=env)


def verify_proof_file(proof: Path, job_kind: str = "policy", *,
                      pop_verify: Path = POP_VERIFY,
                      pop_script: Path = POP_SCRIPT) -> Dict[str, Any]:
    """验证一份**已保存**的证明，返回验证器输出的字典。

    能走 ``pop-verify``（免构造证明器）就走，否则退回 ``pop-script --verify``；
    **core 证明必须走后者** —— core 没有可供第三方核验的递归工件。
    验证失败一律抛 ``ValueError``（**不降级**）。

    组合层（``compose.py``）与会话层（``session.py``）共用这一份实现。放在这里
    而不是各写一份的理由是具体的：``--out`` 那个坑只要漏一次就会在**仓库根**
    落一个 ``results.json``（`pop-script` 的 `--out` 默认值是相对 cwd 的
    ``results.json``，而 cwd 是仓库根）—— 2026-09-12 审计在组合层发现并修好过
    一次，不希望它在第二份拷贝里复活。
    """
    sidecar = sidecar_path(proof)
    if prefer_verifier_only(proof, pop_verify):
        proc = run_cmd([str(pop_verify), "--meta", str(sidecar)])
        if proc.returncode != 0:
            # pop-verify 只在**验证失败**时非 0（用法错误是 2/3，也会到这里）；
            # 两种情形都必须 fail closed，把 stderr 带上以便定位。
            raise ValueError(f"pop-verify 拒绝这份证明（job={job_kind}）："
                             f"{proc.stderr.strip() or proc.stdout.strip()}")
        return json.loads(proc.stdout)
    args = [str(pop_script), "--verify", "--proof", str(proof), "--job", job_kind]
    with tempfile.TemporaryDirectory(prefix="pop-verify-") as tmp:
        args += ["--out", str(Path(tmp) / "verify.json")]
        proc = run_cmd(args, {"SP1_PROVER": "cpu"})
    if proc.returncode != 0:
        raise ValueError(f"pop-script --verify 失败（job={job_kind}）："
                         f"{proc.stderr.strip() or proc.stdout.strip()}")
    # pop-script --verify 把 JSON 打到 stdout，最后一段才是结果
    start = proc.stdout.find("{")
    if start < 0:
        raise ValueError(f"pop-script --verify 没有输出 JSON：{proc.stdout!r}")
    return json.loads(proc.stdout[start:])


def short_hash(h: str, n: int = 8) -> str:
    """把长哈希截断成便于打印的形式（仅用于诊断输出）。"""
    return f"{h[:n]}…" if len(h) > n + 1 else h


def outcome_without_meta(proof_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """把验证结果里的 outcome 去掉展示元信息（``name``/``mode``）后的副本。

    证书载荷里的 ``outcome`` 是签发时以同样方式剥掉这两个字段存的，因此
    验证方要用相同的剥法才能逐字段比对。取不到 outcome 时返回 None。

    ⚠️ 这里剥掉的 ``mode`` 是**运行模式**（``public``/``private``/``infer``），
    在证书载荷里它与顶层的 ``payload["mode"]`` 冗余，所以剥了不会有损失。
    但**别的用途**下 ``mode`` 可能正是要判的东西（组合层就用它做域绑定检查）——
    那种场合别用本函数，见 ``policydsl/compose.py::_outcome_of``。
    """
    outcome = proof_result.get("outcome")
    if not isinstance(outcome, dict):
        return None
    return {k: v for k, v in outcome.items() if k not in ("name", "mode")}
