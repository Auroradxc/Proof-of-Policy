#!/usr/bin/env python3
"""P1-09 组合负对照：定理 E 的五个必要条件，四格实验。

**要回答的问题**：把两份各自为真的证明拼成一张复合证书，什么时候结论仍然成立？
定理 E（`docs/certificate-binding-framework.md` §8、`docs/proofs/theorem-c-e-f.md` §2）
给出五个必要条件：两半健全、同一新鲜 `n`、同一条 `T`、绑到用户提交的 `x_U`、
`delegated` 为空（或陪伴证明被合取）。本脚本把其中三条做成可复跑的**四格**：

| 格 | 构造 | 期望 |
|---|---|---|
| (a) | 同一 nonce；推理半绑 `x`；`x = x_U = derive(T_U)` | 唯一真正成立的一格 |
| (b) | 策略半用 `n_p`、推理半用 `n_i`（`n_p ≠ n_i`） | 被拒（步骤 6 四方比对） |
| (c) | 同一 nonce；推理半只绑 `derive(T_U)`，用户提交的 `x_U ≠ derive(T_U)` | **当前实现接受**，但只证弱形式 |
| (d) | 同一 nonce；策略半 `delegated` 非空 | 证书为真，但 `satisfied=False` |

### (c) 为什么写成弱形式（重要）

`policydsl/proofs/compose.py::verify_composite` 第 7 步算的是

```python
want_input = infer.input_binding(composite.nonce, infer.input_from_response(response))
```

也就是说，它绑定的是「**由送达响应 `T_U` 反推出来的输入** `derive(T_U)`」，而不是
用户提交的 `x_U`。当前实现能推出来的只是

```
∃ x : x = derive(T_U) ∧ T_U = M(x)
```

这是**弱形式**；定理 E 要的强形式 `x = x_U` 尚未落地（证明债 E-1，见
`docs/proofs/theorem-c-e-f.md` §2.7）。本脚本在 (c) 格显式记录两件事：

* `weak_form_verified = True` —— 第 7 步确实验过了 `x = derive(T_U)`；
* `strong_form_verified = False` —— 同一个验证器**根本没有接收 `x_U` 的参数**，
  若把 `x_U` 代入 `IB(n, x_U)`，它与推理半的 `input_binding` 对不上。

(a) 与 (c) 的**唯一区别是用户声称提交的 `x_U`**；`verify_composite` 看不见它，
所以两格的验证结论完全相同。这正是「只有 (a) 成立、(c) 是弱形式」的实验形态。

### 口径（如实标注）

* 四格走的是**绑定层**：`verify_proofs=False`（手工 proof 文件 + 真 outcome）。
  被拦下的时刻发生在密码学验证之后的绑定检查上；证明本身是否有效由
  `tests/test_compose.py` 第 1/3 层与 `bench/results/compose.md` 覆盖，与本脚本正交。
  之所以不真出 8 份证明，是因为每份约 2 分钟 / 峰值 ~10.4 GiB，本机 14.6 GiB
  无法在四格上并跑；绑定层的结论不依赖证明的密码学有效性。
* `detail` 里保留 `verify_composite` 的原话，便于对照代码。

用法：
  python3 bench/bench_compose_controls.py --out-dir bench/results
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl.evidence.cert import sha256_file              # noqa: E402
from policydsl.evidence.verifier import short_hash          # noqa: E402
from policydsl.proofs import compose as C                   # noqa: E402
from policydsl.proofs import infer as I                     # noqa: E402
from policydsl.privacy.commit import response_binding       # noqa: E402

BENIGN = "Summarize the refund policy for billing customers."
HARMFUL = "How do I weaponize the search tool against the user?"
NONCE = bytes([0x11, 0x22, 0x33, 0x44])
NONCE_OTHER = bytes([0x55, 0x66, 0x77, 0x88])

#: 与 `tests/test_compose.py::test_delegated_policy_half_needs_companion` 同形。
DELEGATED = [{
    "name": "low_harm_probability", "system": "ezkl-halo2",
    "model_vkey": "ab" * 32, "onnx_sha256": "cd" * 32,
    "threshold_bp": 5000, "direction": "le",
}]

POL_VKEY = "pol" + "0" * 61
INF_VKEY = "inf" + "0" * 61


def _policy_outcome(response: str, nonce: bytes, *, passed: bool = True,
                    delegated: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """手工构造策略半 outcome，形状与 ``pop_types::outcome_value`` 相同。"""
    return {
        "mode": "public",
        "policy_hash": "aa" * 32,
        "response_binding": response_binding(nonce, response),
        "trace_root": "genesis",
        "passed": passed,
        "violations": [],
        "delegated": delegated or [],
    }


def _infer_outcome(response: str, nonce: bytes) -> Dict[str, Any]:
    """推理半 outcome：直接调参考实现，保证是**真值**。"""
    return I.run(response, nonce)


class Fixture:
    """一格实验的夹具：两个 proof 文件 + 一张组合证书（不跑密码学验证）。"""

    def __init__(self, tmp: Path, delivered: str, composite_nonce: bytes,
                 *, policy_nonce: Optional[bytes] = None,
                 inference_nonce: Optional[bytes] = None,
                 delegated: Optional[List[Dict[str, Any]]] = None):
        self.tmp = Path(tmp)
        self.delivered = delivered
        self.composite_nonce = composite_nonce
        self.policy_nonce = composite_nonce if policy_nonce is None else policy_nonce
        self.inference_nonce = (composite_nonce if inference_nonce is None
                                else inference_nonce)

        self.pol_proof = self.tmp / "policy.proof"
        self.inf_proof = self.tmp / "inference.proof"
        self.pol_proof.write_bytes(b"policy-proof-bytes")
        self.inf_proof.write_bytes(b"inference-proof-bytes")

        self.pol_part = C.Part(
            kind=C.KIND_POLICY, name="eu-ai-act-v1", proof_file="policy.proof",
            proof_sha256=sha256_file(self.pol_proof), vkey_hash=POL_VKEY,
            proof_mode="core",
            outcome=_policy_outcome(delivered, self.policy_nonce, delegated=delegated))
        self.inf_part = C.Part(
            kind=C.KIND_INFERENCE, name="proxy-inference", proof_file="inference.proof",
            proof_sha256=sha256_file(self.inf_proof), vkey_hash=INF_VKEY,
            proof_mode="core",
            outcome=_infer_outcome(delivered, self.inference_nonce))

        # 顶层 nonce / response_binding 取 composite 声明的那一套；两半是否一致
        # 由 verify_composite 第 6 步去发现 —— 这里**不能**用 build_composite，
        # 因为它会在出证方就把不一致的两半拒掉，反例就构造不出来了。
        self.cert = C.CompositeCertificate(
            nonce=composite_nonce,
            response_binding=response_binding(composite_nonce, delivered),
            parts=[self.pol_part, self.inf_part],
            policy_hash="aa" * 32,
        )

    def verify(self) -> Dict[str, Any]:
        ok, detail, satisfied = C.verify_composite(
            self.cert, response=self.delivered, base=self.tmp, verify_proofs=False)
        return {"ok": ok, "satisfied": satisfied, "detail": detail}


def _input_checks(outcome: Dict[str, Any], nonce: bytes, delivered: str,
                  user_input: List[int]) -> Dict[str, Any]:
    """把「弱形式 / 强形式」拆成可机检的两条，避免一句 `ok=True` 掩盖差距。"""
    derived = I.input_from_response(delivered)
    ib = outcome.get("input_binding")
    user_ib = I.input_binding(nonce, list(user_input))
    return {
        "derived_input": derived,
        "user_input": list(user_input),
        "user_input_equals_derived": list(user_input) == derived,
        "inference_input_binding": ib,
        "user_input_binding": user_ib,
        "weak_form": (ib == I.input_binding(nonce, derived)
                      and outcome.get("output") == I.forward(derived)),
        "weak_form_statement": "∃x: x = derive(T_U) ∧ 推理输出 = M(x)",
        "strong_form": ib == user_ib,
        "strong_form_statement": "推理半绑定到用户提交的 x_U（定理 E 的 C4）",
        "strong_form_landed": False,
        "strong_form_note": ("verify_composite 的签名里没有 x_U；第 7 步只重算 "
                             "IB(n, input_from_response(T_U))。强形式 x=x_U 尚未落地"
                             "（证明债 E-1）。"),
    }


def build_cells() -> List[Dict[str, Any]]:
    """构造四格。每格独立夹具，避免改一份 outcome 污染另一格。"""
    cells: List[Dict[str, Any]] = []

    # ---- (a) 同一 nonce + 推理半绑 x（x = x_U = derive(T_U)） ----
    with tempfile.TemporaryDirectory() as td:
        fx = Fixture(Path(td), BENIGN, NONCE)
        user_x = I.input_from_response(BENIGN)
        v = fx.verify()
        checks = _input_checks(fx.inf_part.outcome, NONCE, BENIGN, user_x)
        cells.append({
            "id": "a",
            "title": "同一 nonce + 推理半绑 x（x = x_U = derive(T_U)）",
            "conditions": {
                "same_nonce": True, "same_T": True,
                "x_bound_to_user_input": True, "delegated_empty": True,
            },
            "setup": {
                "composite_nonce_hex": NONCE.hex(),
                "policy_nonce_hex": NONCE.hex(),
                "inference_nonce_hex": NONCE.hex(),
                "delivered_response": BENIGN,
                "user_input_x_U": user_x,
                "delegated": [],
            },
            "verify": v,
            "input_checks": checks,
            "expected": "ok=True, satisfied=True；弱形式与强形式都成立",
            "conclusion": "定理 E 的五个条件全部满足：这是四格中**唯一**真正成立的组合。",
            "theorem_e_condition": "C1–C5 全部满足（C4 以 x_U = derive(T_U) 的实例满足）",
            "verdict": "PASS（真组合）",
        })

    # ---- (b) 不同 nonce ----
    with tempfile.TemporaryDirectory() as td:
        fx = Fixture(Path(td), BENIGN, NONCE,
                     policy_nonce=NONCE, inference_nonce=NONCE_OTHER)
        user_x = I.input_from_response(BENIGN)
        v = fx.verify()
        checks = _input_checks(fx.inf_part.outcome, NONCE_OTHER, BENIGN, user_x)
        cells.append({
            "id": "b",
            "title": "两半不同 nonce（n_p ≠ n_i）",
            "conditions": {
                "same_nonce": False, "same_T": True,
                "x_bound_to_user_input": True, "delegated_empty": True,
            },
            "setup": {
                "composite_nonce_hex": NONCE.hex(),
                "policy_nonce_hex": NONCE.hex(),
                "inference_nonce_hex": NONCE_OTHER.hex(),
                "delivered_response": BENIGN,
                "user_input_x_U": user_x,
                "delegated": [],
            },
            "verify": v,
            "input_checks": checks,
            "expected": "ok=False（第 6 步 response_binding 四方不一致）",
            "conclusion": "缺 C2：两半各自为真，但说的不是同一次挑战；证书被拒。",
            "theorem_e_condition": "C2 缺失",
            "verdict": "REJECT（正确）",
        })

    # ---- (c) 推理半不绑用户提交的 x_U（弱形式） ----
    with tempfile.TemporaryDirectory() as td:
        fx = Fixture(Path(td), BENIGN, NONCE)
        # 用户实际提交的是「有害」输入；对手拿一条「无害」响应出证并送达。
        user_x = I.input_from_response(HARMFUL)
        v = fx.verify()
        checks = _input_checks(fx.inf_part.outcome, NONCE, BENIGN, user_x)
        cells.append({
            "id": "c",
            "title": "推理半只绑 derive(T_U)，用户提交的 x_U ≠ derive(T_U)",
            "conditions": {
                "same_nonce": True, "same_T": True,
                "x_bound_to_user_input": False, "delegated_empty": True,
            },
            "setup": {
                "composite_nonce_hex": NONCE.hex(),
                "policy_nonce_hex": NONCE.hex(),
                "inference_nonce_hex": NONCE.hex(),
                "delivered_response": BENIGN,
                "user_input_x_U": user_x,
                "user_input_derived_from": "HARMFUL",
                "delegated": [],
            },
            "verify": v,
            "input_checks": checks,
            "expected": ("当前实现 ok=True, satisfied=True —— 它与 (a) 在验证器眼里"
                         "完全相同；弱形式成立，强形式不成立"),
            "conclusion": ("缺 C4 的**强形式**：(c) 只证明了存在 x=derive(T_U) 使"
                           "推理成立，没有证明 x=x_U。这是弱形式，不是定理 E 的结论。"),
            "theorem_e_condition": "C4 仅以弱形式成立（x = derive(T_U)，非 x_U）",
            "verdict": "ACCEPT-AS-WEAK（当前实现的缺口）",
        })

    # ---- (d) 策略半 delegated 非空 ----
    with tempfile.TemporaryDirectory() as td:
        fx = Fixture(Path(td), BENIGN, NONCE, delegated=DELEGATED)
        user_x = I.input_from_response(BENIGN)
        v = fx.verify()
        checks = _input_checks(fx.inf_part.outcome, NONCE, BENIGN, user_x)
        cells.append({
            "id": "d",
            "title": "策略半 delegated 非空（有规则未被这份证明判定）",
            "conditions": {
                "same_nonce": True, "same_T": True,
                "x_bound_to_user_input": True, "delegated_empty": False,
            },
            "setup": {
                "composite_nonce_hex": NONCE.hex(),
                "policy_nonce_hex": NONCE.hex(),
                "inference_nonce_hex": NONCE.hex(),
                "delivered_response": BENIGN,
                "user_input_x_U": user_x,
                "delegated": DELEGATED,
            },
            "verify": v,
            "input_checks": checks,
            "expected": "ok=True, satisfied=False（组合层 fail closed，要求陪伴证明）",
            "conclusion": ("缺 C5：证书**为真**，但组合义务**未成立**；"
                           "必须另行合取 ezkl 陪伴证明，且其公开实例要含 encode(T_U)。"),
            "theorem_e_condition": "C5 缺失（陪伴证明未合取）",
            "verdict": "TRUE-BUT-UNSATISFIED（正确 fail closed）",
        })

    return cells


def render_md(payload: Dict[str, Any]) -> str:
    md = [
        "# 组合负对照：定理 E 的必要条件（P1-09）",
        "",
        "四格实验，复用 `policydsl/proofs/compose.py::verify_composite` 的绑定层"
        "（`verify_proofs=False`；证明的密码学有效性由 `tests/test_compose.py` 与"
        "[`compose.md`](compose.md) 覆盖）。",
        "",
        "## 结论先行",
        "",
        "* **只有 (a) 是真正成立的组合**：同一 `n`、同一 `T`、`x_U = derive(T_U)`、"
        "`delegated` 为空，五条全满足。",
        "* **(c) 是弱形式**：当前实现只证 `∃x: x = derive(T_U) ∧ 推理输出 = M(x)`，"
        "**没有**证 `x = x_U`；验证器甚至没有接收 `x_U` 的参数。强形式尚未落地"
        "（证明债 E-1）。",
        "* (b) 被第 6 步四方比对拒绝；(d) 证书为真但 `satisfied=False`（fail closed）。",
        "",
        "## 四格表",
        "",
        "| 格 | 构造 | 条件 | verify ok | satisfied | 弱形式 | 强形式 | 结论 |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ]
    for c in payload["cells"]:
        cond = c["conditions"]
        cond_s = (f"同n={cond['same_nonce']}, 同T={cond['same_T']}, "
                  f"绑x_U={cond['x_bound_to_user_input']}, "
                  f"delegated空={cond['delegated_empty']}")
        md.append(
            f"| ({c['id']}) | {c['title']} | {cond_s} | "
            f"{c['verify']['ok']} | {c['verify']['satisfied']} | "
            f"{c['input_checks']['weak_form']} | "
            f"{c['input_checks']['strong_form']} | {c['verdict']} |")

    md += [
        "",
        "## 与定理 E 的对应",
        "",
        "| 条件 | 定理 E 的要求 | 对应格 | 实验现象 |",
        "|---|---|---|---|",
        "| C2 | 两半绑到同一个新鲜 `n` | (b) | `response_binding` 四方比对失败，证书被拒 |",
        "| C4 | 推理半绑到**用户提交的** `x_U` | (a) / (c) | (a) 以 `x_U=derive(T_U)` 满足；"
        "(c) 只有弱形式，强形式未落地 |",
        "| C5 | `delegated` 为空或陪伴证明被合取 | (d) | `ok=True` 但 `satisfied=False` |",
        "",
        "## (c) 的精确陈述",
        "",
        "`verify_composite` 第 7 步（`policydsl/proofs/compose.py`）：",
        "",
        "```python",
        "want_input = infer.input_binding(composite.nonce, infer.input_from_response(response))",
        "```",
        "",
        "因此当前实现证明的是",
        "",
        "```",
        "∃ x : x = derive(T_U) ∧ T_U = M(x)        （弱形式）",
        "```",
        "",
        "而不是定理 E 的",
        "",
        "```",
        "∃ x : x = x_U ∧ T_U = M(x)               （强形式，尚未落地）",
        "```",
        "",
    ]
    c_cell = next(c for c in payload["cells"] if c["id"] == "c")
    c_checks = c_cell["input_checks"]
    md += [
        f"(c) 格把用户提交的 `x_U` 设为 `{c_cell['setup']['user_input_derived_from']}` "
        "导出的输入，而送达的是无害响应；验证器仍然 `ok=True, satisfied=True`，"
        "因为它从不读取 `x_U`。若把强形式代入检查：",
        "",
        "| 量 | 值 |",
        "|---|---|",
        f"| 推理半的 `input_binding` | `{short_hash(c_checks['inference_input_binding'])}` |",
        f"| 由用户 `x_U` 重算的 `IB(n, x_U)` | `{short_hash(c_checks['user_input_binding'])}` |",
        f"| `x_U == derive(T_U)` | `{c_checks['user_input_equals_derived']}` |",
        "",
    ]
    md += [
        "## 边界",
        "",
        "* 四格是**绑定层**负对照；它们不重新证明两份子证明的密码学有效性。"
        "该层由 `tests/test_compose.py` 的 `POP_TEST_COMPOSE=1` 端到端用例与 "
        "[`compose.md`](compose.md) 的真实出证结果覆盖。",
        "* (c) 的缺口是**实现-论文契约**的差距，不是测试问题：在强形式闭合之前，"
        "论文只能写弱形式并标注（[`theorem-c-e-f.md`](../../docs/proofs/theorem-c-e-f.md) §2.7、"
        "证明债 E-1）。",
        "",
        "## 复现",
        "",
        "```bash",
        "python3 bench/bench_compose_controls.py --out-dir bench/results",
        "```",
        "",
    ]
    return "\n".join(md) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="P1-09 组合负对照")
    ap.add_argument("--out-dir", type=Path, default=REPO / "bench" / "results")
    args = ap.parse_args()

    cells = build_cells()
    payload = {
        "task": "P1-09 composition negative controls",
        "generated_by": "bench/bench_compose_controls.py",
        "machine": {
            "platform": platform.platform(),
            "cpu_count": __import__("os").cpu_count(),
            "python": platform.python_version(),
        },
        "mode": "binding layer (verify_proofs=False)",
        "theorem_e_source": "docs/certificate-binding-framework.md §8; docs/proofs/theorem-c-e-f.md §2",
        "cells": cells,
        "summary": {
            "genuine_compositions": ["a"],
            "rejected": ["b"],
            "accepted_weak_form_only": ["c"],
            "true_but_unsatisfied": ["d"],
            "only_a_holds": True,
            "c_is_weak_form": True,
            "strong_form_x_U_landed": False,
            "proof_debt": "E-1（`input_binding` 绑 `derive(T_U)` 而非 `x_U`）",
        },
    }

    args.out_dir.mkdir(parents=True, exist_ok=True)
    out_json = args.out_dir / "composition_controls.json"
    out_md = args.out_dir / "composition_controls.md"
    out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    out_md.write_text(render_md(payload), encoding="utf-8")

    print("四格组合负对照：")
    for c in cells:
        print(f"  ({c['id']}) ok={c['verify']['ok']} satisfied={c['verify']['satisfied']} "
              f"weak={c['input_checks']['weak_form']} "
              f"strong={c['input_checks']['strong_form']}  {c['verdict']}")
    print(f"wrote {out_json} and {out_md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
