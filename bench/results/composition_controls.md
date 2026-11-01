# 组合负对照：定理 E 的必要条件（P1-09）

四格实验，复用 `policydsl/proofs/compose.py::verify_composite` 的绑定层（`verify_proofs=False`；证明的密码学有效性由 `tests/test_compose.py` 与[`compose.md`](compose.md) 覆盖）。

## 结论先行

* **只有 (a) 是真正成立的组合**：同一 `n`、同一 `T`、`x_U = derive(T_U)`、`delegated` 为空，五条全满足。
* **(c) 是弱形式**：当前实现只证 `∃x: x = derive(T_U) ∧ 推理输出 = M(x)`，**没有**证 `x = x_U`；验证器甚至没有接收 `x_U` 的参数。强形式尚未落地（证明债 E-1）。
* (b) 被第 6 步四方比对拒绝；(d) 证书为真但 `satisfied=False`（fail closed）。

## 四格表

| 格 | 构造 | 条件 | verify ok | satisfied | 弱形式 | 强形式 | 结论 |
|---|---|---|---:|---:|---:|---:|---|
| (a) | 同一 nonce + 推理半绑 x（x = x_U = derive(T_U)） | 同n=True, 同T=True, 绑x_U=True, delegated空=True | True | True | True | True | PASS（真组合） |
| (b) | 两半不同 nonce（n_p ≠ n_i） | 同n=False, 同T=True, 绑x_U=True, delegated空=True | False | False | True | True | REJECT（正确） |
| (c) | 推理半只绑 derive(T_U)，用户提交的 x_U ≠ derive(T_U) | 同n=True, 同T=True, 绑x_U=False, delegated空=True | True | True | True | False | ACCEPT-AS-WEAK（当前实现的缺口） |
| (d) | 策略半 delegated 非空（有规则未被这份证明判定） | 同n=True, 同T=True, 绑x_U=True, delegated空=False | True | False | True | True | TRUE-BUT-UNSATISFIED（正确 fail closed） |

## 与定理 E 的对应

| 条件 | 定理 E 的要求 | 对应格 | 实验现象 |
|---|---|---|---|
| C2 | 两半绑到同一个新鲜 `n` | (b) | `response_binding` 四方比对失败，证书被拒 |
| C4 | 推理半绑到**用户提交的** `x_U` | (a) / (c) | (a) 以 `x_U=derive(T_U)` 满足；(c) 只有弱形式，强形式未落地 |
| C5 | `delegated` 为空或陪伴证明被合取 | (d) | `ok=True` 但 `satisfied=False` |

## (c) 的精确陈述

`verify_composite` 第 7 步（`policydsl/proofs/compose.py`）：

```python
want_input = infer.input_binding(composite.nonce, infer.input_from_response(response))
```

因此当前实现证明的是

```
∃ x : x = derive(T_U) ∧ T_U = M(x)        （弱形式）
```

而不是定理 E 的

```
∃ x : x = x_U ∧ T_U = M(x)               （强形式，尚未落地）
```

(c) 格把用户提交的 `x_U` 设为 `HARMFUL` 导出的输入，而送达的是无害响应；验证器仍然 `ok=True, satisfied=True`，因为它从不读取 `x_U`。若把强形式代入检查：

| 量 | 值 |
|---|---|
| 推理半的 `input_binding` | `9e69cb26…` |
| 由用户 `x_U` 重算的 `IB(n, x_U)` | `639dd303…` |
| `x_U == derive(T_U)` | `False` |

## 边界

* 四格是**绑定层**负对照；它们不重新证明两份子证明的密码学有效性。该层由 `tests/test_compose.py` 的 `POP_TEST_COMPOSE=1` 端到端用例与 [`compose.md`](compose.md) 的真实出证结果覆盖。
* (c) 的缺口是**实现-论文契约**的差距，不是测试问题：在强形式闭合之前，论文只能写弱形式并标注（[`theorem-c-e-f.md`](../../docs/proofs/theorem-c-e-f.md) §2.7、证明债 E-1）。

## 复现

```bash
python3 bench/bench_compose_controls.py --out-dir bench/results
```

