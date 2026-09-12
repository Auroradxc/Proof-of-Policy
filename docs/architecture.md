# 架构文档

> 本文只讲**分层与契约**（一页纸）。按板块深入代码请读 [`modules/`](modules/README.md)：
> 01 策略 DSL 与编译 · 02 隐私与承诺 · 03 合规证书 · 04 锚定与审计 ·
> 05 ZK 电路层 · 06 框架集成 · 07 CLI 与脚本 · 08 测试与评测。

## 双层架构

- **Python 层（链下）**：策略作者写 JSON 策略包 → `policydsl.compile()` 产出 **ConstraintSpec**（唯一的链上/链下契约）；`policydsl.evaluate()` 提供**参考判定**（golden），供单测与交叉验证使用。
- **Rust + SP1 层（证明）**：`circuits/program` 在 zkVM 内消费 ProofRequest（`response + ConstraintSpec`），重放约束判定并 `commit(passed, evidence)`；`circuits/script` 负责证明生成与验证（宿主机，可选链上）。

## ConstraintSpec 契约（v1）

```jsonc
{
  "spec_version": "v1",
  "policy_id": "eu-ai-act-v1",
  "policy_version": "0.1.0",
  "semantic": "and",
  "constraints": [
    {"kind": "keyword_block", "name": "...", "keywords": ["exploit", "weaponize", ...]},
    {"kind": "length_bound",  "name": "...", "min": 1, "max": 2000},
    {"kind": "pattern_block", "name": "...", "patterns": ["..."], "nfa": {"status": "compiled_in_circuit_wo3"}},
    ...
  ],
  "sha256": "<64 hex>"
}
```

- `sha256` = canonical hash of `{spec_version, policy_id, policy_version, semantic, constraints}`（排序键、紧凑分隔符）。用于策略溯源绑定（合规证书中的 `circuit_hash`/`policy_hash`）。
- 约束语义：`semantic="and"`，全部约束通过即合规。违规定位到具体约束（`violations[].kind`）。

## 数据流（完整）

```
策略作者                链下作者/编译                证明方(SP1)              验证方
policy_packs/a.json ──► policydsl.compile ──► ConstraintSpec ──► ProofRequest
                                                                    │
response.txt ──────────────────────────────────────────────────────┤
nonce ─────────── challenge.new_nonce() ────────────────────────────┘
                                                                    │
                                      circuits/program 内重放约束判定 commit(passed, policy_hash, response_binding, trace_root)
                                                                    │
                                     host/链上 verify(passed, proof) ◄── 合规证书
                                                                    │
                          验证方：用送达的 T′ 与 nonce 重算 response_binding 并比对
                                  用网关侧回执重算链尾 trace_root 并比对（P1-5）
```

工具轨迹（P1-5）另有一路：**工具网关**在每次调用执行后签发回执并接链，agent 只能原样转发；
`tool_arg_guard` / `budget_bound(calls)` 判的是这条链，链尾摘要 `trace_root` 进公开值。

语义规则（P2-9）还有第三路：策略含 `semantic_bound` 时，出证方额外产出一条
**ezkl 陪伴证明**（`scripts/ezkl_prove.py`），它证明「该策略指定的模型在这条响应上给出的分数满足阈值」。
两份证明**必须一起验**：SP1 那份的 `delegated[]` 说明「哪几条没被判」，ezkl 那份补上判定结果，
二者由 `{vk 指纹, onnx 哈希, 阈值, 方向}` 逐字段绑定，且 ezkl 的公开实例输入 `encode(T)` 由验证方
拿送达的 `T′` 现场重算比对。

组合证明（P1-6）是第四路，方向与前几路都不同 —— 它把**另一个证明系统/程序**的结论与策略合规
**合取**：

```
Compose = (推理完整性 ∧ 策略合规)
  推理半：circuits/infer-program（pop-infer）—— 代理模型前向，vkey_infer
  策略半：circuits/program      （pop-program）—— 全部策略判定，vkey_policy
  两半共用同一个 (nonce, T) ⇒ response_binding 相同 ⇒ 验证方现场重算即知「说的是同一条 T」
  policydsl/compose.py 合成 CompositeCertificate 并跑 8 步验证（含**键分离**）
```

**键分离**是组合成立的前提：两半必须来自**不同程序**（不同 vkey），否则「这份证明属于哪一半」
无从判断。做法是两个 guest 入口各断言一次自己的域（`pop-types::job_domain`），
把这条要求钉进电路。⚠️ 推理半在当前仓库里是**代理**（确定性定点 MLP），
不是 zkAgent（D1）—— 组合的是**机制**，不是真实 LLM 的推理。见
[`security-model.md`](security-model.md) 引理 L6 与 `bench/results/compose.md`。

## 安全模型

- **合规健全性**：不满足 π 的响应无法产出被接受的证明（证明者不能伪造通过）——**七类可判定规则均已入电路**（P2-9b 起含 `normalized_keyword_block`）。
  ⚠️ `semantic_bound`（P2-9）**不在电路内判定**：它被**委托**给 ezkl/halo2 陪伴证明，
  电路只把「这条被委托了」登记进公开值 `delegated`。因此 `passed=true` 而 `delegated` 非空的证明
  **不等于**策略被满足 —— 验证方必须额外合取陪伴证明，否则必须拒绝（fail closed），见下。
- **策略绑定（P0-1）**：公开值**必然携带** `policy_hash`，且它与参与判定的约束来自**同一段规范字节**，
  所以「用策略 π′ 判定却声称 π 的哈希」不可能。
- **响应绑定（P0-2）**：验证者出一次性 `nonce`，电路把 `response_binding = SHA256("pop-bind-v1"‖len‖nonce‖T)`
  写进公开值。持送达的 `T′` 与 `nonce` 的**任何一方**都能离线核对 —— 换掉 T 就核不上。
- **承诺隐私**（私有模式）：验证者看不到响应全文，只看到承诺与违规定位（+ 可证明的脱敏）。
  ⚠️ 上界（P0-4 查证，[`sp1-zk-audit.md`](sp1-zk-audit.md)）：公开值里的 `response_binding` 是
  **公开可重算**的 `T` 的函数，对低熵 `T` 可离线枚举 —— 该性质是「不暴露明文」，**不是**「`T` 不可恢复」。
- **轨迹绑定（P1-5）**：`tool_arg_guard` / `budget_bound` 判的是**工具网关**签发的**回执链**
  （不再是 agent 自填的 `tool_calls`）。链**结构**由电路保证（删/换/重排 → `trace_unbound` fail-closed，
  见 `pop-types::verify_receipt_chain`），链尾摘要 `trace_root` 进公开值；**签发者身份**由**链下**
  Ed25519 验签承担（zkVM 内不验签）。因此信任前提是「网关密钥不被滥用」——网关是被显式信任的第三方。
  详见 [`security-model.md`](security-model.md) §5 与 `docs/modules/05-zk-circuits.md` §2.3a/§2.5b。
- **语义规则的委托（P2-9）**：`semantic_bound`（学习型/语义规则）由外部证明系统承担：
  电路公开值里登记 `delegated[]`，出证方附一条 **ezkl 陪伴证明**，验证方核到
  `{system, model_vkey, onnx_sha256, threshold_bp, direction}` **逐字段相等**、证明文件字节哈希
  等于证书承诺的 `proof_sha256`、且公开实例的输入部分 == **由送达的 `T′` 现场重算的 `encode(T′)`**
  （信任边界 ③，防「拿别人的证明顶包」）。**三个信任边界**：模型权重被承诺（onnx sha256 + vk 指纹）、
  特征由图内确定性导出、输入绑到响应。⚠️ `encode` 在词表上单射 ⇒ 公开实例可反查原文，
  故语义规则**只支持公开模式**（私有模式 `evaluate_private` 直接 panic，fail closed）。
  详见 [`design-semantic-rules.md`](design-semantic-rules.md) 与 [`security-model.md`](security-model.md) 引理 L7。
- **组合义务（P1-6）**：`Compose = (推理完整性 ∧ 策略合规)`，由两份**来自不同程序**
  （不同 vkey）的证明合成，验证方跑 `compose.verify_composite` 的 8 步 ——
  证明文件哈希、密码学有效性、**键分离**、域绑定、四方 `response_binding`（含现场重算）、
  `model_hash`/`input_binding` 现场重算、合规结论。⚠️ 组合层在策略半 `delegated` 非空时
  **不下合规结论**（那条要合取 ezkl 陪伴证明，见下）；⚠️ 推理半是**代理**，
  不是真实 LLM 的推理证明（D1）。详见 [`security-model.md`](security-model.md) 引理 L6。
- **不可伪造**：无原响应的攻击者不能伪造「通过」证明；证据开示需 `SHA256(片段)=承诺`。
- **记录完整性**：哈希链账本 + 链上锚定（`cert_digest` 登记进 `contracts/Anchor.sol`）。

完整定义、归约论证与对应实验见 [`security-model.md`](security-model.md)；
实现层面的落点见 [`modules/03-certificate.md`](modules/03-certificate.md) 与
[`modules/04-anchoring-audit.md`](modules/04-anchoring-audit.md)。

## 与既有项目的关系

独立方向；SP1 仅作为通用证明基础设施使用，与既有私有面部认证项目无代码/数据依赖。
