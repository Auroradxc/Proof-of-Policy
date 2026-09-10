# Proof-of-Policy: Zero-Knowledge Compliance Certificates for LLM Agent Responses without Trusted Hardware

> 论文初稿（Phase 6 / W8）。目标投稿：CCS / USENIX Security / S&P / NDSS（系统安全），退而 PoPETs / 领域会议 / 中文学报。
> 仓库：`zk-policy`（开源，含复现指南 `docs/reproduce.md`）。

## Abstract

面向 LLM 智能体的合规声明当前无法被独立核验：TEE 方案只证明“护栏执行过”而非“输出满足策略”，且引入硬件信任与厂商依赖；
形式化方法需要人工形式化政策且难覆盖模糊规则；现有 ZK 积木（zk-regex、PII 脱敏证明）只是单条原语，未构成策略级系统。
我们提出 **Proof-of-Policy（PoP）**：证明「响应 `T` 满足公开策略 `π`」，**无 TEE、无硬件信任**，并支持**双隐私模式**——
透明模式公开响应，私有模式只公开响应承诺、违规定位与证据承诺，并可证明**带脱敏的选择性披露**。
PoP 以**通用策略 DSL**（黑名单/长度/格式/正则-PII/工具参数/预算，AND 组合）编译为可序列化 **ConstraintSpec**，
在 **SP1 zkVM** 内确定性判定并提交结果；证书以 DSSE 信封绑定策略哈希、电路 vkey 与证明，并锚定到防篡改账本。
我们在单机 CPU 上实测：20k 字符 × 6 条规则的判定约 `1.1×10^8` 周期，真实 STARK/Groth16 证明 ~**1–2 分钟**、
工件 ~**2.7 MiB**（峰值内存 ~10 GB）；并提出首个针对「策略合规」的 NFA 匹配消融，显示 Pike VM 相对朴素逐起点重跑在
对抗输入上避免二次退化（99×）。PoP 与 LangChain/LangGraph/MCP 集成，可对生成路径与工具调用（参数与响应侧）逐次出证。
与同期 **zkAgent**（证「provider 执行了声明的模型与工具轨迹」，ePrint 2026/199）**正交且可组合**：zkAgent 证明推理完整性、
PoP 证明策略合规，二者组合得到全栈可验证 agent；对标显示 PoP 在**低一个数量级的硬件**（24 核/12 GB vs 32 核/512 GB）上
达到同量级证明时间，证明大小 2.7 MiB 与 zkAgent(LogUp) 的 3.1 MiB 相当、远小于 zkAgent(Shout) 的 ~96 MiB，并额外提供内容隐私。

## 1. Introduction

LLM 智能体正在执行越来越敏感的动作（客服答复、工具调用、金融/医疗内容）。监管（如 EU AI Act Art.12/13）与
企业治理要求「合规可审计」，但现实中合规性只能**听信**运营方：日志可伪造、护栏声明不可验证、内容隐私又要求不留明文。

现有四派各占一角但互不贯通：
- **TEE 执行证明**（Proof-of-Guardrail [arXiv 2603.05786]）证明护栏代码确被执行、输入输出被签名——**执行 ≠ 合规**（作者自述），且约 34% 延迟、依赖硬件；
- **TEE 治理栈**（Agentrust/cMCP/cA2A）同样依赖 TEE 与厂商设施；
- **形式化验证**（Lean-Agent 等）需人工形式化整个政策，且对黑盒响应不适用；
- **ZK 正则/PII 原语**（zk-regex V2、VDR/IACR 2024/813、ZK Email）是**积木**，无「策略级」系统。

最接近的 WITNESS（Midnight）仅支持 2 类策略且闭源、无内容隐私；`@brivora/verify` 非 ZK；DeepProve 证的是**模型计算**层
而非**策略合规**层。**「通用策略 DSL → ZK 约束编译 + 无 TEE + 响应隐私选择性披露 + 形式化安全模型 + 开源」的组合是明确空位。**

本文贡献：
1. **PoP 系统**：首个通用策略 DSL → ZK 判定 → 双隐私模式 → 合规证书的开源实现（§5）；
2. **可序列化 NFA 契约**：正则子集编译为跨层（Python 参考 ↔ zkVM）一致的 NFA，含 fail-fast 语法子集与 Pike VM 判定（§5.2）；
3. **形式化安全模型**：健全性/内容隐私/不可伪造/绑定/记录完整性，并给出对应可复现实验（§6）；
4. **评测**：zkVM 周期数矩阵（长度×规则数）、**NFA 消融**（pike vs naive，含对抗二次退化证据）、真实证明时间/大小，
   以及信任-成本四象限对比（§8）。

## 2. Background & Related Work

（见 §1 四派；补充）ZK 在 agent 侧的相邻工作：zkML（证明推理）、可验证 DP（Noisette）、zkAgent（整轨迹证明）。
PoP 与它们**正交且可组合**：PoP 证的是「输出/轨迹满足**策略**」，不证模型计算。zk-regex 的“离线匹配 + 电路内验证路径”
启发了我们的 NFA 契约；VDR 的位选择器启发了 `mask_covered` 的脱敏证明。

### 2.1 与 zkAgent 的关系（最贴近的同期工作）

**zkAgent**（SJTU，ePrint 2026/199）是首个证明**完整推理管线**的 SNARK 系统：把 GPT-2 的一次推理 + 长程自回归生成 +
外部工具调用（zkTLS/zkVM 证工具真实性）打包成 **one-shot transcript 证明**，用于消除「provider 替换模型/伪造工具观测」的
端到端完整性缺口。其报告（32 核 / 512 GB CPU 服务器）：T=512 时 Shout 后端 **194.40 s** / 验证 **0.42 s** / 证明 **≈96 MiB**；
LogUp 后端 **3.1 MiB** / 验证 **38 ms**（证明慢 5.5×）；逐步基线 zkGPT 需 149,192.6 s / ~933 MB。

**差异与互补**：

| | zkAgent | **PoP（本文）** |
|---|---|---|
| 证明的义务 | provider 执行了声明的**模型+工具**（推理完整性） | 响应/轨迹**满足策略 π**（合规性） |
| 是否依赖模型 | 是（需权重与算术化/查表） | **否**（与模型无关，仅判策略） |
| 成本增长 | 随模型/序列长度 | 随「响应长度 × 规则数」 |
| 内容隐私 | 否（证推理与工具轨迹） | **是**（双模式 + 可证明脱敏） |
| 组合 | 推理层证明 | **策略层证明**；`zkAgent ⊕ PoP` = 全栈可验证 agent |

因此我们**不主张**“更快”，而是主张：*对“合规”这一义务，PoP 在不涉模型的前提下以同量级时间、更小内存、可比的证明大小完成，
并补上 zkAgent 未覆盖的策略合规与内容隐私；二者组合覆盖“推理执行 + 策略合规”的完整义务*（对应我们计划中的 M1）。
详细对标数据见仓库 `bench/comparison_zkagent.md`。

## 3. Threat Model & Goals

**参与方**：证明者=agent 运营方（不可信）；验证者=监管/审计/第三方；策略作者（发布 `π`）。
**目标**：(G1) 健全性——违反 `π` 的 `T` 无法产出被接受的证明；(G2) 内容隐私——私有模式下公共值不泄露 `T`；
(G3) 可溯源绑定——策略版本、电路与证明工件绑定；(G4) 选择性披露——可证明的带脱敏与证据开示；(G5) 记录完整性——审计日志防篡改。
**非目标**：不证明模型推理本身；不覆盖训练数据/模型卡。

## 4. System

### 4.1 架构（双层 + 契约）

```
策略包 JSON ──compile──▶ ConstraintSpec(JSON, sha256) ──serialize──▶ ProofRequest
响应/轨迹 ───────────────────────────────────────────────────────────┘
        └──▶ SP1 zkVM: run_job → evaluate(确定性) → commit(Outcome)
                     └── host verify → 证书(DSSE) → 锚定账本 → 第三方验证
```
`ConstraintSpec` 是**唯一跨层契约**（含编译后的 NFA），Python 参考层与 Rust/zkVM 层消费同一份，保证一致性。

### 4.2 策略 DSL 与 NFA 契约

规则子集：`keyword_block` / `length_bound` / `pattern_block`（入电路）；`format_check` / `tool_arg_guard` / `budget_bound`（链下参考）。
正则编译为 **Thompson NFA**（可序列化：states/eps/edges/ranges），受支持子集 + ASCII 语义，**不支持即 fail-fast**
（锚点/反向引用/环视）。判定用 **Pike VM** 单趟状态并集（unanchored 存在性，对齐 `re.search`）。

### 4.3 双隐私模式

- **透明模式**：公开响应 + 判定（`passed`、违规 `rule/kind/evidence`）。
- **私有模式**：只公开 `response_commitment = SHA256(T)`、每条违规的 `rule/kind/evidence_commitment`，以及
  **脱敏证明**：`redaction_ok`（`R` 与 `T` 仅掩码位不同）+ **`mask_covered`**（掩码位落在**电路内验证为真实完整匹配**的见证 span 内）。
  证据开示为链下核验（`SHA256(fragment)=commitment`）。

### 4.4 合规证书与锚定

证书 payload：`{cert_version, policy{id,version}, policy_hash, mode, outcome, binding{vkey_hash, proof_sha256}, ai_act, ts}`，
以 **DSSE 信封**签名（当前为 HMAC demo signer，可替换 Ed25519），`cert_digest` 写入**哈希链锚定账本**；
流式证书额外构成**流式链**（`streaming.chain={index,prev}`）并支持**早停**。

### 4.5 框架集成

`AgentMonitor`（框架无关钩子）产证书；**LangChain 回调**（`on_llm_end`/`on_tool_start`/`on_tool_end`/`on_llm_new_token`）；
**LangGraph**（同一回调 + `guard_node` 包装 + `astream_events` 全事件）；**MCP**（`MCPGuard` 对工具**参数**与**响应**判定，
可预检拦截）。真实框架（langchain 1.4 / langgraph 1.2 / mcp 2.2）均通过端到端测试。

## 5. Security Model（摘要；详见仓库 `docs/security-model.md`）

- **Soundness**：**全部 6 类规则入电路**（keyword/length/pattern/format/tool-arg/budget）后，`pub` 等于 zkVM 确定性执行输出 `J(π,T)`；伪造需攻破 zkVM 或哈希。
- **Privacy**：验证者视图仅含承诺；Leak 实验验证无明文泄露。
- **Redaction soundness**：`redaction_ok ∧ mask_covered` ⇒ 只遮蔽真实命中内容。
- **Unforgeability/binding**：证据开示需 `SHA256(f)=e`；策略/电路/证明哈希绑定并在验证时**重算**。
- **Integrity**：账本与流式链的篡改/重排可检出。
- **边界**：链下规则（format/tool/budget、MCP 工具路径）证书标 `zk:false`，不主张 zk 健全性。

## 6. Implementation

Python 参考层（DSL/编译/NFA/私密/证书/锚定/框架适配）+ Rust（SP1 v6 workspace：`types` 共享判定、`program` guest、`script` 驱动）。
单测 + 集成测试 **102 全绿（1 skip 为设计内）**；`scripts/` 提供交叉验证、demo、证书签发/验证、截图；`docs/reproduce.md` 复现指南。

## 7. Evaluation

### 7.1 zkVM 周期数（长度 × 规则数；`pop-script --execute`）

| 长度 | 规则 | pike | naive | 比值 |
|---:|---:|---:|---:|---:|
| 200 | 3 | 879,595 | 1,623,555 | 1.85× |
| 2,000 | 3 | 8,392,873 | 15,855,095 | 1.89× |
| 20,000 | 3 | 83,514,326 | — | — |
| 20,000 | 6 | 111,684,879 | — | — |

基线（仅长度）近线性（20k 字 5.4e4 周期）；字符串规则 ≈ **~4.2k 周期/字符**。完整矩阵见 `bench/results/cycles.md`。

### 7.2 匹配器消融（对抗输入 `a`×n vs `a+b`）

| n | pike | naive | 比值 |
|---:|---:|---:|---:|
| 100 | 519,955 | 12,748,918 | 24.5× |
| 200 | 1,021,653 | 50,441,932 | 49.4× |
| 400 | 2,024,955 | 200,722,858 | 99.1× |

比值随 n 翻倍 ⇒ naive 可能被对抗输入拖入 **O(n²)**；pike 保持线性。这是首个针对策略合规匹配的消融证据。

### 7.3 真实证明：时间 / 验证 / 大小 / 内存（本机 CPU，24 核/12GB）

| 配置（响应字符 × 规则数） | 证明时间 | 纯验证 | 证明大小 | 峰值内存 |
|---|---:|---:|---:|---:|
| 200 × 3 | 127.4 s | **~90 ms** | **2.72 MiB** | 10.76 GiB |
| 200 × 6 | 140.5 s | ~90 ms | 2.72 MiB | 10.86 GiB |
| 1,000 × 1 | 98.5 s | ~90 ms | 2.71 MiB | 9.83 GiB |

- vkey setup 1.5 s（一次性）；CLI `--verify` 冷启动 ~20 s 来自构造 SP1 证明器（~10 GB），属实现细节。
- 证明时间由证明器**固定开销主导**（~100 s 量级），随长度/规则数的边际为 zkVM 周期（§7.1）；
- 峰值内存 ~10 GB 是「需 12 GB 内存」的复现前提来源。

### 7.4 对标 zkAgent（ePrint 2026/199）

zkAgent 证明「provider 执行了声明的模型与工具轨迹」（推理完整性），与 PoP 的「策略合规」**正交且可组合**：

| 维度 | zkAgent (Shout) | zkAgent (LogUp) | **PoP（本文）** |
|---|---:|---:|---:|
| 义务 | 推理+工具完整性 | 同左 | **策略合规** |
| 规模 | GPT-2, T=512 | 同左 | 200–1000 字符 × 1–6 规则 |
| 证明时间 | 194.40 s | ~1069 s | **98–141 s** |
| 验证时间 | 0.42 s | **0.038 s** | **~0.090 s** |
| 证明大小 | ~96 MiB | **3.1 MiB** | **~2.7 MiB** |
| 硬件 | 32 核 / 512 GB | 同左 | **24 核 / 12 GB** |
| 内容隐私 | ❌ | ❌ | ✅ 双模式 |
| 依赖模型 | ✅ | ✅ | ❌ |

**可比性声明**：二者证明义务不同，**不可宣称“PoP 更快”**。正确结论是：*对“合规”义务，PoP 在不涉模型的前提下，
以同量级证明时间、**低一个数量级的硬件**、与 LogUp 相当的证明/验证规模完成，并补上 zkAgent 未覆盖的**内容隐私**；
`zkAgent ⊕ PoP` 则覆盖“推理执行 + 策略合规”的完整义务（成本 ≈ 推理证明 + 合规证明，由前者主导）*。详见 `bench/comparison_zkagent.md`。

### 7.5 信任-成本四象限（实现 vs TEE/形式验证/hash-chain）

见 `docs/quadrant.md`：PoP 落在「密码学健全 + 证性质」象限，代价由「硬件延迟」变为「证明时间」，换取**无硬件信任 + 内容隐私**。

### 7.6 端到端与审计

`scripts/demo_e2e.py` 产生 12 张证书（流式链+早停、MCP 参数+响应、zk 证明）并锚定；
`scripts/verify_session.py` 第三方仅凭公开产物验证：`ledger_chain / signature / policy_hash / anchored / stream_chains / zk_proof` 全 PASS。

## 8. Limitations & Future Work

链下规则入电路（format/budget/tool）；生产签名（Ed25519/HSM）与链上锚定（RPC/合约）；语义级规则（嵌入/学习型护栏，ezkl）；
正则子集与 ASCII 语义扩展；证明开销优化（lookup/并行/预计算）；与 zkAgent 轨迹证明、可验证 DP 的组合。

## 9. Conclusion

PoP 首次把「智能体响应满足公开策略」做成**无硬件信任、可选择性披露、可审计锚定**的开源系统，并给出安全模型与
（含对抗消融的）系统评测；它是可插拔的“合规证明原语”，可嵌入推理证明、隐私机制、流式证明与监管流程。

## Appendix A. Reproduction

见 `docs/reproduce.md`：环境 → 一次合规证明 → 交叉验证 → 私有模式 → 证书 → 一键 demo → 第三方验证（关键命令与期望输出）。
