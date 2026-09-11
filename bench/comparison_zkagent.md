# 基准对标：PoP vs zkAgent（eprint 2026/199）

> 结论先行：**两者证明的是不同义务、可组合**。zkAgent 证「provider 确实执行了声明的模型与工具」（推理 + 工具轨迹完整性）；
> PoP 证「响应/轨迹满足公开策略 π」（合规性）。它们**正交**：PoP 不证模型计算，zkAgent 不证策略合规。
> 组合（我们计划中的 M1）= 全栈可验证 agent：`zkAgent 证明` ⊕ `PoP 合规证明`，成本近似相加，且**由推理证明主导**。

## 1. zkAgent 报告数据（SJTU；C++；GPT-2）

**硬件**：Intel Xeon 6982P-C 3.20GHz，**32 核**，**512 GB RAM**（32 线程并行；无 GPU。zkLLM 对照为 A100）。

| 配置 | 证明时间 | 验证时间 | 证明大小 | 备注 |
|---|---|---|---|---|
| zkAgent (Shout)，T=512（30 提示 + 482 生成） | **194.40 s**（**0.40 s/生成 token**） | **0.42 s** | **≈96 MiB**（98,374.2 KB） | one-shot transcript 证明 |
| zkAgent (LogUp)，同上 | ~1069 s（Shout 的 5.5×） | **0.038 s** | **3.1 MiB** | prover/verifier 权衡 |
| zkGPT（逐步基线） | 149,192.60 s | 4,361.09 s | ~933 MB | 被 zkAgent 降 767× / 10,384× |
| zkLLM（A100，30-token 上下文/步） | 15.8 s/步 | 0.54 s | 126 KB | GPU；A100≈25× 峰值算力 |
| 真实轨迹：weather agent（154 token） | 100.53 s | 0.31 s | — | zkTLS 工具 |
| 真实轨迹：coding assistant（146 token） | 99.74 s | 0.28 s | — | zkVM 沙箱工具 |

zkEmbed 预处理 759.91 s / 4.52 GB 辅助存储（→0.40 s/1024 查询）；zkPosEnc 相对朴素矩阵化提速 11.5×–31.3×；zkDecode 0.035 s/token（greedy）。

## 2. PoP 实测数据（本仓库；SP1 zkVM；CPU 单机）

**硬件**：WSL2，**24 核**，**12 GB RAM**（对比 zkAgent 的 32 核/512 GB——**低配得多**）。

| 配置 | 证明时间 | 验证时间 | 证明大小 | 峰值内存 |
|---|---|---|---|---|
| 200 字符 × 3 规则 | 127.4 s | **纯验证 ~90 ms**（vkey setup 1.5 s；CLI 冷启动 ~20 s，含证明器构造） | **2.72 MiB** | 10.76 GiB |
| 200 字符 × 6 规则 | 140.5 s | 同上 | 2.72 MiB | 10.86 GiB |
| 1000 字符 × 1 规则 | 98.5 s | 同上 | 2.71 MiB | 9.83 GiB |

zkVM 执行周期数：20k 字符 × 3 规则 ≈ **8.35×10⁷**；× 6 规则 ≈ **1.12×10⁸**（≈ 4.2k 周期/字符的字符串规则）。

## 3. 对照表（同口径字段）

| 维度 | **zkAgent (Shout)** | **zkAgent (LogUp)** | **PoP (本文)** |
|---|---|---|---|
| 证明的义务 | provider 执行了声明的模型+工具（**推理完整性**） | 同左 | 响应/轨迹满足策略 π（**合规性**） |
| 证明规模/上下文 | GPT-2，T=512 | 同左 | 200–1000 字符 × 1–6 规则 |
| 证明时间 | 194.40 s | ~1069 s | **98–141 s**（固定开销主导） |
| 验证时间 | 0.42 s | **0.038 s** | **~0.090 s**（纯验证；vkey setup 1.5 s 一次性） |
| 证明大小 | ~96 MiB | **3.1 MiB** | **~2.7 MiB** |
| 硬件 | 32 核 / 512 GB | 同左 | **24 核 / 12 GB** |
| 内容隐私 | ❌（证明推理与工具轨迹） | ❌ | ⚠️ 双模式（承诺/选择性披露/带证明脱敏）——**上界见 §4.4** |
| 是否需要模型 | ✅ 需 GPT-2 权重与算术化 | ✅ | ❌（与模型无关，仅判策略） |
| 可组合性 | 推理层（zkAgent） | 同左 | **策略层（PoP）**，二者组合 = 全栈可验证 agent |

## 4. 解读与可比性声明（避免误导）

1. **非同义务对比**：zkAgent 证的是**大模型推理 + 工具完整性**（昂贵，依赖模型与量化/查表算术化）；PoP 证的是**策略合规**
   （无模型参与，成本随「响应长度 × 规则数」增长）。因此**不能**宣称“PoP 比 zkAgent 快”——正确表述是：
   *对“合规”这一义务，PoP 以与 zkAgent 同量级的证明时间/更小的内存规模完成，且额外提供承诺式隐私（见 §4.4）*。
2. **证明大小**：PoP（~2.7 MiB）与 zkAgent(LogUp)（3.1 MiB）同量级；显著小于 zkAgent(Shout)（~96 MiB，换取更快证明）。
3. **验证时间**：zkAgent 0.038 s–0.42 s；PoP **纯验证 ~90 ms**（与 LogUp 同量级、优于 Shout），
   vkey setup 1.5 s 为一次性；我们 CLI 的 `--verify` 冷启动 ~20 s 来自构造 SP1 证明器（~10 GB），
   属实现细节——**verifier-only 二进制**（不构造证明器）是明确的后续优化。
4. **硬件不对等**：PoP 在 12 GB 消费级 WSL 上完成，zkAgent 用 32 核/512 GB 服务器；PoP 的内存瓶颈来自 zkVM 证明器固定开销（~10 GB），已记录为复现前提。
5. **互补而非竞争**：把 PoP 的合规证明与 zkAgent 的 one-shot transcript 证明组合，可得到「既证明推理执行、又证明策略合规」的全栈凭证；
   总成本 ≈ 推理证明 + 合规证明，且由前者主导。这正是我们计划中的 M1（PoP × zkAgent 联合证明）。

### 4.4 「内容隐私」的准确口径（P0-4 查证后收紧）

上表 PoP 列的「内容隐私」应当读作「**不对外公开明文**」，不应读作「响应内容不可恢复」。
两条独立的理由（全文见 [`../docs/sp1-zk-audit.md`](../docs/sp1-zk-audit.md)）：

1. **证明系统层面**：本项目默认出证模式是 SP1 的 `core`，而 SP1 官方安全模型明文写着
   "individual STARK proofs in SP1 do not currently satisfy the zero-knowledge property"；
   源码侧独立印证 —— 整个 SLOP 证明栈对 blinding/hiding/randomizer **命中 0**，
   `ShardProof` 把轨迹 Merkle 根与轨迹开值明文放进证明。
   （`groth16`/`plonk` 把内部 STARK 证明作为私有见证，是唯一可能隐藏见证的模式，但需 ≥16 GB 内存，本机未实测。）
2. **设计层面（更根本，与 SP1 无关）**：即使换成真正 ZK 的证明，PoP 公开值里的
   `response_binding` / `response_commitment` 都是**公开且可离线重算**的 `T` 的函数。
   `response_binding` 之所以必须公开可重算，正是为了让验证者能独立核对「送达的 `T′` 就是被证明的 `T`」；
   而这恰恰构成一个**猜测-验证 oracle**：自然语言响应的熵远低于 SHA-256 的 256 bit，枚举可行。
   即在「验证者独立重算绑定」的前提下，**响应绑定与响应内容隐藏对低熵 `T` 互斥**。

**这仍然是对 zkAgent 的真实差异点**：zkAgent 的证明对象含模型推理与工具轨迹，隐私性同样受
其证明系统与公开承诺的约束；而 PoP 不需要把输入交给任何第三方硬件（对比 TEE 的「❌ 需读输入输出」）。
但对比表两侧都不应被读成「内容不可恢复」。

## 5. 引用

- zkAgent: Lizheng Wang, Hancheng Lou, Chongrong Li, Yu Yu, Yuncong Hu. *zkAgent: Verifiable LLM Agent Execution via One-Shot Transcript Proofs.* IACR ePrint 2026/199. <https://eprint.iacr.org/2026/199.pdf>
- zkGPT / zkLLM：见 zkAgent 论文中的基线（[66]/[76]）。
