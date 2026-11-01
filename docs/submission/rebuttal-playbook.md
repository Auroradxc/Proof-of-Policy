# Rebuttal playbook（A8 + M6 更新）

> **日期**：2026-11-01　**基线**：`1c1fc60`（M6 更新；首轮基线 `4fe5c41`）
> **配套**：[`mock-reviews.md`](mock-reviews.md)、[`../certificate-binding-framework.md`](../certificate-binding-framework.md)、
> [`../plan-bhv.md`](../plan-bhv.md)、[`../../paper/tdsc-paper.tex`](../../paper/tdsc-paper.tex)
> **用途**：把最可能出现的反对意见，逐条变成“事实 + 证据位置 + 可补实验 + 不能让步的边界”。
> 所有数字必须能在 `bench/results/*` 或论文表格中找到；未完成项标
> `pending` / `blocker` / `open`，**不编造结果**。
> **M6 状态**：X1c（groth16 + EU AI Act + 矩阵）、X1d（6 规则边界 + 真实隐私面）、
> E1（`k` 与 N 截断）、E2（L2 链接性）、E3（DeepSeek e2e）、A11（语义 demote）已落地。
> 下面用 `【M6】` 标出可替换旧回复的新事实；**论文正文尚未同步**，所以 rebuttal 的
> 前提是“修订稿会把这些写进 §5/§7”，不能用仓库结果冒充已发表内容。

---

## 0. 先手：三句话定调

1. **本文的主张是“框架 + 测量 + 一个构造性实例”，不是“发明了一个新的猜测界”。**
   猜测熵界、ROM 隐藏、union bound、D-privacy 混合论证、Thompson/Pike 构造都是标准的；
   新意在把响应/请求/策略三面收进同一个 BHV 记账、给出策略侧实例、并用负对照和
   披露曲线把定理落地（[`certificate-binding-framework.md`](../certificate-binding-framework.md) §14）。
2. **本文明确不主张的事情和主张一样多**：不主张 `core` 是 ZK，不主张策略隐私已解决，
   不主张组合强形式已落地，不主张网关信任已消除，不主张 E3 的 DeepSeek 会话是
   “合规真值”，不主张 A11 的语义分类器可用。这些边界写在摘要的 “Scope of privacy”、
   §7.1、§7.3–§7.6 和 §7.7。
3. **Rebuttal 期能改变结论的两类东西已经落地**：`X1c/X1d`（witness-hiding 档 +
   隐私面 + 规模矩阵 + 真实 EU AI Act）和 `E1/E3`（真实模型 + 实测 `k` + 端到端）。
   **但**它们带来两个新的诚实边界：E2 的 L2 承诺可链接、A11 的语义模型 demote。
   回复时要把“已有数字”与“论文是否已写进正文”分开；不要用仓库结果替代论文表格。

**审稿人心理**：TDSC 的系统/安全审稿人最反感“标题写 ZK、正文说没测 ZK”；
理论审稿人最反感“把标准界包装成新定理”；隐私审稿人最反感“加盐 = 策略隐私已解决”。
本 playbook 的每一节都围绕这三条。

---

## 1. 十一类反对点优先级

| # | 反对点 | 危险度 | 类型 | 是否决策关键 | 主要证据 | 补实验 / 动作 | M6 状态 |
|---|---|---|---|---|---|---|---|
| R1 | 理论太浅、定理是标准界 | 高 | 文字 + 定位 | 否（但影响评分） | 论文 §1/§3；框架 §14；证明底稿 | 标准 vs 新意表；tightness 例；不承诺新定理 | 无新定理；**未变** |
| R2 | ZK 未交付 / 标题 | **极高** | 实验 + 标题 | **是** | 论文标题/摘要/§5.3/§7.2；`sp1-zk-audit.md` | `X1c`：groth16 + 隐私面；否则改 “Succinct” | **已交付但 wrapper-only** |
| R3 | 规模小、旗舰策略不可证 | **极高** | 实验 | **是** | 论文 §5.1–5.3；`scale-cloud.md`；`scale-6x*.md` | 调参矩阵 + 90 GiB 云机 + 旗舰包 | **已缓解**；3×10k/6×5k 仍 OOM |
| R4 | 策略隐私没落地 | **极高** | 实验 + 文字 | **是** | 论文 §3.4/§4.1/§4.2；`C1.md`；`policy_corpus_infer.md` | 隐私面 + 电路级 coarsening + 更大语料 | **语料已扩，L2 反例出现** |
| R5 | 网关信任 | 高 | 文字 + 可选实验 | 否 | 论文 §2/§5.6/§7.6；`gateway_sig.md`；`B1.md` | 电路内 Ed25519（blocked）或明确 residual trust | 未变 |
| R6 | E-1 只证弱形式 | 高 | 实现 | 是（组合贡献） | 论文 §5.5/§7.5；`composition_controls.md` | 实现 `x_U` 承诺 + 负对照 | **未闭合** |
| R7 | G-1/V1-2 实现 bug | 中 | 已修 + 文字 | 否 | 论文 §7.3/§7.7；`Core.md`；`fuzz.md` | 终版二进制重跑 fuzz；解析器契约表 | 已修；fuzz 终版待补 |
| R8 | 页数 / 超长费 | 中 | 编辑 | 否（但费钱） | `tdsc-writing-plan.md` §0.1；`plan-m2-m6.md` | 编译终稿、移附录、拍板付费或压缩 | 16 页口径；待复编 |
| R9 | 引文债 | 高 | 文字 | 否（但不修会被拒） | 论文 `\need` 与 bibliography；`tdsc-fixlist.md` | 逐条打开核实；删不可核实的断言 | 未变（9 个 `\need`） |
| R10 | 真实 LLM 缺失 | **极高** | 实验 | **是** | 论文 §5.10/§7.7；`k_entropy_*.md`；`agent_e2e_deepseek.md` | `E1/E3`：k 分布 + 真模型端到端 + XSTest P/R/F1 | **部分交付**；N 截断 + 策略质量仍缺 |
| R11 | **L2 证据承诺可链接** | **高（新增）** | 实验 + 文字 | 是（隐私贡献） | `policy_corpus_infer.md` §3/§7 | 加盐/桶级承诺 + 重跑 | **新发现，未修复** |

> **M6 后的优先级**：`X1c/X1d` 与 `E1/E3` 已把 R2/R3/R10 从“完全无结果”降为
> “有结果但有边界”。现在**最能改变结论**的是：**(a) 把新数字写进正文**（否则审稿人
> 仍按原稿评审）；**(b) E2 的 L2 修复**（这是新出现的隐私反对点）；**(c) 6 规则
> 边界与 gateway/E-1 的诚实收口**。不要再把“将补 X1b/X2”当作 rebuttal 主承诺——它们
> 已经补了，缺的是论文同步与两个新边界。

---

## 1.1 M6 证据台账（回复时直接引用）

| 主题 | 可引用事实 | 结果文件 | 不能越界的话 |
|---|---|---|---|
| groth16 矩阵 | 18 点 **16 ✓ / 2 OOM**；成功点 **279–344 s / 29.7–35.1 GB / verified** | [`scale-cloud.md`](../../bench/results/scale-cloud.md) | 不说“所有规模可证”；`10000×3` 两档 OOM |
| EU AI Act | 3 规则包：core **48.82 s / 12.38 GB / 2.79 MB**；groth16 **301.19 s / 30.07 GB / 1,874 B**；两档 `verify_cert` PASS | [`eu_ai_act_proof.md`](../../bench/results/eu_ai_act_proof.md) | 是 167 字符示例，不是 10k 压力点；不代表“EU AI Act 全面合规” |
| 6 规则边界 | 2000/3000/4000/4500 可行；**4500 = 181.66 s / 64.2 GB**；**5000 OOM**；6 规则 groth16 未跑 | [`scale-6x4500.md`](../../bench/results/scale-6x4500.md)、[`scale-6x5000.md`](../../bench/results/scale-6x5000.md) | 不写“6 规则不可能”；只写 90 GiB cgroup 下的实测边界 |
| 真实隐私面 | 交付物中响应整条/逐行 **0 命中**；私有输入逐行 7/7；策略名 1 处（公开输入） | [`privacy_surface_real.md`](../../bench/results/privacy_surface_real.md) | `canary=0` 不是 ZK 证明；`sha256(T)` 仍是公开 oracle |
| E1 `k` | Qwen N=50 **5.644 bit（=log2 50）**；N=20 **4.322**；DeepSeek mean **4.242**；均远低于 40 bit | [`k_entropy_largeN.md`](../../bench/results/k_entropy_largeN.md)、[`k_entropy_crossmodel.md`](../../bench/results/k_entropy_crossmodel.md) | **N 截断**：全 unique 不能证明真实熵；不把 5.644 当上界/下界 |
| E2 L2 | 300 候选 top-1：L0 **0.500** / L1 **0.068** / L2 **0.382**；count-only **0.014**；字典 **0.207**；真实 L2 **0.112** | [`policy_corpus_infer.md`](../../bench/results/policy_corpus_infer.md) | 证书层，不是电路层；确定性承诺可链接 |
| E3 端到端 | 6 轮、**19 证书**、11 项 PASS、回调 **10.8 ms/轮**、**无 SP1** | [`agent_e2e_deepseek.md`](../../bench/results/agent_e2e_deepseek.md) | 机制演示，不是合规真值 |
| A11 语义 | recall **0.50%**、F1 **0.010**、ROC-AUC **0.583** → **demote** | [`semantic_feasibility.md`](../../bench/results/semantic_feasibility.md) | 不把 XSTest accuracy 当策略质量 |

---

## 2. 十一个反对点的逐条打法

### R1. “理论太浅；定理 A–G 大多是标准界”

**事实（可写进 response）**
- 命题 A.1 是 ROM 下的标准 `q · Guess(X|Z)` 界；定理 B 在 `q ≥ 1` 时接近猜测熵定义；
  定理 C 是预置 transcript 集合上的 union bound；定理 D 是 hidden-credentials /
  predicate-encryption 一类的标准混合论证；定理 E 的五条件是必要条件；定理 F 的
  不可能性方向是“什么都不做即获胜”，充分性方向是标准透明日志 + 抽样公式；
  定理 G 是 Thompson/Pike 的标准构造。论文自己在 §1 写“The single guess bound
  `q·Guess` is standard; what is new is the framework...”。
- 新意不在单条界，而在：三面统一记账、策略侧实例（`policy_hash` 与
  `response_binding` 是同一个数学对象）、D-privacy 的工件固定、组合必要条件、
  签发“不可能/条件充分/检出曲线”对，以及实测披露曲线。

**证据位置**
- 论文：§1 Contributions（标准界声明）、§3.2 Proposition 2 + Remark 3（三难是分类）、
  §3.3 Theorem 3（B 的分解价值）、§7.2（ZK 只在需要的角落有价值）。
- 框架：[`certificate-binding-framework.md`](../certificate-binding-framework.md) §4–§9、§14
  （“标准 vs 新意”清单）。
- 证明：[`theorem-a-b.md`](../proofs/theorem-a-b.md) §2、[`theorem-c-e-f.md`](../proofs/theorem-c-e-f.md)、
  [`theorem-d-g.md`](../proofs/theorem-d-g.md) §0。

**可补实验 / 动作**
- 不补新定理也能做：在论文加一张 **“standard vs new” 表**，逐条列出 A–G 的标准来源、
  本文新增的部分、以及“本文不主张什么”。这张表能直接消解“包装标准界”的指责。
- 加一个 **tightness 小例子**：定理 C 在 `c=1`、挑战集两两不交时取等；
  定理 A 的 `β = id` 反例已在 Remark 4，可再给一个 `β = encode` 的可手算例子。
- 若审稿人坚持“要新定理”，**不要承诺**；把论文定位改为 framework + measurement，
  并说明“我们的贡献是让标准界在同一框架下可比较、可测量”，而不是“更强的界”。

**不能让步的边界**
- 不把 A–G 任何一条写成“新的不可能性定理”；三难保持 Proposition + Remark。
- 不删除 `β = id` / `β = encode` 反例——它们证明 guess-tight 假设不可省。
- 不把标准界（Dodis 等）的引用删掉来制造“原创”假象。

---

### R2. “ZK 未交付；标题还写 Zero-Knowledge”

**事实（可写进 response）**
- **【M6】groth16 档已交付并测量**：云机 16 核 / 90 GiB、post-NFA-fix binary
  `7f99fdb1…`、policy vkey `0x003eb14d…`；18 点 **16 ✓ / 2 OOM**，成功点
  **279–344 s / 29.7–35.1 GB / verified=True**；`10000×3` 的 core 与 groth16 都
  SIGKILL（[`scale-cloud.md`](../../bench/results/scale-cloud.md)，
  [`X1c.md`](../blockers/X1c.md)）。
- **【M6】真实 EU AI Act 包**：3 规则（含 `pattern_block`）的 `eu_ai_act_v1`
  两档都过：core **48.82 s / 12.38 GB / 2,793,531 B**；groth16
  **301.19 s / 30.07 GB / 1,874 B**；`verify_cert.py --proof --response` 均
  `RESULT: PASS`（[`eu_ai_act_proof.md`](../../bench/results/eu_ai_act_proof.md)）。
- **但隐藏性仍有限**：groth16 的 `hiding=wrapper-only`，是包装器层面隐藏、
  **非后量子**；`core` 仍 `hiding=none`；`10000×3` 仍 OOM。
- 旧文档的“云机仍是 pre-NFA-fix binary”已过时：本轮实测 binary `7f99fdb1…`、
  vkey `0x003eb14d…`，即 **post-NFA-fix**。pre-fix 表仍不能与 post-fix 混表
  （[`Core.md`](../blockers/Core.md) §5、[`X1c.md`](../blockers/X1c.md) §6）。

**证据位置**
- 论文：标题（`tdsc-paper.tex` 第 88 行）、摘要（129–133）、§5.3（1286–1296）、
  §7.2（1761–1765）、§7.7（1931–1945）。
- 结果：[`proofs.md`](../../bench/results/proofs.md)（全部 `core`）。
- 审计：[`sp1-zk-audit.md`](../sp1-zk-audit.md) §2；计划：[`plan-bhv.md`](../plan-bhv.md) P0-06/P0-07。

**可补实验 / 动作**
- **【M6】首选已执行**：`X1c` 在 90 GiB 云机跑通 groth16 矩阵与真实 EU AI Act
  两档；`X1d` 跑真实响应隐私面。修订稿应把 **groth16 表 + 真实包点**写进 §5.3，
  并标明 wrapper-only / 非后量子 / 3×10k OOM。
- **若审稿人仍要求更大规模**：在 ≥128 GB 云机补 `3×10k`/`6×10k` groth16；当前
  90 GiB 的证据是“3×10k 两档 OOM、6 规则 core 止于 4500”。
- **若 groth16 最终不被接受为交付档**：按论文已写好的 fallback 改标题为
  “Proof-of-Policy: Succinct Compliance Certificates for LLM Agent Outputs”，
  同步删摘要/关键词/§8 的 “zero-knowledge” 措辞，并在 §7.2 说明原因。
- 不把 `core` 的“两次证明不同”当作 ZK 证据——审计文档 §2.2 已说明
  transcript 随机化不是见证盲化。

**不能让步的边界**
- 不说 `core` 是 ZK；不说“包装器 ZK 已测”如果没有写 wrapper-only/非后量子。
- 不在正文写清 **wrapper-only / 非后量子 / 3×10k OOM** 之前把标题的 ZK 当作无条件交付；
  不在 rebuttal 里用“将会有”替代数字。
- 不混 pre/post-NFA vkey；不把旧 binary 的 groth16 结果放进新 vkey 表。
- 不声称后量子安全。

---

### R3. “评估规模太小；旗舰策略根本证不出来”

**事实（可写进 response）**
- **【M6】云机矩阵已重跑**（16 核 / 90 GiB cgroup，post-NFA-fix）：
  `core` 与 `groth16` 各 9 点，**16 ✓ / 2 OOM**；`core` 地板 ~10.5 GB，
  `2000×3` 跳到 **34.7 GB**；`groth16` 成功点 **279–344 s / 29.7–35.1 GB**；
  `10000×3` 两档都 OOM（[`scale-cloud.md`](../../bench/results/scale-cloud.md)）。
- **【M6】旗舰包已证**：`eu_ai_act_v1`（3 规则含 `pattern_block`）core
  **48.82 s / 12.38 GB**、groth16 **301.19 s / 30.07 GB**，两档验证 PASS
  （[`eu_ai_act_proof.md`](../../bench/results/eu_ai_act_proof.md)）。
- **【M6】6 规则边界**：core 在 2000/3000/4000/4500 字符成功
  （**181.66 s / 64.2 GB** @4500），**5000 OOM**；6 规则 groth16 未跑
  （[`scale-6x4500.md`](../../bench/results/scale-6x4500.md)、
  [`scale-6x5000.md`](../../bench/results/scale-6x5000.md)）。
- 论文旧的 Table 6（24 核/12 GB、pre-fix、4 个成功点）仍可作为“本机默认旋钮”的
  历史基线，但**不能**再作为“PoP 的规模结论”；修订稿应替换或并列新表。
- `prover_knobs_cliff.md` 的 `(200,3)` 调参成功仍是有效对照，但不再承担
  “旗舰包能否证”的举证责任。

**证据位置**
- 论文：§5.1–§5.3（Table 4–6）、§5.7（Table 10）、§7.7（O(N)、无递归聚合）。
- 结果：[`cycles.md`](../../bench/results/cycles.md)（100k 字符 × 6 规则仅执行、不出证）、
  [`proofs.md`](../../bench/results/proofs.md)、[`prover_knobs_cliff.md`](../../bench/results/prover_knobs_cliff.md)、
  [`prover_knobs.md`](../../bench/results/prover_knobs.md)。
- 策略包：`policy_packs/eu_ai_act_v1.json`、`policy_packs/agent_content_v1.json`、
  `policy_packs/pii_redaction_v1.json`。

**可补实验 / 动作**
- **【M6】最低成本已做**：把 `scale-cloud`、`eu_ai_act_proof`、`scale-6x*` 写进 §5.3，
  把 “three or more do not come out at all” 改为 “at default options on a 12 GB
  machine; on a 90 GiB cgroup, 3×10k and 6×5k still OOM”。
- **若审稿人要求更大规模**：只在 ≥128 GB 云机补 `3×10k`/`6×10k` groth16；
  不要用 90 GiB 的成功点推断 128 GB 的边界。
- **旗舰包**：`eu_ai_act_v1` 已证；`agent_content_v1` / `pii_redaction_v1` 仍是
  3–4 规则 `pattern_block`，若要声称“所有旗舰包可证”，需逐包出证，不能外推。
- 若云机仍不够，明确写“本机可行域”与“部署所需机器”，不要把 90 GiB 的边界写成
  prover 的机器无关性质。

**不能让步的边界**
- 不说“3+ 规则不可能”；只说“默认选项 / 90 GiB 下，3×10k 与 6×5k OOM”。
- 不说 6 规则 groth16 已测——它因 core 先撞墙而**未跑**。
- 不与 zkAgent 做“同一数量级”的速度结论——硬件不匹配（24 核/12 GB vs 32 核/512 GB），
  论文已声明，rebuttal 不要越界。
- 不隐藏 OOM、不删除失败点、不用执行周期数代替证明规模。

---

### R4. “策略隐私没落地；加盐只是公开值通道”

**事实（可写进 response）**
- 加盐承诺只关闭 `policy_hash` 的公开值枚举通道：无盐枚举在 2000 候选中恢复
  （下标 1000，56.8 ms），错盐枚举失败，盐泄露后恢复（58.2 ms）
  （[`policy_leak.md`](../../bench/results/policy_leak.md)）。
- 另外两条通道仍开：`core` 工件的 `spec_canonical` 含策略与盐；电路公开值仍是
  raw `rule`/`kind`；`delegated` 暴露结构；证据开示暴露规则
  （论文 §4.1 Table 2；[`C1.md`](../blockers/C1.md)）。
- **【M6】真实响应隐私面**：core/groth16 的**交付物**中，响应整条与逐行子串
  **0 命中**；私有输入逐行 7/7（证明确实在出证方输入里）；策略名 1 处是公开的
  违规规则名（[`privacy_surface_real.md`](../../bench/results/privacy_surface_real.md)）。
  这支持“交付物不含明文”，**不支持**“内容不可恢复”。
- **【M6】E2 300 候选 / 220 条真实响应**：构造性 holdout top-1
  L0 **0.500** / L1 **0.068** / L2 **0.382**；`L2-count-only` **0.014**；
  真实响应 L2 **0.112**；**L2 承诺字典攻击覆盖样本 top-1 0.207**。
  结论：确定性 `evidence_commitment = SHA256(evidence)` 可跨样本链接，
  “L2 只给承诺所以不泄露”不成立（[`policy_corpus_infer.md`](../../bench/results/policy_corpus_infer.md)）。
- L0/L1/L2 仍是**证书层投影**，不是电路级 coarsening；第三方直接读证明公开值仍看到
  L0。A1 的 20 变体数字（L0 0.810/0.840；L1 0.113/0.313；L2 0.073/0.220）是
  旧口径，E2 已用更大语料和真实响应替换其解释力。

**证据位置**
- 论文：§3.4 “What the salt does not close”、§4.1 Table 2、§4.2 Table 3、§7.1。
- 结果：[`policy_leak.md`](../../bench/results/policy_leak.md)、
  [`policy_infer.md`](../../bench/results/policy_infer.md)。
- 证明/实现：[`theorem-d-g.md`](../proofs/theorem-d-g.md) §7；[`C1.md`](../blockers/C1.md)。

**可补实验 / 动作**
- **【M6】已做**：真实响应隐私面（交付物 0 命中）与 E2 大语料推断。
- **必须补的修复**：为 L2 的 `evidence_commitment` 加**按证书加盐**（绑定
  `policy_hash` / response nonce / signer domain）或改成**桶级承诺**，然后重跑 E2；
  目标是把 L2 top-1 从不加盐的 0.382 拉回接近 `L2-count-only` 的 0.014。
- 电路级 coarsening：让公开值只含类别（L1）或仅计数（L2），需要改 `circuits/types`
  并重建 vkey；这是 C1 明确留下的独立任务。
- 扩大策略语料：13 个 `policy_packs` × 参数网格；换更强的分类器；把“审计效用”
  从代理指标改成人工/LLM 审计验证。
- 若 `delegated` 类别级协议未定义，保持 L1/L2 对非空 `delegated` fail closed，
  并在论文里写成显式限制。

**不能让步的边界**
- 不说“策略隐私已解决”；加盐只关闭公开值通道，且 E2 显示 L2 承诺可链接。
- 不把证书层 L1/L2 说成电路级隐藏；不把 L2 的“零效用”藏起来。
- 不把 L2 的 0.382/0.112 说成随机猜（随机基线 0.0033 / 真实 300 类）；
  也不把 count-only 的 0.014 当作 L2 的完整隐私。
- 不忽略 P-PP 权威与盐的信任：运营方也拿到盐，主动泄露即失败；这是自愿披露，
  不是密码学缺陷，但必须在威胁模型里说清。
- 不把 300 候选 / 真实 chat 语料的结果外推成部署风险（真实响应主要触发
  format/length/budget 粗规则，内容规则覆盖不足）。

---

### R5. “网关仍然是信任根；电路内验签没做”

**事实（可写进 response）**
- 回执链的 `seq/prev/digest` 结构在电路内检查，Ed25519 验签在电路外；电路对
  链尾元素的伪造是盲的，靠链下摘要比对 + 签名验证两道门；`ToolSeal` 堵截尾，
  但依赖验证方持有网关公钥（论文 §2、§5.6、§7.6）。
- 链下 Ed25519 成本已测：1/10/100 条回执验签 0.094 / 0.844 / 10.165 ms；
  `ToolSeal` 签 0.074 ms、验 0.184 ms、345 B；2-of-3 多签签 0.173 ms、
  验 0.508 ms、981 B（[`gateway_sig.md`](../../bench/results/gateway_sig.md)）。
- 电路内 Ed25519 是 `blocked`：`circuits/` 按设计不含验签，新增 guest 越界，
  本机无 proof lock；cycles/time/memory 全为 `null`，不是 0
  （[`B1.md`](../blockers/B1.md)）。
- 2-of-3 是宿主侧原型，未接入证书路径；它降低单点信任，但不消除截尾缺口——
  两个网关仍可一起为截断链签 seal。

**证据位置**
- 论文：§2 “What the verdict is bound to”、§5.6 Table 9、§7.6、§7.7。
- 结果：[`gateway_sig.md`](../../bench/results/gateway_sig.md)。
- 安全模型：[`security-model.md`](../security-model.md) §5.3/§5.4；blocker：[`B1.md`](../blockers/B1.md)。

**可补实验 / 动作**
- 若 circuit owner 提供 Ed25519 guest：测 1 条回执的 cycles / prove time / peak RSS，
  这是把“信网关”换成“信电路”的唯一硬证据；成本可能很高，需云机。
- 若不做电路内验签：把 2-of-3 接入证书路径，并单独论证“多网关对链尾的共识”；
  否则只写 residual trust，不要用阈值原型暗示缺口已闭。
- 透明日志的 split-view 仍是外部假设（[`B1.md`](../blockers/B1.md) B1-split-view）；
  若要声称 split-view resistance，需 RFC 6962 一致性证明 + gossip。

**不能让步的边界**
- 不从链下 0.094 ms 推断电路内成本；两者的信任含义与工作量级不同。
- 不说网关已从信任根移除；不说 2-of-3 关闭截尾。
- 不把“签名链结构正确”说成“回执内容真实”。

---

### R6. “E-1：组合只证弱形式，强形式没落地”

**事实（可写进 response）**
- `verify_composite` 第 7 步用 `derive(T_U)` 重算 `input_binding`，而不是用户提交的
  `x_U`；因此当前实现只证
  `∃x: x = derive(T_U) ∧ T_U = M(x)`，没有证 `x = x_U`
  （[`composition_controls.md`](../../bench/results/composition_controls.md)；
  [`theorem-c-e-f.md`](../proofs/theorem-c-e-f.md) §2.7）。
- 四格中 (c) 是决定性的：用户提交 `x_U = HARMFUL` 导出输入、送达 BENIGN 响应，
  验证器仍 `ok=True, satisfied=True`，因为它从不读取 `x_U`。
- 论文已经明确只主张弱形式（§5.5、§7.5 Proposition 6），这是正确的；但定理 E 的
  强形式与实现之间的差距必须在 rebuttal 里主动承认，不能等审稿人发现。

**证据位置**
- 论文：§5.5 Table 8、§7.5 Proposition 6。
- 结果：[`composition_controls.md`](../../bench/results/composition_controls.md)。
- 证明/计划：[`theorem-c-e-f.md`](../proofs/theorem-c-e-f.md) §2.7；
  [`plan-bhv.md`](../plan-bhv.md) §3.2.1；[`V1.md`](../blockers/V1.md) “与定理 E 的关系”。

**可补实验 / 动作**
- 把 `x_U` 或其承诺放进证书公开值，验证方现场重算 `IB(n, x_U)`；加一个负对照：
  `x_U ≠ derive(T_U)` 时必须拒绝。这是 E-1 的最小闭合。
- 若需要改电路公开值，协调 vkey 重建；不要用证书层字段假装电路层绑定。
- 在强形式落地前，论文继续只写弱形式，并把 Proposition 6 的标题/陈述与
  “current implementation” 分开。

**不能让步的边界**
- 不说“组合闭合了 divergent delivery”；不说强形式已证/已实现。
- 不隐藏 (c) 格；不把 `derive(T_U)` 说成“用户输入”。
- 不把组合层 5 ms 的哈希比对说成“组合的密码学成本”。

---

### R7. “G-1 / V1-2 实现 bug 说明实现不可信”

**事实（可写进 response）**
- G-1：空字符类 `[^\d\D]` 曾编译成 `Lit([])` → ε，匹配空串；V1-2：`a{0}` 曾抛
  `AttributeError`。两者都在 2026-11-01 修复（Core `45d7f61` / 合并 `9ac2d59`）：
  空字符类改为解析期 fail-closed，`a{0}`/`a{0,0}` 等价 ε；Rust `nfa_match_naive`
  的空文本 ε 缺口同步修复（[`Core.md`](../blockers/Core.md)）。
- 修复后 vkey 变为 `0x003eb14d…`，`pop-script` sha256 为 `7f99fdb1…`；旧结果
  （pre-NFA-fix）不得与新 vkey 混表（[`Core.md`](../blockers/Core.md) §5）。
- 差分模糊：46,320 次比较，Pike vs `re` 0 mismatch，Pike vs naive 0 mismatch；
  Python↔Rust 172 对 0 mismatch；空字符类 5 个模式全部 fail-closed，零次重复 4 个
  模式全部 ε（[`fuzz.md`](../../bench/results/fuzz.md)）。
- 两条 bug 都不破坏健全性：G-1 是语义 bug（空语言 vs ε），V1-2 在出证前崩溃；
  修复后解析器契约把空类排除在支持子集外。

**证据位置**
- 论文：§7.3（DoS 段的 G-1/V1-2 说明）、§7.7（limitations 第一条）。
- 记录：[`Core.md`](../blockers/Core.md)、[`V1.md`](../blockers/V1.md)（V1 原文是历史，
  已注明以 Core 为准）。
- 结果：[`fuzz.md`](../../bench/results/fuzz.md)；证明底稿：
  [`theorem-d-g.md`](../proofs/theorem-d-g.md) §12.3 / §19。

**可补实验 / 动作**
- 用**终版二进制**重跑 fuzz，并把 parser contract（空类拒绝、`a{0}=ε`）写进论文
  或附录；这是低成本、高信噪比的补强。
- 若审稿人要求“编译器正确性”，把定理 G 的 (a)(b) 纸面证明放进附录；G(c) 的实际
  Rust 代码层只能由差分测试支持，需明确写“experimental evidence, not proof”。
- 不把 V1 文档的历史表述当作“当前仍有缺口”；rebuttal 引用 Core 的修复记录。

**不能让步的边界**
- 不说“编译器已机器验证”；G(c) 的 Rust 代码层不是纸面证明。
- 不混旧/新 vkey；不把 pre-fix 的 proofs/dos 表当作当前 binary 的结果。
- 不说“从未有 bug”；说“由我们自己的差分模糊发现、已修、已回归、未破坏健全性”。

---

### R8. “页数 / 超长费；TDSC 12 页硬约束”

**事实（可写进 response）**
- TDSC 常规论文 12 页双栏（含参考文献），最多 18 页，超出 12 页按 **$200/页**
  强制超长费（MOPC）；来源与历史变化见
  [`tdsc-writing-plan.md`](../tdsc-writing-plan.md) §0.1。
- 当前任务口径是 **16 页稿**；若按 16 页投稿，4 页超出 ≈ **$800**；18 页 ≈ **$1,200**
  （[`plan-m2-m6.md`](../plan-m2-m6.md) 的预算行）。
- 论文有 13 张表 + 两个附录（Proofs / Reproduction），其中 Table 10（49 格基线）、
  Table 11（签发）、附录证明是页数大户；但 §7.1/§7.7 的 limitations 和负对照不能删。

**证据位置**
- [`tdsc-writing-plan.md`](../tdsc-writing-plan.md) §0.1、§1（页数预算与“不超页”的历史结论）；
  [`plan-bhv.md`](../plan-bhv.md) §7（超页 fallback）；[`plan-m2-m6.md`](../plan-m2-m6.md)（M5 出口 ≤18 页、预算）。
- 论文：[`tdsc-paper.tex`](../../paper/tdsc-paper.tex)（编译后页数以 PDF 为准）。

**可补实验 / 动作**
- 编译终稿 PDF，按 live author guide 复核页数；不要用 `wc -l` 估页。
- 优先移入 supplementary / 在线附录：完整证明、Reproduction 的逐步命令、
  Table 10 的 cited 行列、部分负对照细节；正文保留结论与指针。
- 合并重复的 scoping 段落（摘要的 Scope、§2 的非目标、§7.1 的三条限制有重叠），
  但不要删“不主张什么”。
- 拍板：付 MOPC（$800–$1,200）或压到 12 页；不要在 rebuttal 里承诺“肯定不超页”
  而没有编译证据。

**不能让步的边界**
- 不删 §7.1 的隐私 caliber、§7.7 的 limitations、四格负对照、OOM 行来省页。
- 不把 16 页说成 12 页；不隐藏超长费。
- 不为了页数把证明/结果移到“不可获取”的补充材料而不给 DOI/链接。

---

### R9. “引文债：很多引用未核实、正文点名不给 cite”

**事实（可写进 response）**
- 论文有多处 `\need{BLOCKER WP8 (citations)}`：Intro 点名的 Proof-of-Guardrail、
  Agentrust/cMCP/cA2A、Lean-Agent、zk-regex V2、ZK Email、WITNESS、
  `@brivora/verify`、DeepProve 以及 EU AI Act Art. 12/13 均未给 `\cite{}`；
  §4.3 的五条 prior-art、§6 的 WITNESS/Apache-2.0、§7.1 的 SP1 安全模型引文
  都待核实；bibliography 里 `zkattach`、`pco`、`hiddencred`、`handshake`、
  `xacmlpriv`、`sw05`/`ksw08`、`vdr` 仍是占位/待核。
- 论文已经记录一条不能回退的更正：IACR ePrint 2024/813 是 Kiraz/Larraia/Vaughan
  “How to Redact the Bitcoin Backbone Protocol”，**不是** Verifiable Document
  Redacting；VDR 是 Springer 条目。
- 这些不是“写作瑕疵”，是 TDSC 编辑会直接退回的提交缺陷。

**证据位置**
- 论文：Intro 的 `\need`（193–196）、§4.3（1058–1062）、§6（1667–1674）、
  §7.1（1698–1702）、附录（2155–2162）、bibliography（2164–2214）。
- 清单：[`tdsc-fixlist.md`](../tdsc-fixlist.md) §2；计划：[`plan-bhv.md`](../plan-bhv.md) P0-11 / P2-04。

**可补实验 / 动作**
- 逐条打开原文核实作者、venue、pages、DOI；不能核实的**删断言**，不要留占位。
- 给 Intro 的每个系统加 `\cite{}`；EU AI Act 用官方 EUR-Lex 引用；SP1 安全模型
  引官方文档的具体小节/URL。
- WITNESS 的 “Apache-2.0” 要么给出仓库链接，要么删掉“open source 不是差异点”的句子。
- 提交前 `grep -c '\\need{'` 与 `grep -c '\\fixme{'` 必须为 0（或每条都有明确 blocker
  且不进 PDF）。

**不能让步的边界**
- 不编造 bibitem；不把未读过的论文写成“已核实”。
- 不用 ePrint 2024/813 冒充 VDR。
- 不保留没有 `\cite{}` 的“first / only / no prior work”断言。
- 不把 `\need{}` 留在提交 PDF 里。

---

### R10. “真实 LLM / `k` / XSTest 策略质量”（M6 已部分交付）

**事实（可写进 response）**
- **【M6】`k` 已测，但受 N 截断**：Qwen2.5-7B 在 XSTest 50 条 prompt 上、
  温度 0.7、N=50：50 组 **全部 `distinct=50`**，只能读到
  **`k = log2(50) = 5.644 bit`**；N=20 的 Qwen/Mistral 为 **4.322 bit**；
  DeepSeek API N=20 mean **4.242 bit**、median 4.322（4 组有重复，p_max max 0.100）。
  论文用的阈值是 **40 bit**，这些测量**远低于阈值**，但
  **N 截断意味着不能证明真实熵的上界或下界**：全 unique 只说明未观测到重复。
  （[`k_entropy_largeN.md`](../../bench/results/k_entropy_largeN.md)、
  [`k_entropy_crossmodel.md`](../../bench/results/k_entropy_crossmodel.md)）
- **【M6】真实端到端已跑**：DeepSeek 6 轮、**19 张证书**（另 stock demo 13 张）、
  第三方 `verify_session.py` 11 项全 PASS；宿主回调均值 **10.8 ms/轮**；
  **没有 SP1 证明**（`unproven`），API 错误/限流 0/0
  （[`agent_e2e_deepseek.md`](../../bench/results/agent_e2e_deepseek.md)）。
- **【M6】A11 语义模型 demote**：真实 toxic 分类器在 XSTest 上主阈值
  recall **0.50%**、F1 **0.010**、ROC-AUC **0.583**；ONNX 255.5 MiB、
  单条 13.33 ms。它测的是“文本是否含毒”，不是“请求是否有害”，
  **不能**替换演示模型，也不足以支撑 P2-01
  （[`semantic_feasibility.md`](../../bench/results/semantic_feasibility.md)）。
- 仍未测：`safety_xstest_v1` 在 XSTest 上的 P/R/F1（策略质量），以及 τ-bench /
  真实工具轨迹的统计分布。E3 是机制演示，不是合规真值；E1 是采样分布的估计，
  不是信息论界。

**证据位置**
- 论文：§5.10（首轮 X2 blocker）、§7.7（semantic model / inference proof 两条）、
  §5.5 的 `\need`（组合成本未验证）。
- **【M6】结果**：[`k_entropy_largeN.md`](../../bench/results/k_entropy_largeN.md)、
  [`k_entropy_crossmodel.md`](../../bench/results/k_entropy_crossmodel.md)、
  [`agent_e2e_deepseek.md`](../../bench/results/agent_e2e_deepseek.md)、
  [`semantic_feasibility.md`](../../bench/results/semantic_feasibility.md)。
- 计划/脚本：[`plan-bhv.md`](../plan-bhv.md) P0-09/P0-10；[`plan-m2-m6.md`](../plan-m2-m6.md) M2-03；
  `bench/bench_k_entropy.py`、`bench/bench_real_llm_e2e.py`；
  [`wave2_smoke/README.md`](../../bench/results/wave2_smoke/README.md)（明示不是论文数字）。

**可补实验 / 动作**
- **【M6】最小闭环已做**：E1 的 Qwen N=50 / 跨模型 N=20 `k` 与 E3 的真实 DeepSeek
  端到端都已有结果。修订稿应把 **N 截断口径**写在 `k` 表旁，并把 E3 的 10.8 ms
  回调与“无 SP1 证明”分开写。
- **若审稿人要求更强 `k`**：把 N 提到 ≥500/1000（API 成本可控），或改报
  `p_max` 的置信区间；不要用 N=50 的 5.644 当熵上界。
- **策略质量**：在 XSTest 上给 `safety_xstest_v1` 报 P/R/F1 与 safe prompt FPR；
  否则明确写“策略质量不在本文评估范围”，不要用 A11 的 toxic 分类器顶替。
- **语义规则**：A11 已 demote；若要推进 P2-01，必须换匹配“有害请求”的数据集
  （不是 toxic 文本），并重新评估 ezkl 可行性。
- **推论**：推理半仍是 stand-in；不要把组合成本写成“推理主导”
  （[`compose.md`](../../bench/results/compose.md) 的 0.87× 是代理规模）。
- 不把 `wave2_smoke` / stub / `--no-prove` 的数字写进论文。

**不能让步的边界**
- 报 `k` 必须同时写 **N 截断**；不把 5.644 bit 说成真实熵的上界/下界。
- 不把 E3 的机制演示说成“模型合规”；不把 `wave2_smoke` / stub / `--no-prove`
  的数字写进论文。
- 不说语义模型可用；A11 的结论是 **demote**，不是“换阈值就好”。
- 不说推理证明“忠实于真实模型”。
- 不说组合成本由推理主导（代理规模下 0.87× 不成立）。
- 没有 XSTest P/R/F1，不说策略“有效合规”。

---

### R11. “L2 证据承诺可链接；‘只给承诺’不等于隐私”（M6 新增）

**事实（可写进 response）**
- E2 用 **300 个候选策略**（13 模板、3–8 规则、unique/shared 命名与证据口径）、
  **220 条真实 X2c chat 响应** + 构造性补充，按 L0/L1/L2 重跑推断攻击。
- 构造性 holdout top-1：L0 **0.500**、L1 **0.068**、L2（实际承诺载荷）**0.382**、
  `L2-count-only`（A1 旧口径）**0.014**；真实响应 L2 **0.112**；L2 承诺字典攻击
  覆盖样本 top-1 **0.207**（[`policy_corpus_infer.md`](../../bench/results/policy_corpus_infer.md)）。
- 原因：`evidence_commitment = SHA256(evidence)` 是**确定性**的；同一条规则/证据值
  在不同响应上给出同一串哈希，攻击者可建“哈希 → 策略/证据”字典。这不是分类器
  泛化，而是**可链接性**。
- 该结果比 A1 的 20 变体结果更不利，且是**我们自己发现的**；论文若已写 L2
  “commitment-only”，必须补这条限制。

**证据位置**
- [`policy_corpus_infer.md`](../../bench/results/policy_corpus_infer.md) §3/§7；
  [`policy_corpus_infer.json`](../../bench/results/policy_corpus_infer.json)；
  [`policy-corpus-inference.md`](../experiments/policy-corpus-inference.md)。

**可补实验 / 动作**
- 最小修复：把 `evidence_commitment` 改为**按证书加盐**
  `SHA256(policy_hash || response_nonce || signer_domain || evidence)`，或只公开
  **桶级**承诺（类别/计数），然后重跑 E2；目标是把 L2 top-1 拉回接近 0.014。
- 在论文 §4.1 Table 2 增加一行“L2 commitment linkability”，并给出修复前后对比。
- 不要把 count-only 的 0.014 继续当作 L2 的隐私数字；也不要把 0.382 外推成
  所有部署的泄露率（构造性样本补的是内容规则覆盖）。

**不能让步的边界**
- 不说“L2 只给承诺所以不泄露”；不隐藏 0.382/0.112/0.207。
- 不把加盐修复写成已实现（当前 `disclosure.py` 是裸 SHA256）。
- 不把证书层结果说成电路级隐藏。

---

## 3. 建议补的实验（按决策价值排序）

| 顺序 | 实验 | 解决哪条 | 资源 | 验收判据 | 失败 fallback | M6 状态 |
|---:|---|---|---|---|---|---|
| 1 | **X1c/X1d**：post-NFA-fix 云机 `groth16` + 真实 EU AI Act + 隐私面 + 规模矩阵 | R2/R3/R4 | 90 GiB 云机 | 16/18 点 verified；EU 两档 PASS；隐私面 0 命中 | 改标题 “Succinct”，删 ZK 措辞 | **已完成**（16/18；EU 两档 PASS） |
| 2 | **E1/E3**：真实 LLM `k` 分布 + 端到端 | R10/R3 | GPU/API | 贪心 `k≈0`、温度采样有分布；端到端延迟/证书可追溯 | 只保留 structural 陈述 | **部分完成**（N 截断；E3 无 SP1） |
| 3 | **E2 L2 加盐/桶级承诺** + 重跑 | R4/R11 | 本地 | L2 top-1 接近 count-only；字典攻击失效 | 明确报告可链接性，不称 L2 隐私 | **未做**（新发现） |
| 4 | **E-1**：`x_U` 承诺进公开值 + 验证方重算 + 负对照 | R6 | 本地（可能需 vkey） | `x_U ≠ derive(T_U)` 必须拒绝；真证明端到端 | 继续只写弱形式，移强形式到 future work | **未做** |
| 5 | **Scale-tuned**：≥128 GB 上 `3×10k`/`6×10k` | R3 | 大内存云机 | 补上 90 GiB 的 OOM 点 | 明确“本机可行域”，不写机器无关边界 | **部分**（90 GiB 已到 6×4500） |
| 6 | **Policy corpus**：13 包 × 参数网格 + 强分类器 + 效用验证 | R4 | 本地 | 每级 top-1/top-3/MI/utility 可复跑 | 保留 300 候选结果，标“shape only” | **部分**（E2 已扩语料） |
| 7 | **Trace-leak**：`core` 工件恢复 `T`/`spec_canonical` 的直接实验 | R1/R3/R4 | 本地（小规模） | 给出恢复率或源级证据 | 保留源级审计，不报恢复率 | **部分**（真实响应探针） |
| 8 | **Circuit-level coarsening**：L1/L2 公开值只含类别/计数 | R4 | 需改电路 + vkey | 第三方读公开值也看不到 raw rule | 明确“证书层投影”，不称电路级隐藏 | **未做** |
| 9 | **Gateway**：Ed25519 guest 或 2-of-3 接入 + 链尾共识 | R5 | 云机 / circuit owner | cycles/time/mem 或接入后的证书路径 | 保持 residual trust，不推断电路成本 | **未做** |
| 10 | **Final fuzz**：终版 binary 重跑差分 + parser contract 表 | R7 | 本地 | 46,320 比较 0 mismatch；Rust 对拍 0 mismatch | 保留现有 fuzz，标 binary sha | **未做** |
| 11 | **Citation/page audit**：逐条核实 + 编译 PDF | R8/R9 | 本地 | 0 `\need`/`\fixme`；页数确定；无占位 bibitem | 删不可核实断言；移附录/付 MOPC | **未做**（9 个 `\need`） |

---

## 4. 回复模板（英文可复用）

### 模板 A：承认边界 + 指向证据 + 给出动作

> We thank the reviewer for raising this. We agree that **⟨claim⟩** is not
> established by the current artefact. The paper already states this in
> **⟨section/table⟩**, but we will make it visible in **⟨title/abstract/§X⟩**.
> The relevant evidence is **⟨result file / table⟩**: **⟨one-sentence fact⟩**.
> In the revision we will **⟨concrete action⟩**; if that experiment does not
> return, we will **⟨fallback: retitle / narrow claim⟩** rather than overclaim.

### 模板 B：拒绝过度主张（理论新颖性）

> We agree that the individual bounds are standard; the paper says so in §1 and
> the framework document §14. We do not claim a new guessing bound or a new
> impossibility theorem. Our contribution is the **unified three-sided
> accounting**, the **policy-side instance** (`policy_hash` is the same
> public-recomputable object as `response_binding`), and the **measurements**
> that instantiate the bounds. We have added a “standard vs new” table and a
> tightness example for Theorem C, and we have kept the trilemma as a
> conditional classification rather than promoting it.

### 模板 C：实验已交付（X1c/X1d/E1/E3）

> The experiments requested in the first round have now run. On a 16-core / 90 GiB
> cloud container with the post-NFA-fix binary (`sha256 7f99fdb1…`, policy vkey
> `0x003eb14d…`), `groth16` verified 16 of 18 matrix points at 279–344 s and
> 29.7–35.1 GB per successful point; a real `eu_ai_act_v1` policy verified in both
> tiers (`core` 48.82 s / 12.38 GB; `groth16` 301.19 s / 30.07 GB / 1,874 B). The
> two failures (`10000×3`, both tiers) and the 6-rule OOM at 5000 characters are
> retained in the tables. We also measured `k` on Qwen/Mistral/DeepSeek and ran a
> real DeepSeek agent session (19 certificates, third-party verification PASS).
> The remaining limits are stated explicitly: `groth16` is wrapper-only and
> non-post-quantum; `k` is capped by N; E3 produces no SP1 proof.

### 模板 C2：实验仍未覆盖（不要用仓库结果冒充论文）

> This is a `pending` item, not a completed result. The protocol and scripts are
> fixed (**⟨file⟩**), but the numbers require **⟨cloud/GPU⟩**. We will report
> **⟨matrix / k distribution / P-R-F1⟩** with hardware and binary digests, or, if
> the resource is not available, we will **⟨retitle / remove the k-dependent
> claim⟩**. We will not substitute smoke/stub output for paper numbers.

### 模板 D：标题 fallback

> If the witness-hiding tier is not delivered by the revision deadline, we will
> retitle the paper “Proof-of-Policy: Succinct Compliance Certificates for LLM
> Agent Outputs”, remove “zero-knowledge” from the abstract and keywords, and
> keep the privacy scope exactly as stated in §7.1. We prefer a defensible
> “succinct” claim to an undelivered “zero-knowledge” one.

### 模板 E：实现 bug（G-1/V1-2）

> These were implementation defects found by our own differential fuzzing, not
> soundness breaks. Both are fixed in commit `9ac2d59`; the parser now fails
> closed on empty character classes and `a{0}` compiles to ε. The fix changed
> the guest, so the policy vkey moved to `0x003eb14d…` and the binary to
> `sha256 7f99fdb1…`; pre-fix results are not mixed with post-fix tables. The
> final binary will be re-fuzzed (46,320 comparisons, 0 mismatch) and the parser
> contract will be stated in the paper.

---

### 模板 F：`k` 的 N 截断（不要过度解释）

> We agree that a finite sample cannot establish an entropy bound. At N=50 the
> smallest observable mode frequency is 1/50, so all-unique samples can only
> report `k = log2(50) = 5.644 bit`; N=20 cross-model runs report 4.322–4.242 bit.
> These values are far below the 40-bit threshold, but we do **not** claim they are
> an upper bound on the true entropy. The paper will report the N-truncation
> explicitly and will not use the measured `k` as an information-theoretic bound.

### 模板 G：L2 证据承诺可链接（主动承认 + 修复）

> We found a leakage channel that the earlier draft did not report: the
> `evidence_commitment` is a deterministic `SHA256(evidence)`, so the same rule or
> evidence value yields the same digest across certificates. On 300 candidate
> policies this raises L2 top-1 from 0.014 (count-only) to 0.382 on the constructive
> holdout and 0.112 on real responses; a hash dictionary reaches 0.207 on covered
> samples. We will (i) state this in §4.1 as a limitation, and (ii) salt the
> commitment per certificate (binding `policy_hash`, response nonce, and signer
> domain) or publish bucket-level commitments, then rerun the attack. We will not
> describe L2 as “commitment-only, therefore private.”

### 模板 H：6 规则边界与 A11 demote

> On the 90 GiB cgroup, 6-rule `core` succeeds at 4500 characters (181.66 s /
> 64.2 GB) and OOMs at 5000; 6-rule `groth16` was not run because `core` hits the
> wall first. We therefore describe a measured machine boundary, not a
> machine-independent impossibility. Separately, the real toxic classifier is
> demoted: on XSTest it reaches recall 0.50%, F1 0.010, ROC-AUC 0.583, because
> “toxic text” is not “harmful request.” We keep the negative result and do not
> present it as a usable guardrail.

## 5. 不能让步的边界（合并版）

1. **ZK**：不说 `core` 是 ZK；不在正文写清 wrapper-only/非后量子/3×10k OOM 之前把
   标题的 ZK 当已交付；不混 pre/post-NFA vkey；不声称后量子。
2. **策略隐私**：不说加盐 = 策略隐私已解决；不把证书层 L1/L2 说成电路级隐藏；
   不隐藏 L2 零效用；不忽略 P-PP 权威与盐的信任；**不把 L2 的 0.382/0.112/0.207
   藏起来，也不把 count-only 的 0.014 当 L2 全貌**。
3. **组合**：不说强形式已落地；不说组合闭合 divergent delivery；不隐藏 (c) 格。
4. **网关**：不推断电路内验签成本；不说网关已从信任根移除；不说 2-of-3 关闭截尾。
5. **真实 LLM / k**：报 `k` 必须写 N 截断；不把 5.644 bit 当真实熵上界/下界；
   不把 E3 机制演示当合规真值；不说语义模型可用（A11 demote）；不说推理证明
   忠实于真实模型；不说组合成本由推理主导。
6. **规模**：不把 90 GiB 的边界写成机器无关；不说 6 规则 groth16 已测；
   不与 zkAgent 做匹配硬件的速度结论；不隐藏 OOM。
7. **理论**：不把标准界包装成新定理；不把三难写成不可能性定理；不删反例。
8. **引文**：不编造 bibitem；不用 ePrint 2024/813 冒充 VDR；不留 `\need{}` 进 PDF。
9. **页数**：不删 limitations/负对照省页；不把 16 页说成 12 页；不隐藏 MOPC。
10. **Artifact**：不写“Docker 镜像已实测”或给未知镜像大小；不把仓库云端结果
    当作镜像内容；不填虚构 DOI/checksum。

---

## 6. 提交前检查清单

```bash
# 1) 论文标记清零（目标 0；若保留，必须每条都有 blocker 且不进 PDF）
grep -c '\\need{' paper/tdsc-paper.tex
grep -c '\\fixme{' paper/tdsc-paper.tex

# 2) 编译两遍，检查 undefined ref / 页数
cd paper && pdflatex "\def\SKELQUIET{}\input{tdsc-paper.tex}" && \
pdflatex "\def\SKELQUIET{}\input{tdsc-paper.tex}"

# 3) 文档链接闸门
python3 -m unittest tests.test_doc_links -v

# 4) 结果文件与论文数字对表（至少覆盖）
#    proofs.md / cycles.md / ablation.md / dos_proof.md / baseline.md
#    composition_controls.md / gateway_sig.md / baselines.md / issuance.md
#    policy_infer.md / policy_leak.md / delivery_binding.md / fuzz.md
```

- [ ] 标题与摘要的 ZK 措辞与 X1c 结果一致；写明 **wrapper-only / 非后量子 / 3×10k OOM**，
      否则已改 “Succinct”。
- [ ] 每张证明表标了 binary sha256、vkey、post-NFA-fix；pre-fix 表已替换或明确并列。
- [ ] 新表包含 `scale-cloud` 的 16/18、`eu_ai_act_proof` 两档、`scale-6x4500/5000`。
- [ ] 801/783 tests 漂移已结清（论文附录与 `reproduce.md` 一致；artifact 口径 42/17）。
- [ ] 所有 `\need{WP8}` 引文已核实或断言已删；无占位 bibitem；当前 9 个 `\need` 清零。
- [ ] 页数已按 live author guide 复核（12 页含 / 18 页上限 / MOPC 费率）；MOPC 预算已拍板。
- [ ] `wave2_smoke` / stub / `--no-prove` 没有进入论文表格。
- [ ] 策略隐私表（Table 2）逐行与 `C1.md` 的通道状态一致，并新增 **L2 可链接**行。
- [ ] E-1 仍是弱形式（若未实现），且 §5.5/§7.5 的措辞一致。
- [ ] 四格负对照、OOM 行、L2 零效用、issuance 0.0000 都还在。
- [ ] `k` 表写 N=50/20 截断；不把 5.644 bit 当上界/下界；40 bit 阈值说明清楚。
- [ ] E3 写“无 SP1 证明”；A11 写 demote；不把 XSTest accuracy 当策略质量。
- [ ] artifact README/Zenodo 不写“Docker 已构建”；镜像大小未知；DOI/checksum 为占位。
- [ ] `python3 -m unittest tests.test_doc_links -v` 通过。
