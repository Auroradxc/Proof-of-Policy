# Rebuttal playbook（A8）

> **日期**：2026-11-01　**基线**：`4fe5c41`（分支 `bhv/a8-review`）
> **配套**：[`mock-reviews.md`](mock-reviews.md)、[`../certificate-binding-framework.md`](../certificate-binding-framework.md)、
> [`../plan-bhv.md`](../plan-bhv.md)、[`../../paper/tdsc-paper.tex`](../../paper/tdsc-paper.tex)
> **用途**：把最可能出现的十类反对意见，逐条变成“事实 + 证据位置 + 可补实验 + 不能让步的边界”。
> 所有数字必须能在 `bench/results/*` 或论文表格中找到；未完成项标
> `pending X1b` / `pending X2` / `blocker` / `open`，**不编造结果**。
> **X1b** = X1 在 post-NFA-fix 新 vkey 上的云机重跑；**X2** = 真实 LLM 采样与 `k` 测量。

---

## 0. 先手：三句话定调

1. **本文的主张是“框架 + 测量 + 一个构造性实例”，不是“发明了一个新的猜测界”。**
   猜测熵界、ROM 隐藏、union bound、D-privacy 混合论证、Thompson/Pike 构造都是标准的；
   新意在把响应/请求/策略三面收进同一个 BHV 记账、给出策略侧实例、并用负对照和
   披露曲线把定理落地（[`certificate-binding-framework.md`](../certificate-binding-framework.md) §14）。
2. **本文明确不主张的事情和主张一样多**：不主张 `core` 是 ZK，不主张策略隐私已解决，
   不主张组合强形式已落地，不主张网关信任已消除，不主张真实 LLM 已测。
   这些边界写在摘要的 “Scope of privacy”、§7.1、§7.3–§7.6 和 §7.7。
3. **Rebuttal 期能改变结论的只有两类东西**：`X1b`（witness-hiding 档 + 隐私面 + 规模矩阵）
   和 `X2`（真实模型 + 实测 `k` + XSTest 质量）。其余反对点用“改文字/补负对照/明确边界”
   处理；不要用新的过度主张去换分数。

**审稿人心理**：TDSC 的系统/安全审稿人最反感“标题写 ZK、正文说没测 ZK”；
理论审稿人最反感“把标准界包装成新定理”；隐私审稿人最反感“加盐 = 策略隐私已解决”。
本 playbook 的每一节都围绕这三条。

---

## 1. 十类反对点优先级

| # | 反对点 | 危险度 | 类型 | 是否决策关键 | 主要证据 | 补实验 / 动作 |
|---|---|---|---|---|---|---|
| R1 | 理论太浅、定理是标准界 | 高 | 文字 + 定位 | 否（但影响评分） | 论文 §1/§3；框架 §14；证明底稿 | 标准 vs 新意表；tightness 例；不承诺新定理 |
| R2 | ZK 未交付 / 标题 | **极高** | 实验 + 标题 | **是** | 论文标题/摘要/§5.3/§7.2；`sp1-zk-audit.md` | `X1b`：groth16/plonk + 隐私面；否则改 “Succinct” |
| R3 | 规模小、旗舰策略不可证 | **极高** | 实验 | **是** | 论文 §5.1–5.3；`proofs.md`；`prover_knobs_cliff.md` | 调参矩阵 + 云机 64–128 GB + 旗舰包 |
| R4 | 策略隐私没落地 | **极高** | 实验 + 文字 | **是** | 论文 §3.4/§4.1/§4.2；`C1.md`；`policy_infer.md` | `X1b` 隐私面 + 电路级 coarsening + 更大语料 |
| R5 | 网关信任 | 高 | 文字 + 可选实验 | 否 | 论文 §2/§5.6/§7.6；`gateway_sig.md`；`B1.md` | 电路内 Ed25519（blocked）或明确 residual trust |
| R6 | E-1 只证弱形式 | 高 | 实现 | 是（组合贡献） | 论文 §5.5/§7.5；`composition_controls.md` | 实现 `x_U` 承诺 + 负对照 |
| R7 | G-1/V1-2 实现 bug | 中 | 已修 + 文字 | 否 | 论文 §7.3/§7.7；`Core.md`；`fuzz.md` | 终版二进制重跑 fuzz；解析器契约表 |
| R8 | 页数 / 超长费 | 中 | 编辑 | 否（但费钱） | `tdsc-writing-plan.md` §0.1/§1；`plan-m2-m6.md` | 编译终稿、移附录、拍板付费或压缩 |
| R9 | 引文债 | 高 | 文字 | 否（但不修会被拒） | 论文 `\need` 与 bibliography；`tdsc-fixlist.md` | 逐条打开核实；删不可核实的断言 |
| R10 | 真实 LLM 缺失 | **极高** | 实验 | **是** | 论文 §5.10/§7.7；`plan-bhv.md` P0-09/10 | `X2`：k 分布 + 真模型端到端 + XSTest P/R/F1 |

> **如果只能补两件事**：`X1b` 和 `X2`。它们分别决定标题能否保留、实证主张能否成立。
> **如果只能改三处文字**：标题/摘要的 ZK 条件、策略隐私的“只关闭公开值通道”、
> 组合的“只证弱形式”。这三处已经是论文的诚实边界，只需让它们在标题/摘要层面也可见。

---

## 2. 十个反对点的逐条打法

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
- 论文所有证明数字都是 `core`（非 ZK）档；论文自己写“no zero-knowledge proving
  number appears anywhere in this paper”（§5.3），并说若 `groth16` 不成为交付档，
  “the word must leave the title”（§7.2）。
- `core` / `compressed` 的 STARK 证明不满足 ZK；证明工件带 `main_commitment` 与
  `opened_values`；只有 `groth16`/`plonk` 包装器把内部 STARK 作为私有见证，
  但这是 wrapper-level 声明、非后量子、需 ≥16 GB、且本机未测
  （[`sp1-zk-audit.md`](../sp1-zk-audit.md) §2–§3）。
- 当前云机 X1 仍用 pre-NFA-fix 旧 binary；任何 `groth16` 表必须标 binary sha256
  与 “pre-NFA-fix”，不能与新 vkey `0x003eb14d…` 混表（[`Core.md`](../blockers/Core.md) §5）。

**证据位置**
- 论文：标题（`tdsc-paper.tex` 第 88 行）、摘要（129–133）、§5.3（1286–1296）、
  §7.2（1761–1765）、§7.7（1931–1945）。
- 结果：[`proofs.md`](../../bench/results/proofs.md)（全部 `core`）。
- 审计：[`sp1-zk-audit.md`](../sp1-zk-audit.md) §2；计划：[`plan-bhv.md`](../plan-bhv.md) P0-06/P0-07。

**可补实验 / 动作**
- **首选**：`X1b` 云机（64–128 GB）跑 `groth16`/`plonk`：至少 1–3 规则 × 10k 字符，
  记录 prove time、proof size、peak RSS、verify time，并跑隐私面探针
  （`spec_canonical` / `response` 是否出现在证明工件中）。成功后标题可保留，
  但必须写明“ZK 是 wrapper-level、非后量子、需 ≥16 GB”。
- **若 X1b 失败**：按论文已写好的 fallback 改标题为
  “Proof-of-Policy: Succinct Compliance Certificates for LLM Agent Outputs”，
  同步删摘要/关键词/§8 的 “zero-knowledge” 措辞，并在 §7.2 说明原因。
- 不把 `core` 的“两次证明不同”当作 ZK 证据——审计文档 §2.2 已说明
  transcript 随机化不是见证盲化。

**不能让步的边界**
- 不说 `core` 是 ZK；不说“包装器 ZK 已测”如果没有测。
- 不在 X1b 之前把标题的 ZK 当作已交付；不在 rebuttal 里用“将会有”替代数字。
- 不混 pre/post-NFA vkey；不把旧 binary 的 groth16 结果放进新 vkey 表。
- 不声称后量子安全。

---

### R3. “评估规模太小；旗舰策略根本证不出来”

**事实（可写进 response）**
- 论文的默认矩阵（24 核 / 12 GB，`core`）只有 4 个成功点：`200×1`、`200×2`、
  `2k×1`、`10k×1`；`200×3` 与 `20k×1` OOM。成功点峰值都在 10,389–10,506 MB，
  说明 ~10.15 GiB 是 prover 固定地板（论文 §5.3 Table 6；
  [`proofs.md`](../../bench/results/proofs.md)）。
- 这不等同于“3 条规则永远证不出来”：仓库的旋钮 A/B 显示同一个 `(200,3)` 在
  `NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1` 下成功（160.1 s / 10,763.8 MiB），
  但 `(20k,1)` 仍 OOM（[`prover_knobs_cliff.md`](../../bench/results/prover_knobs_cliff.md)）。
  论文目前没有把这条旋钮结果写进 §5.3，审稿人可能据此认为“3+ rules”结论过强。
- 旗舰包 `eu_ai_act_v1` / `agent_content_v1` 都是 3 条规则且含 `pattern_block`，
  正好落在默认 OOM 点；`pii_redaction_v1` 是 4 条 `pattern_block`。
  这意味着“能证 EU AI Act 策略”目前不是论文的实测结论。

**证据位置**
- 论文：§5.1–§5.3（Table 4–6）、§5.7（Table 10）、§7.7（O(N)、无递归聚合）。
- 结果：[`cycles.md`](../../bench/results/cycles.md)（100k 字符 × 6 规则仅执行、不出证）、
  [`proofs.md`](../../bench/results/proofs.md)、[`prover_knobs_cliff.md`](../../bench/results/prover_knobs_cliff.md)、
  [`prover_knobs.md`](../../bench/results/prover_knobs.md)。
- 策略包：`policy_packs/eu_ai_act_v1.json`、`policy_packs/agent_content_v1.json`、
  `policy_packs/pii_redaction_v1.json`。

**可补实验 / 动作**
- **最低成本**：在论文加一段“knob sensitivity”，承认 Table 6 是默认选项下的边界，
  并给出 `(200,3)` 旋钮成功的单点；把“three or more do not come out at all”改为
  “at default options on a 12 GB machine”。
- **推荐**：云机 64–128 GB 重跑矩阵：规则数 `{1,2,3,4,6,8}` × 长度 `{200,2k,10k,50k}`
  × 档 `{core, groth16}`；至少覆盖 3 条规则 × 10k 和 6 条 × 10k。
- **旗舰包**：至少证明 `eu_ai_act_v1`、`agent_content_v1`、`pii_redaction_v1` 三个包
  的真实响应；报告每包的成功/失败、时间、内存。
- 若云机仍不够，明确写“本机可行域”与“部署所需机器”，不要把 12 GB 的边界写成
  prover 的性质。

**不能让步的边界**
- 不说“3+ 规则不可能”；只说“默认选项 / 12 GB 下 OOM”。
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
- L0/L1/L2 是**证书层投影**，不是电路级 coarsening；第三方直接读证明公开值仍看到
  L0。推断曲线：L0 top-1 0.810 / top-3 0.840 / MI 3.445 bit / utility 1.000；
  L1 0.113 / 0.313 / 0.940 / 0.405；L2 0.073 / 0.220 / 0.216 / 0.000
  （论文 §4.2 Table 3；[`policy_infer.md`](../../bench/results/policy_infer.md)）。
- 语料是 20 个策略变体、每变体 40 训练 / 15 测试、stdlib naive Bayes；这是形状结果，
  不是部署风险估计。

**证据位置**
- 论文：§3.4 “What the salt does not close”、§4.1 Table 2、§4.2 Table 3、§7.1。
- 结果：[`policy_leak.md`](../../bench/results/policy_leak.md)、
  [`policy_infer.md`](../../bench/results/policy_infer.md)。
- 证明/实现：[`theorem-d-g.md`](../proofs/theorem-d-g.md) §7；[`C1.md`](../blockers/C1.md)。

**可补实验 / 动作**
- `X1b` 隐私面探针：在 `groth16` 档检查证明工件是否仍含 `spec_canonical` / 盐 /
  响应明文；这是“策略隐私是否真正关闭证明工件通道”的唯一直接证据。
- 电路级 coarsening：让公开值只含类别（L1）或仅计数（L2），需要改 `circuits/types`
  并重建 vkey；这是 C1 明确留下的独立任务。
- 扩大策略语料：13 个 `policy_packs` × 参数网格；换更强的分类器（sklearn / 逻辑回归 /
  小型 transformer）；把“审计效用”从代理指标改成人工/LLM 审计验证。
- 若 `delegated` 类别级协议未定义，保持 L1/L2 对非空 `delegated` fail closed，
  并在论文里写成显式限制。

**不能让步的边界**
- 不说“策略隐私已解决”；加盐只关闭公开值通道。
- 不把证书层 L1/L2 说成电路级隐藏；不把 L2 的“零效用”藏起来。
- 不忽略 P-PP 权威与盐的信任：运营方也拿到盐，主动泄露即失败；这是自愿披露，
  不是密码学缺陷，但必须在威胁模型里说清。
- 不把 20 变体 / naive Bayes 的结果外推成部署风险。

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

### R10. “真实 LLM 缺失；`k` 没测；XSTest 策略质量没报”

**事实（可写进 response）**
- 论文 §5.10 明确标 `BLOCKER X2`：`Guess(T|Z)` 未在真实模型上测量，因此没有 `k`、
  没有阈值实例；所有关于 `k` 的陈述是 structural，不是 measured。
- 语义规则模型是 demonstration proxy；“$P(\text{harmful})$ is low”只对**这个**模型
  成立；推理半是 640 个定点权重的固定点 MLP，证明的是“这个图在这个响应上算出这个
  输出”，不是图有多好（§7.7）。
- 组合成本在代理规模下不是推理主导：策略半 127.3 s / 643,610 cycles，推理半
  110.8 s / 83,492 cycles，比值 0.87×；论文没有声称“推理主导”
  （[`compose.md`](../../bench/results/compose.md)）。
- 真实 LLM 端到端脚本已就绪，但结果 `pending X2`；`wave2_smoke/` 是冒烟输出，
  **不是论文数字**（[`plan-bhv.md`](../plan-bhv.md) 的 Wave 2 说明；
  [`plan-m2-m6.md`](../plan-m2-m6.md) M2-03）。
- XSTest 策略质量：论文没有 P/R/F1；`safety_xstest_v1` 在仓库里被描述为
  “naive keyword blocklist ... exposes the false-positive rate of keyword-only policies”。
  没有这个数字，“合规”是否有效无法判断。

**证据位置**
- 论文：§5.10（X2 blocker）、§7.7（semantic model / inference proof 两条）、§5.5 的
  `\need`（组合成本未验证）。
- 计划/脚本：[`plan-bhv.md`](../plan-bhv.md) P0-09/P0-10；[`plan-m2-m6.md`](../plan-m2-m6.md) M2-03；
  `bench/bench_k_entropy.py`、`bench/bench_real_llm_e2e.py`；
  [`wave2_smoke/README.md`](../../bench/results/wave2_smoke/README.md)（明示不是论文数字）。

**可补实验 / 动作**
- `X2` 最小闭环：XSTest 450 条（safe 250 / unsafe 200）+ 合规 100 + τ-bench 50；
  同一模型每 prompt 贪心 N=50、T=0.7 N=50；估计 `Guess(T|Z)`，报 `k` 分布；
  代入 `k ≥ log q + log(1/ε)` 给阈值实例。
- 真实 LLM 端到端：LangChain 回调 + 策略包 + 证书；报延迟、证明成本、策略 P/R/F1；
  用 XSTest 的 prompt 级标签评策略质量（响应级无 ground truth，要写明）。
- 语义规则：换真实分类器（XSTest 上有可报告准确率）再谈语义规则；否则保留
  “public-mode only” 并明确 proxy。
- 推理半：换真 prover 之前，不要声称“推理主导组合成本”；组合层毫秒级开销的
  结论可以保留。

**不能让步的边界**
- 没有测量就不报 `k`；不把 structural 说成 measured。
- 不把 `wave2_smoke` / stub / `--no-prove` 的数字写进论文。
- 不说语义模型可用；不说推理证明“忠实于真实模型”。
- 不说组合成本由推理主导（代理规模下不成立）。
- 没有 XSTest P/R/F1，不说策略“有效合规”。

---

## 3. 建议补的实验（按决策价值排序）

| 顺序 | 实验 | 解决哪条 | 资源 | 验收判据 | 失败 fallback |
|---:|---|---|---|---|---|
| 1 | **X1b**：post-NFA-fix 云机 `groth16`/`plonk` + 隐私面 + 规模矩阵 | R2/R3/R4 | 64–128 GB 云机 | ≥3 规则 × 10k 可证；隐私面无 `spec_canonical`/响应明文；表标 binary sha/vkey | 改标题 “Succinct”，删 ZK 措辞 |
| 2 | **X2**：真实 LLM `k` 分布 + 端到端 + XSTest P/R/F1 | R10/R3 | GPU/API | 贪心 `k≈0`、温度采样有分布；端到端延迟/证书/P/R/F1 可追溯 | 只保留 structural 陈述，删 `k` 依赖 |
| 3 | **E-1**：`x_U` 承诺进公开值 + 验证方重算 + 负对照 | R6 | 本地（可能需 vkey） | `x_U ≠ derive(T_U)` 必须拒绝；真证明端到端 | 继续只写弱形式，移强形式到 future work |
| 4 | **Scale-tuned**：默认 vs 调参矩阵 + 旗舰包证明 | R3 | 本地 + 云机 | `eu_ai_act_v1`/`agent_content_v1`/`pii_redaction_v1` 至少各一个真实响应 | 明确“本机可行域”，不写机器无关边界 |
| 5 | **Policy corpus**：13 包 × 参数网格 + 强分类器 + 效用验证 | R4 | 本地 | 每级 top-1/top-3/MI/utility 可复跑；L2 效用不是 0 或明确 0 | 保留 20 变体结果，标“shape only” |
| 6 | **Trace-leak**：`core` 工件恢复 `T`/`spec_canonical` 的直接实验 | R1/R3/R4 | 本地（小规模） | 给出恢复率或源级证据；不是只写“structural” | 保留源级审计，不报恢复率 |
| 7 | **Circuit-level coarsening**：L1/L2 公开值只含类别/计数 | R4 | 需改电路 + vkey | 第三方读公开值也看不到 raw rule | 明确“证书层投影”，不称电路级隐藏 |
| 8 | **Gateway**：Ed25519 guest 或 2-of-3 接入 + 链尾共识 | R5 | 云机 / circuit owner | cycles/time/mem 或接入后的证书路径 | 保持 residual trust，不推断电路成本 |
| 9 | **Final fuzz**：终版 binary 重跑差分 + parser contract 表 | R7 | 本地 | 46,320 比较 0 mismatch；Rust 对拍 0 mismatch | 保留现有 fuzz，标 binary sha |
| 10 | **Citation/page audit**：逐条核实 + 编译 PDF | R8/R9 | 本地 | 0 `\need`/`\fixme`；页数确定；无占位 bibitem | 删不可核实断言；移附录/付 MOPC |

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

### 模板 C：实验待补（X1b/X2）

> This is a `pending X1b/X2` item, not a completed result. The protocol and
> scripts are fixed (**⟨file⟩**), but the numbers require **⟨cloud/GPU⟩**.
> We will report **⟨matrix / k distribution / P-R-F1⟩** with hardware and binary
> digests, or, if the resource is not available, we will **⟨retitle / remove the
> k-dependent claim⟩**. We will not substitute smoke/stub output for paper
> numbers.

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

## 5. 不能让步的边界（合并版）

1. **ZK**：不说 `core` 是 ZK；不在 X1b 之前把标题的 ZK 当已交付；不混 pre/post-NFA vkey；
   不声称后量子。
2. **策略隐私**：不说加盐 = 策略隐私已解决；不把证书层 L1/L2 说成电路级隐藏；
   不隐藏 L2 零效用；不忽略 P-PP 权威与盐的信任。
3. **组合**：不说强形式已落地；不说组合闭合 divergent delivery；不隐藏 (c) 格。
4. **网关**：不推断电路内验签成本；不说网关已从信任根移除；不说 2-of-3 关闭截尾。
5. **真实 LLM / k**：没有测量就不报 `k`；不把 smoke/stub 当论文数字；不说语义模型
   可用；不说推理证明忠实于真实模型；不说组合成本由推理主导。
6. **规模**：不把 12 GB 默认旋钮的边界写成机器无关；不与 zkAgent 做匹配硬件的速度结论；
   不隐藏 OOM。
7. **理论**：不把标准界包装成新定理；不把三难写成不可能性定理；不删反例。
8. **引文**：不编造 bibitem；不用 ePrint 2024/813 冒充 VDR；不留 `\need{}` 进 PDF。
9. **页数**：不删 limitations/负对照省页；不把 16 页说成 12 页；不隐藏 MOPC。

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

- [ ] 标题与摘要的 ZK 措辞与 X1b 结果一致；无结果则已改 “Succinct”。
- [ ] 每张证明表标了 binary sha256、vkey、pre/post-NFA-fix。
- [ ] 801/783 tests 漂移已结清（论文附录与 `reproduce.md` 一致）。
- [ ] 所有 `\need{WP8}` 引文已核实或断言已删；无占位 bibitem。
- [ ] 页数已按 live author guide 复核；MOPC 预算已拍板。
- [ ] `wave2_smoke` / stub / `--no-prove` 没有进入论文表格。
- [ ] 策略隐私表（Table 2）逐行与 `C1.md` 的通道状态一致。
- [ ] E-1 仍是弱形式（若未实现），且 §5.5/§7.5 的措辞一致。
- [ ] 四格负对照、OOM 行、L2 零效用、issuance 0.0000 都还在。
