# M2–M6 计划清单（2026-11-01 立）

> **状态：计划中。** 本文件把 [`plan-bhv.md`](plan-bhv.md) 的 M2–M5 展开，并新增
> **M6（投稿与 rebuttal）**。当前 **M2 进行中**（X1/X2 在云机跑），M3/M4 部分完成，
> M5 已有第一版（16 页），M6 未开始。
>
> **用户指令**：等 X1/X2 跑完再继续；在那之前**不新开 agent、不启动新实验**。
> 本文件只列清单与验收判据。
>
> **纪律**（贯穿 M2–M6）：
> 1. **不编数字**：没有结果文件的数字不进论文；缺的写 blocker。
> 2. **vkey/binary 标注**：X1 云机结果 = pre-NFA-fix（binary `b81e6d07…`、
>    commit `c78ca67`、旧 policy vkey `0x0091b406…`）；Core 修复后 = binary
>    `7f99fdb1…`、新 vkey `0x003eb14d…`。**两套不能混表。**
> 3. **每个数字指回结果文件**：`bench/results/*.{json,md}`。
> 4. **每个改动验证通过后单独提交**；合并顺序见 [`plan-parallel.md`](plan-parallel.md)。

---

## 0. 状态快照

| 里程碑 | 状态 | 已交付 | 关键缺口 |
|---|---|---|---|
| **M2** 云机 + 真模型 | 🚧 进行中 | X1/X2 已启动；预编译 binary 已验证（core 38.1 s / 10.5 GiB） | `scale-cloud.json`、groth16 矩阵、`privacy_surface`、`k_entropy`、`real_llm_e2e` |
| **M3** 理论与契约 | 🟡 部分 | BHV 框架；定理 A–G 底稿；Core 修 G-1/V1-2 + 新 vkey | E-1 `x_U` 强绑定；P-PP 实例化；T1/T2/T3 证明债收口；801/783 |
| **M4** 剩余实验 | 🟡 部分 | C1 披露/推断/接收方 nonce；V1 组合/DoS/模糊；B1 网关/基线/签发 | 策略私密电路级/`delegated` schema；可选真语义/真推理；TEE 真机；artifact |
| **M5** 论文定稿 | 🟡 第一版 | 16 页 compsoc；0 error；0 `\fixme`；13 `\need` | groth16/`k` 数字；引文核实；页数/overfull；附录；作者元数据 |
| **M6** 投稿/rebuttal | ⬜ 未开始 | — | 投稿包、artifact DOI、mock review、rebuttal playbook |

---

## 0.1 不依赖 X1/X2 结果、可先跑的任务

> **判据**：不读 `scale-cloud.json` / `k_entropy.json` / `privacy_surface.*`，
> 不需要云机证明，也不改 vkey。可以与本机工作并行；与云机只共享“不要抢资源”这一条。

| ID | 任务 | 为什么独立 | 产出 | 资源/冲突 |
|---|---|---|---|---|
| **A1** | M3-01 定理 A–G 证明债收口（A-RO、带密钥 β、PV-2、定理 C、D-privacy） | 纯纸面；已有证明底稿 | `docs/proofs/*` 更新 + §3 修补 | `[LOCAL]`；不碰云机 |
| **A2** | M3-03 P-PP 原型（权威签名清单/注册表 + 带盐承诺开示） | 证书层；不依赖 groth16/k | 新 `policydsl/evidence/policy_registry.py` + 测试 + §4 输入 | `[LOCAL]`；不改 vkey |
| **A3** | M3-04 计数统一（801/783/469）、Ω(n²) 升定理 vs 观察 | 文档/决策 | `plan-bhv`/`modules/08`/论文注记 | `[LOCAL]` |
| **A4** | M4-03 Artifact：Dockerfile + 一键复现 + Zenodo 占位 | 不依赖云机数字 | `Dockerfile`、`scripts/ops/reproduce_*`、artifact README | `[LOCAL]`；Docker 可用 |
| **A5** | M5-02 引文核实（WP8）：逐条打开原文、补作者/页码/DOI | 不依赖实验 | `paper/tdsc-paper.tex` bibliography + `docs/citation-audit.md` | `[LOCAL]`；需网络；P 单 owner |
| **A6** | M5-03 当前稿件一致性审计（标题/摘要/§1 vs §5/§7；不编数字） | 用现有结果即可 | `docs/paper-inputs/audit.md` + §7 注记 | `[LOCAL]`；最终数字后续再核 |
| **A7** | M6-01 cover letter 草稿 | 不依赖最终数字 | `docs/submission/cover-letter.md` | `[LOCAL]` |
| **A8** | M6-03 mock review + rebuttal playbook（理论/系统/隐私三份） | 读现有稿即可 | `docs/submission/mock-reviews.md`、`rebuttal-playbook.md` | `[LOCAL]` |
| **A9** | M4-01 电路级披露 coarsening 的**设计**（不改代码） | 设计不依赖云机 | `docs/design-disclosure-levels.md` | `[LOCAL]`；**实现/重建 vkey 等 X1 结束** |
| **A10** | M4-02 透明日志一致性证明/gossip 原型 | 本地密码学/日志 | `policydsl/evidence/transparency.py` 扩展 + 测试 | `[LOCAL]`；不改 vkey |
| **A11** | M4-02 真语义模型**本地**准确率/ONNX 可行性（不跑 ezkl） | 不依赖 X1/X2 结果 | `bench/results/semantic_feasibility.md` | `[LOCAL]` CPU/8GB；不占云 GPU |
| **A12** | M4-02 电路内 Ed25519 的**设计/成本估算**（不实现） | 设计不依赖云机 | `docs/design-gateway-sig.md` | `[LOCAL]`；实现等 vkey 排期 |

### 必须等 X1/X2 的任务（不要提前做）

- §5 groth16 / scale / privacy surface 的数字列；
- §5.6 实测 `k` 与端到端；
- 标题 “Zero-Knowledge” vs “Succinct” 的最终决定（取决于 groth16）；
- 最终页数/表格布局（填数字后会变）；
- 任何“响应可恢复/隐私上界”的定量主张（需要 X2 的 `k`）；
- 云机上的新 binary 重跑 probe、真推理证明、TEE 真机、任何与 X1 抢 CPU/内存的实验。

### 推荐批次（若现在开）

- **Batch A（3 agent）**：A1 理论收口、A2 P-PP 原型、A4 Artifact/Docker。
- **Batch B（2 agent）**：A5 引文核实（resume P）、A8 mock review/rebuttal。
- **Batch C（按需）**：A9 披露设计、A11 语义可行性、A10 透明日志扩展。
- **不要开**：任何改 `circuits/` / 重建 vkey 的实现；任何占云机 CPU/GPU 的重任务。

---

## M2 — 云机证明 + 真模型（进行中）

### M2-01 X1：groth16 探针与矩阵（`[CLOUD]`）

- [ ] **M2-01a** 36610 第二个 probe 的来源/结果取证（ppid、cmdline、exe sha、mtime、verified）
- [ ] **M2-01b** groth16 单点 `200×1`：time / proof KiB / peak RSS / verified
- [ ] **M2-01c** groth16 矩阵：至少 `3 rules × 10k`，最好 `6 rules × 10k/50k`
- [ ] **M2-01d** core+groth16 规模矩阵写入 `bench/results/scale-cloud.json`
- [ ] **M2-01e** 结果表头标：host（16 核/90 GiB）、binary `b81e6d07…`、commit `c78ca67`、**pre-NFA-fix**、旧 vkey `0x0091b406…`

**验收**：`scale-cloud.json` 存在；至少一个 `groth16` 点 `verified=True`；OOM/失败点如实保留；`.md` 由 `.json` 渲染。

### M2-02 X1：隐私面（`[CLOUD]`）

- [ ] `bench/results/privacy_surface.{json,md}`：`core` 的 proof 工件 canary 命中（确定泄露）；`groth16` 交付物无 canary/无响应明文
- [ ] `response_commitment` 仍是公开可重算 oracle；重执行标 `skipped`（由 X2/E2 承担）
- [ ] 标 binary/vkey/pre-NFA-fix

**验收**：表里每档 status/hiding/canary 命中数齐全；负结果不写成“零知识已证明”。

### M2-03 X2：真实 LLM + 实测 `k`（`[GPU/CLOUD]`）

- [ ] 云机 5090 装 `transformers/accelerate`；模型 `Qwen2.5-7B-Instruct`（回退 3B/4bit）
- [ ] XSTest 50 prompts × 20 样本 × 温度 `0,0.7` → `bench/results/k_entropy.{json,md}`、`k_samples.jsonl`
- [ ] 报告 `p_max`、`k` 分布、`k < 40 bit` 比例、温度 0 的 `k≈0`
- [ ] 端到端 `bench/results/real_llm_e2e.{json,md}`：prompt 级 P/R/F1、响应违规率、拒绝代理
- [ ] 结果标模型/版本/GPU/样本数/温度；保留“标签是 prompt 级、拒绝代理是启发式”的边界

**验收**：`k_entropy.md` 有按温度汇总 + 逐 prompt 表；`real_llm_e2e.md` 有三类指标；不伪造样本。

### M2 出口判据

- [ ] X1/X2 结果已拷回本地并 commit；
- [ ] 全量回归（OpenAI 环境变量 unset）通过；
- [ ] 每份结果有 host/binary/vkey/commit 标签；
- [ ] 云机密码文件 `/tmp/pop-cloud-pass` 用完删除，建议轮换实例密码。

---

## M3 — 理论与契约收口

### M3-01 定理陈述与证明债（T1/T2/T3）

- [ ] **A-RO/guess-tight**：定理 A(1) 的公开 β 界补显式假设；正文写 heuristic，不写信息论界
- [ ] **带密钥 β**：删掉“k=0 也能隐藏”的错误措辞，改为“去掉 q 放大”
- [ ] **PV-2**：三难统一用“公开重算绑定”口径
- [ ] **定理 C**：精确化为“重放接受”界；divergent delivery 在 D2 下是 negl；不要混写
- [ ] **D-privacy**：固定同一 `T` / 相同 public T-view；补完整不可区分游戏与混合论证
- [ ] **T1/T2/T3 的 Proof debts 表**逐条关闭或降级为 Remark

### M3-02 E-1：`x_U` 强绑定

- [ ] 决定：落地 or 论文明确只证弱形式
- [ ] 若落地：证书/证明公开值加入 `x_U` 或 `commit(x_U)`；验证方重算 `IB(n,x_U)`；改电路/vkey
- [ ] 若降级：§7.5 写清“当前只证 `∃x=derive(T_U)`”，并把 E-1 列为 open

### M3-03 P-PP 实例化

- [ ] 决定：链上登记 vs 签名清单 vs 带盐承诺 + 权威开示
- [ ] 与 `policy_nonce` 的带盐承诺对齐；写清“public verifiability 交给权威”的代价
- [ ] 更新 §4 与 security-model 的 P-PP 段落

### M3-04 文档与计数

- [ ] 801 vs 783 vs 469 的测试计数统一（以实测为准）
- [ ] `docs/blockers/V1.md`/`Core.md`/`theorem-d-g.md` 的修复注记与 main 同步
- [ ] 决定 Ω(n²) 升定理还是保留为 observation

**M3 出口**：定理陈述冻结；证明债表每项有状态；E-1/P-PP 有明确决策；新 vkey 记录在案。

---

## M4 — 剩余实验与隐私闭环

### M4-01 策略私密（C1 之后）

- [ ] 电路级披露 coarsening（让公开值本身只含类别/计数/承诺）——需要 vkey 重建
- [ ] `delegated` 的类别级 schema；解除 L1/L2 的 fail-closed
- [ ] 策略推断攻击在电路级数据上重跑；给出“披露粒度 vs 审计效用”曲线

### M4-02 可选实验（按论文需要取舍）

- [ ] P2-01 真语义模型（DistilBERT/DeBERTa/Llama Guard + ezkl）或明确 demote
- [ ] P2-02 真推理证明（小 transformer）或明确 demote 为机制演示
- [ ] TEE 真机基线（B1 目前只有模拟；Nitro/SGX）
- [ ] 透明日志一致性证明/gossip（B1-split-view）或继续作为外部假设
- [ ] 网关电路内验签（B1-circuit-ed25519）或保留 residual trust

### M4-03 Artifact / 复现

- [ ] 一键复现脚本（Docker 或 `scripts/demo/demo_all.sh` + `reproduce.md`）
- [ ] Zenodo DOI；README/许可证；结果文件 checksums
- [ ] 云机/本机两套结果的口径表（不许混表）

**M4 出口**：论文每条主张都有结果文件或明确的 blocker；artifact 可独立复现。

---

## M5 — 论文定稿（IEEE CS 模板）

### M5-01 填 X1/X2 数字

- [ ] §5 groth16/scale 列：从 `scale-cloud.json` 填；若 groth16 失败，标题改 “Succinct” 并收窄 ZK 措辞
- [ ] §5.6 `k`：从 `k_entropy.json` 填；温度 0 的 `k≈0` 与阈值比例
- [ ] §7 组合成本/推理证明：按 E-1/P2-02 决策写
- [ ] 每张表 caption/正文指回结果文件

### M5-02 引文与格式

- [ ] WP8：逐条打开原文核实作者/页码/DOI；删掉未核实条目
- [ ] `\need` 清零或每项有 blocker；`\fixme` 保持 0
- [ ] 页数 ≤18；处理 overfull；图/表/算法编号
- [ ] 附录 A（证明 A–G）、附录 B（复现）；补充材料
- [ ] 作者/资助/致谢/利益冲突

### M5-03 最终一致性审计

- [ ] 标题/摘要/§1 不与 §5/§7 的负面结果矛盾
- [ ] “Zero-Knowledge” 只按交付档写；policy-zero-knowledge 的上界前置
- [ ] 不把标准界包装成新定理；不把证书层投影写成电路级隐藏
- [ ] 所有数字与 `bench/results/*` 对得上

**M5 出口**：PDF ≤18 页、0 error/undefined ref、0 `\need`/`\fixme`（或全部有 blocker）、全部数字可追溯。

---

## M6 — 投稿与 rebuttal 准备

### M6-01 投稿包

- [ ] TDSC 投稿 PDF + LaTeX 源 + 图源
- [ ] Cover letter（问题、贡献、为何 TDSC、与 zkAgent/Proof-of-Guardrail 的关系）
- [ ] 作者信息、资助、利益冲突、推荐/回避审稿人
- [ ] 页数/超长费确认（live author guidelines）

### M6-02 Artifact 与可复现

- [ ] Zenodo DOI、Docker 镜像、`reproduce.md` 一键命令
- [ ] 硬件/版本/种子/结果 checksums
- [ ] Artifact appendix（TDSC 可选徽章）

### M6-03 Mock review / rebuttal playbook

- [ ] 三份模拟审稿：系统、理论、隐私各一
- [ ] 预设反驳：理论太浅、ZK 未交付、规模太小、策略隐私没落地、网关信任、E-1、G-1/V1-2 已修
- [ ] 大修计划：云机最终 binary/vkey 重跑；补充实验清单

**M6 出口**：投稿包完整；mock review 的主要反对点都有回应；rebuttal 素材可复用。

---

## 1. 并行与依赖

```
M2 X1/X2（云机，进行中）
   │
   ├─→ M5-01 填 groth16/k 数字 ─→ M5-02/03 定稿
   │
M3 理论/契约（可与 M2 并行，等 X1/X2 后再开 agent）
   │
   ├─→ M4 策略私密/可选实验 ─→ M5
   │
M4 Artifact ─────────────────→ M6
M5 定稿 ─────────────────────→ M6 投稿
```

- **M3 不依赖云机**，但用户要求等 X1/X2；之后可先开 M3 的理论收口。
- **M4-01 电路级 coarsening** 会改 vkey，必须与 X1 的最终 binary 重跑协调；不要在 X1 当前矩阵中途做。
- **M5-01** 必须等 `scale-cloud.json` 与 `k_entropy.json`。
- **M6** 必须等 M5 定稿。

## 2. X1/X2 完成后的立即动作

1. 审 X1 的分支/结果：确认 `scale-cloud.json`、`privacy_surface.*` 的 host/binary/vkey 标签；合并。
2. 审 X2 的分支/结果：确认模型/样本/温度；合并。
3. 全量回归（OpenAI env unset）；推送。
4. 把 §5 的 `\need` 填成真实数字；重编译；报告页数/`\need` 计数。
5. 决定是否需要把新 binary `7f99fdb1…` 传云机重跑一个 groth16 probe（若论文要求最终代码；正常策略语义不变，但 vkey 不同，不能混表）。
6. 按 M3-01–M3-04 开理论收口 agent；M4 按论文需要取舍。

## 3. 资源与成本

| 项 | 估算 |
|---|---|
| AutoDL 云机 | 1×4090/5090 档 ¥1.88/h；X1 约 6–10 h、X2 约 2–4 h；总计约 ¥20–30 |
| API（若不用本地模型） | $0–20 |
| TDSC 超长费 | 16–18 页，若超 12 页按 $200/页；当前 16 页，预算 $800–1200 |
| 人力 | 1 人全职约 2–4 个月（M3–M6） |

## 4. 风险登记

| 风险 | 影响 | 应对 |
|---|---|---|
| groth16 在 90 GiB 仍 OOM/太慢 | 标题不能保留 ZK | 改 “Succinct”；论文写清交付档 |
| X1 结果用旧 binary | 与最终 vkey 不一致 | 重跑 probe 或论文标 pre-NFA-fix |
| X2 7B 下载/显存失败 | §5.6 空 | 回退 3B/4bit 或 API；标注限制 |
| E-1 不落地 | 组合只能写弱形式 | 论文降级；M3-02 明确 |
| 页数超 18 | 投稿成本 | 压 §5 表格/§6；MOPC |
| 理论仍被评“标准界” | 拒稿 | 强调框架/三难/策略侧/测量；M6 mock review 预演 |
