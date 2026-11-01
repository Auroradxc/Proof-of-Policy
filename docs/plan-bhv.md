# BHV 改造任务计划（2026-11-01 立）

> **目标**：把 PoP 从「系统 + 若干 remark」改造成
> **「一般 certificate-binding 框架（BHV）+ 构造性实例」**，并按 P0 / P1 / P2 落地。
>
> **关联文档**：[`certificate-binding-framework.md`](certificate-binding-framework.md)（理论底稿）、
> [`security-model.md`](security-model.md)（实现安全模型）、
> [`tdsc-writing-plan.md`](tdsc-writing-plan.md)（论文写作规格）、
> [`../paper/tdsc-paper.tex`](../paper/tdsc-paper.tex)（论文正文）。
>
> **资源标记**：
> - `[LOCAL]` 本机可做（纯 Python / 现有 SP1 `core` 档）。
> - `[CLOUD]` 需要 **64–128 GB 内存、32+ vCPU** 的云机（groth16/plonk、大规模证明矩阵）。
> - `[GPU/API]` 需要 24 GB+ GPU 或真实模型 API（Llama-8B 多次采样、真实 LLM 端到端）。
> - `[CLOUD-OPT]` 本机可起步，但完整结论需要云机（DoS n=400、跨系统基线、TEE 对照）。

---

## 0. 范围与不做什么

**做**：

1. 把响应 / 请求 / **策略**三个面收进 BHV 框架（定理 A–F）；
2. 让标题里的 “Zero-Knowledge” 有交付档（groth16/plonk + 隐私面表）；
3. 真实 LLM 端到端 + 实测猜测熵 `k`；
4. 策略侧从“泄露表”升级为“带盐承诺 + 披露层级 + 推断攻击”；
5. 组合 / 签发 / 覆盖的边界从 remark 升级为定理 + 负对照实验；
6. 论文按 16–18 页重写（TDSC 允许最多 18 页，超出 12 页按 $200/页）。

**不做 / 明确降级**：

- 不证真实 LLM 的推理完整性（除非 P2-02 交付；否则组合只证机制）；
- 不做递归聚合（验证成本仍是 `O(N)`）；
- 不做生产级 HSM/TLS/主网部署（只在 Limitations 写清）；
- 不把标准猜测界包装成新定理（见框架文档 §14）。

---

## 1. 最小可交付（M0 / M1）

| 编号 | 交付物 | 状态 | 位置 |
|---|---|---|---|
| M0-1 | BHV 框架文档（D1–D8、定理 A–F、实例化表、证明债） | ✅ 2026-11-01 | [`certificate-binding-framework.md`](certificate-binding-framework.md) |
| M0-2 | 本任务计划（含云资源标记） | ✅ 2026-11-01 | 本文件 |
| M1-1 | `Policy.policy_nonce` + 规范字节按非空 nonce 纳入哈希 | ✅ 2026-11-01 | `policydsl/core/model.py`、`policydsl/core/compile.py` |
| M1-2 | 带盐承诺原语（生成 / 附加 / 校验） | ✅ 2026-11-01 | `policydsl/privacy/policy_commit.py` |
| M1-3 | 策略枚举攻击基准（无盐恢复 / 有盐失败） | ✅ 2026-11-01 | `bench/bench_policy_leak.py` |
| M1-4 | 单元测试 + 回归 | ✅ 2026-11-01 | `tests/test_policy_commit.py` |

**M1 验收判据**（必须逐条实跑）：

```bash
# 1) 新增测试
python3 -m unittest tests.test_policy_commit -v

# 2) 现有 7 个策略包的 policy_hash 不变（验收基线）
python3 -m unittest tests.test_acceptance_baseline tests.test_loader_parity -v

# 3) 判定 / 证书 / 多方切片不回归
python3 -m unittest tests.test_cross_validate tests.test_serialize \
    tests.test_multiparty tests.test_policy_binding tests.test_binding \
    tests.test_commit tests.test_cert tests.test_doc_links -v

# 4) 枚举攻击：无盐恢复成功、有盐恢复失败
python3 bench/bench_policy_leak.py --out-dir bench/results
```

**M1 已实跑结果**（2026-11-01，本机 24 核 / 11.7 GiB：

| 场景 | 结果 |
|---|---|
| 无盐枚举（2000 候选） | **恢复成功**，匹配下标 1000，56.8 ms |
| 有盐枚举（攻击者不知道盐，用错盐） | **恢复失败**，116.8 ms |
| 有盐 + 盐泄露（对照） | **恢复成功**，匹配下标 1000，58.2 ms |
| 现有 7 包 `policy_hash` | `test_acceptance_baseline` / `test_loader_parity` 全绿，未变 |
| 新增测试 | 13 例全绿；回归子集 156 例全绿（3 skip 为设计内） |

> 全量 `unittest discover` 本机 814 例中 3 例失败，**均为环境问题**（`OPENAI_API_KEY`
> 无效、`OPENAI_BASE_URL=https://api.deepseek.com` 覆盖了测试的本地 stub），
> 与本批改动无关；M1 的验收以 §1 的四条命令为准。

> **M1 的诚实边界**：加盐只关闭**证书公开值**里的 `policy_hash` 枚举通道；
> `core` 证明工件仍可能泄露 `π`，规则名 / `delegated` 仍泄露策略结构。
> 这两条分别由 M2（groth16）与 M4（披露层级）还，**不能靠 M1 宣称“策略隐私已解决”**。

---

## 2. 里程碑

| 里程碑 | 周 | 内容 | 出口判据 | 资源 |
|---|---|---|---|---|
| **M0** | W1 | 框架 + 计划 | 两篇文档落盘、链接通过 | `[LOCAL]` |
| **M1** | W1–2 | 带盐承诺原型 + 枚举攻击 + 测试 | M1 验收四条全绿 | `[LOCAL]` |
| **M2** | W2–6 | groth16/plonk 交付、隐私面、规模、真实 LLM | 至少 3 规则 × 10k 字符出 groth16；`k` 分布落地；规模曲线 | `[CLOUD]` + `[GPU/API]` |
| **M3** | W4–8 | 定理 A–F 的完整证明 + 论文 §3 重写 | 附录证明、反例、与 T1/T3 的对应表 | `[LOCAL]` |
| **M4** | W6–11 | 披露层级、策略推断、接收方 nonce、组合负对照、网关/DoS/基线/签发 | E4–E10 结果文件 | `[LOCAL]` + `[CLOUD-OPT]` |
| **M5** | W11–16 | 真语义模型、真推理、模糊测试、论文重写、引文、页数 | 16–18 页可编译稿、0 `\need{}`、引文核实 | `[GPU/CLOUD]` + `[LOCAL]` |

---

## 3. 任务总表

> **状态**：`✅` 已交付；`🚧` 进行中；`⏳` 待做；`⛔` 被外部资源阻塞。
> **依赖**：`→` 表示“必须先完成”。

### 3.1 P0（不解决不要投）

| ID | 任务 | 交付物 | 依赖 | 资源 | 验收 | 状态 |
|---|---|---|---|---|---|---|
| P0-01 | BHV 框架文档 | `docs/certificate-binding-framework.md` | — | `[LOCAL]` | D1–D8 + 定理 A–F + 证明债 | ✅ |
| P0-02 | 任务计划 + 云标记 | `docs/plan-bhv.md` | — | `[LOCAL]` | 本文件 | ✅ |
| P0-03 | 带盐策略承诺 | `policydsl/privacy/policy_commit.py` + `Policy.policy_nonce` | P0-01 | `[LOCAL]` | 现有 7 包哈希不变；有盐哈希变化 | ✅ |
| P0-04 | 策略枚举攻击基准 | `bench/bench_policy_leak.py` + `bench/results/policy_leak.*` | P0-03 | `[LOCAL]` | 无盐恢复 = 100%，有盐恢复 = 0% | ✅ |
| P0-05 | M1 测试与回归 | `tests/test_policy_commit.py` | P0-03/04 | `[LOCAL]` | 新增测试 + 现有回归全绿 | ✅ |
| P0-06 | groth16/plonk 真出证 | `bench/results/scale_groth16.md/.json` | 云机 | `[CLOUD]` | ≥3 规则 × 10k 字符可证；验证通过 | ⏳ |
| P0-07 | 隐私面探针 | `bench/results/privacy_surface.md/.json` | P0-06 | `[CLOUD]` | core 泄露 trace；groth16 无明文/无 trace | ⏳ |
| P0-08 | 真实规模重扫 | `bench/results/scale.md/.json` | 云机 | `[CLOUD]` | 6 规则 × 10k（最好 50k）字符可证 | ⏳ |
| P0-09 | 真实 LLM + 实测 `k` | `bench/results/k_entropy.md/.json` | GPU/API | `[GPU/API]` | 贪心 `k≈0`；温度采样 `k` 分布；T1 阈值实例化 | ⏳ |
| P0-10 | 真实 LLM 端到端 | `bench/results/real_llm_e2e.md/.json` | P0-09 | `[GPU/API]` | 真实模型 + LangChain；延迟/证书/策略 P/R/F1 | ⏳ |
| P0-11 | 可提交性清理 | 0 `\need{}` / 0 `\fixme{}`；引文核实；801/783/469 统一 | — | `[LOCAL]` | `grep` 计数为 0；文档漂移表结清 | ⏳ |

> **Wave 2 预启动（2026-11-01）**：X1/X2/X3 的**脚本与数据集已就绪**，见
> [`runbook-wave2.md`](runbook-wave2.md)：
> `scripts/datasets/prepare_wave2.py`（XSTest 450 + smoke 20）、
> `bench/bench_k_entropy.py`、`bench/bench_real_llm_e2e.py`、
> `bench/bench_privacy_surface.py`、`scripts/ops/check_wave2_env.py`、
> `scripts/ops/provision_cloud.sh`、`scripts/ops/run_wave2_cloud.sh`。
> P0-06/07/08/09/10 仍标 ⏳：**脚本能跑，但真实数字需要云机/GPU**；
> 本机可用 `stub` / `--no-prove` 跑通全链路（冒烟输出在
> [`../bench/results/wave2_smoke/`](../bench/results/wave2_smoke/README.md)，
> **不是论文数字**）。

### 3.2 P1（决定论文上限）

| ID | 任务 | 交付物 | 依赖 | 资源 | 验收 | 状态 |
|---|---|---|---|---|---|---|
| P1-01 | 定理 A 的形式化 | 论文 §3 + 附录 | P0-01 | `[LOCAL]` | 三难写成 Proposition + Remark；响应/策略两实例 | ⏳ |
| P1-02 | 定理 B/D 的完整证明 | 附录 A | P1-01 | `[LOCAL]` | ROM 证明、D-privacy 游戏、混合论证 | ⏳ |
| P1-03 | 定理 C/E/F 的证明 | 附录 A | P1-01 | `[LOCAL]` | 紧致性/分离/反例/不可能性 | ⏳ |
| P1-04 | 论文 §3 重写 | `paper/tdsc-paper.tex` | P1-01–03 | `[LOCAL]` | 从“两命题”改为“框架 + 三面” | ⏳ |
| P1-05 | 披露层级 L0/L1/L2 | `policydsl/privacy/` + 证书字段 | P0-03 | `[LOCAL]` | L0 规则名 / L1 类别 / L2 仅承诺可切换 | ⏳ |
| P1-06 | 策略推断攻击 | `bench/results/policy_leak.md` 扩展 | P1-05 | `[LOCAL]` | 每层 top-1/top-3 准确率 + 审计效用曲线 | ⏳ |
| P1-07 | 接收方 nonce 协议 | 证书 `challenge` 扩展 + 用户验签路径 | P0-01 | `[LOCAL]` | `f=0` / verifier-only / end-user 三场景 | ⏳ |
| P1-08 | 交付绑定实验 | `bench/results/delivery_binding.md/.json` | P1-07 | `[LOCAL]` | `f=0` 重放成功；end-user `f>0` 失败 | ⏳ |
| P1-09 | 组合负对照 | `bench/results/composition_controls.md/.json` | 现有 compose | `[LOCAL]` | 同 nonce/不同 nonce/绑 x 与否四格 | ⏳ |
| P1-10 | 电路内验签 / 阈值网关 | `bench/results/gateway_sig.md` | — | `[LOCAL]`+`[CLOUD-OPT]` | 1/10/100 回执的成本表；或 2-of-3 阈值 | ⏳ |
| P1-11 | 证明路径 DoS | `bench/results/dos_proof.md` | — | `[LOCAL]`+`[CLOUD-OPT]` | `a^n` vs `a+b` 的 prove 时间/内存 | ⏳ |
| P1-12 | 跨系统 / TEE 基线 | `bench/results/baselines.md` | — | `[CLOUD-OPT]` | 信任×延迟×大小×隐私表（measured/cited 分栏） | ⏳ |
| P1-13 | 签发 / 透明日志 | `bench/results/issuance.md` + 原型 | — | `[LOCAL]` | 不可能性 + `1-(1-p)^m` 检出曲线 | ⏳ |

### 3.3 P2（工程与叙事）

| ID | 任务 | 交付物 | 依赖 | 资源 | 验收 | 状态 |
|---|---|---|---|---|---|---|
| P2-01 | 真实语义模型 | `bench/results/semantic_real.md` | E1? | `[GPU/CLOUD]` | 真实分类器 + ezkl；准确率/证明成本 | ⏳ |
| P2-02 | 真实推理证明 | `bench/results/compose_real.md` | — | `[GPU/CLOUD]` | 小 transformer 或明确 demote | ⏳ |
| P2-03 | 差分模糊测试 | `tests/test_fuzz_*.py` + 结果 | — | `[LOCAL]` | Python↔Rust 0 mismatch；覆盖率 | ⏳ |
| P2-04 | 引文核实 | bibliography | P0-11 | `[LOCAL]` | 每条打开原文；无 `\need{}` | ⏳ |
| P2-05 | 论文重写 / 页数 | `paper/tdsc-paper.tex` | P1-04 + M2/M4 | `[LOCAL]` | 16–18 页、0 error、0 undefined ref | ⏳ |
| P2-06 | Artifact / DOI | Zenodo + Docker | P2-05 | `[LOCAL]` | 一键复现；DOI 可引 | ⏳ |

---

## 4. 云机资源清单（`[CLOUD]` / `[GPU/API]`）

### 4.1 `[CLOUD]` 证明机

| 项 | 建议 |
|---|---|
| CPU | 32+ vCPU（优先级高于 GPU） |
| 内存 | **64 GB 起步，128 GB 推荐**（groth16 本机 12 GB 会 OOM；`compressed` 本机 14 GB 已过） |
| 磁盘 | 200 GB SSD（Rust target + 证明工件 + 数据集） |
| OS | Ubuntu 22.04 x86-64（与仓库 `reproduce.md` 对齐） |
| 工具链 | Rust stable + `cargo-prove` v6.7.0 + Go ≥1.24 |
| 预算 | 约 200–400 机时；按 $0.5–1.5/机时估 **$150–600** |

### 4.2 `[GPU/API]` 真模型机

| 项 | 建议 |
|---|---|
| GPU | 24 GB VRAM（A10 / A100 40G 更好）；Llama-3.1-8B-Instruct 采样 |
| 备选 | API（GPT-4o-mini / Qwen）；预算 **$200–500** |
| 样本 | XSTest 200 + 合规 100 + τ-bench 50；每 prompt 贪心 N=50、T=0.7 N=50 |
| 产出 | `k` 分布、重执行恢复演示、端到端 P/R/F1 |

### 4.3 被云机阻塞的任务

| 任务 | 为什么必须云机 | 如果拿不到云机 |
|---|---|---|
| P0-06 groth16/plonk | 12 GB 必 OOM；16 GB 物理装不下 | 改标题为 “Succinct”；收窄全部 ZK 措辞 |
| P0-07 隐私面探针 | 需要 groth16 工件 | 只能报 `core` 泄露；不能声称隐私已交付 |
| P0-08 规模矩阵 | 6 规则 × 10k 需要 ≥64 GB | 保留 12 GB 两级台阶，但必须标“机器限制” |
| P0-09/P0-10 真模型 | 8B 采样需 GPU/API | 用小模型 + 小样本；标注限制 |
| P1-10 电路内验签 | 可选；本机可先测周期数 | 只给链下验签 + residual trust |
| P2-01 真语义模型 | ezkl 大模型可能需要内存 | 保留玩具模型 + 明确降级 |
| P2-02 真推理证明 | 小 transformer 也可能很重 | 明确 demote 为机制演示 |

---

## 5. 排期（16 周）

| 周 | 本地 | 云机 / GPU | 里程碑 |
|---|---|---|---|
| W1 | M0 文档 + M1 带盐承诺 + 枚举基准 | 申请云机/GPU 配额 | M0 / M1 |
| W2 | M1 测试 + 回归；开始 P1-01 定理 A | 云机环境搭建（SP1 v6.7.0） | M1 |
| W3–4 | P1-01–P1-03 证明；P1-05 披露层级 | P0-06 groth16 首轮 | M2 启动 |
| W5–6 | P1-04 §3 重写；P1-07 接收方 nonce | P0-07 隐私面；P0-09 `k` 采样 | — |
| W7–8 | P1-08 delivery；P1-09 composition | P0-08 规模；P0-10 端到端 | M2 收口 |
| W9–10 | P1-06 策略推断；P1-13 issuance | P1-10 网关（可选云） | M4 启动 |
| W11 | P1-11 DoS；P1-12 基线 | P2-01 语义 / P2-02 推理（如可行） | — |
| W12–13 | P2-03 模糊测试；P0-11 清理 | 云机收尾 / 复验 | — |
| W14–15 | P2-04 引文；P2-05 论文重写 | — | M5 |
| W16 | P2-06 artifact；投稿检查 | — | 投稿 |

> **并行原则**：`[LOCAL]` 任务不依赖云机；云机任务按“最长杆优先”（groth16 先跑，
> 因为它的结果决定标题与 §5 的矩阵列）。理论任务与实验任务可以并行，但论文 §3
> 必须等 P1-01–P1-03 的证明定稿后再重写。

---

## 6. 验收命令与判据（汇总）

```bash
# M1（本批）
python3 -m unittest tests.test_policy_commit -v
python3 -m unittest tests.test_acceptance_baseline tests.test_loader_parity -v
python3 -m unittest tests.test_cross_validate tests.test_serialize \
    tests.test_multiparty tests.test_policy_binding tests.test_binding \
    tests.test_commit tests.test_cert tests.test_doc_links -v
python3 bench/bench_policy_leak.py --out-dir bench/results

# M2（云机）
python3 bench/bench_scale.py --tiers core,groth16 --out-dir bench/results   # 需改脚本支持 tiers
python3 bench/bench_proofs.py --out-dir bench/results
python3 bench/bench_policy_leak.py --out-dir bench/results --full

# M3（论文）
cd paper && pdflatex "\def\SKELQUIET{}\input{tdsc-paper.tex}"   # 两遍
grep -c '\\need{' tdsc-paper.tex    # 必须为 0
grep -c '\\fixme{' tdsc-paper.tex   # 必须为 0
```

**每项实验的判据**见 `certificate-binding-framework.md` 对应定理与
`plan-bhv.md` §3 的“验收”列。

---

## 7. 风险与 fallback

| 风险 | 影响 | Fallback |
|---|---|---|
| groth16 仍 OOM/太慢 | 标题不能叫 ZK | 换 plonk / 128 GB；若仍不行，改 “Succinct” 并收窄全部措辞 |
| 真实 LLM 采样成本/限流 | P0-09/P0-10 不完整 | 本地 7B 量化 + 小样本；明确标注模型/样本量 |
| 策略枚举恢复率在真实策略库上不高 | §4 的“泄露”不显著 | 用更大的策略空间/结构化枚举；如实报告负结果，并说明小策略空间泄露更严重 |
| 真实推理证明做不出来 | 组合贡献缩水 | 明确 demote 为机制演示；不要写成端到端结论 |
| 页数超限 | 投稿成本 | TDSC 12 页常规 / 18 页上限；超出按 $200/页，预算 $800–1200；或 E11/E13 放 supplementary |
| 审稿人认为定理是标准界 | 理论新颖性不足 | 引用标准界；主张框架/三难/策略侧/分离；用 E4 的测量把定理落地 |
| 加盐被误读为“策略隐私已解决” | 审稿人抓 overclaim | 框架文档 §7.3 的两个通道表必须原样进论文；M1 明确只关闭公开值通道 |

---

## 8. 决策记录

| 日期 | 决策 | 理由 |
|---|---|---|
| 2026-11-01 | 采用 BHV 框架，论文主轴从 “two sides” 改为 “three sides” | 策略侧是当前最大的理论空位；也与 P-PP 直接对齐 |
| 2026-11-01 | 最小可交付先做“带盐承诺 + 枚举攻击”，而不是立刻改电路 | 无需改 vkey/重建 ELF；能在本机先证明“当前哈希可枚举、加盐可关闭公开值通道” |
| 2026-11-01 | 加盐放在 `Policy.policy_nonce`（规范字节里、证书里不出现） | 不改 Rust 解析（`ConstraintSpec` 未标 `deny_unknown_fields`）；现有 7 包哈希不变 |
| 2026-11-01 | cloud 任务统一标 `[CLOUD]` / `[GPU/API]` | 用户要求显式标记；见 §4 |
| 2026-11-01 | 不把“三难”写成不可能性定理 | 目前是分类 + 推论；写成 Proposition + Remark 更稳 |

---

## 9. 与论文 / 安全模型 / 写作计划的映射

| 论文位置 | 本计划任务 | 说明 |
|---|---|---|
| §1 Intro | P1-04 | 用“三难”开场；四派 → 同一张绑定表的不同行 |
| §2 System | P1-05/P1-07 | 加披露层级、接收方 nonce；与现有系统章节合并 |
| §3 Framework | P1-01–P1-04 | D1–D8 + 定理 A–F；替代现有三条命题 |
| §4 Policy-Private | P1-05/P1-06 + P0-03/04 | D-privacy + 带盐承诺 + 推断攻击曲线 |
| §5 Evaluation | P0-06–P0-10 + P1-08/P1-09 | 隐私面、规模、`k`、delivery、composition |
| §6 Related Work | P0-11 + P2-04 | 加 designated-verifier ZK、authenticated delivery、transparency logs |
| §7 Discussion | P1-13 + 现有 §7 | 组合、coverage/issuance、residual trust |
| 附录 A | P1-02/P1-03 | 完整 ROM 证明、反例、紧致性 |
| 附录 B | P2-06 | 复现 + artifact DOI |
