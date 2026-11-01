# BHV 并行执行计划（agent 分工与依赖）

> **状态：维护中（2026-11-01 立）。** 配套 [`plan-bhv.md`](plan-bhv.md)：那篇回答
> “做什么、什么顺序”，这篇回答“**哪些能同时做、谁和谁抢文件、怎么开 agent**”。
>
> **用途**：给多 agent 并行执行提供一份**依赖图 + 文件所有权 + 合并协议**。
> 每个 agent 只拿自己那一段，不跨文件写；跨文件的部分由“文件所有者”合并。
>
> **前提**：M0/M1 已落盘（BHV 框架、带盐承诺、枚举基准、13 例测试）。

---

## 0. 结论（先看这张表）

| 类别 | 能同时开吗 | 说明 |
|---|---|---|
| **理论证明 A/B/C/D/E/F/G** | ✅ 可以，拆 3 个 agent | 定理陈述已在框架文档冻结；证明写到各自的 `docs/proofs/*.md`，不抢同一文件 |
| **证书层 P1-05→P1-08** | ⚠️ 一个 agent 串行 | 都改 `cert.py` / `verify_cert.py`；拆两个 agent 会冲突 |
| **验证基准 P1-09/P1-11/P2-03** | ✅ 可以与证书层并行 | 只写新 bench/test 文件 |
| **信任/签发/基线 P1-10/P1-12/P1-13** | ✅ 可以与证书层并行 | 主要写新模块/新 bench；`anchor.py` 只有 issuance 一个 owner |
| **云机 P0-06→P0-07/P0-08** | ⚠️ 一个 agent 串行 | 同一台机器、每次证明 ~10 GiB，不能并发 |
| **GPU/API P0-09→P0-10** | ⚠️ 一个 agent 串行 | 同一 GPU/API 配额，采样任务不能并发 |
| **语义/推理 P2-01/P2-02** | ✅ 可以并行（资源允许时） | 两者不抢文件；但都吃 GPU/云 |
| **论文 P1-04 / P2-05** | ⚠️ 一个 owner 串行 | `tdsc-paper.tex` 是单文件；其他 agent 只写 `docs/paper-inputs/*.md` |
| **引文清理 P0-11/P2-04** | ✅ 可以与论文 owner 并行 | 只写 `docs/citation-audit.md`，**不碰** `tdsc-paper.tex` |

**一句话**：**理论、验证基准、信任/签发、云机、GPU 五条线可以同时开**；
证书层内部串行；论文最后单 owner 合并。

---

## 1. 依赖图

```
M1（已完成：框架 + 带盐承诺 + 枚举基准 + 测试）
│
├─ T1  定理 A + B（三难 + 泄漏剖面）──────────────┐
├─ T2  定理 C + E + F（交付/组合/签发）──────────┤
├─ T3  定理 D + G（策略隐私 + 编译器正确性）─────┤
│                                                 ├─→ P1-04 论文 §3 初稿 ─┐
├─ C1  证书层：P1-05 → P1-06（披露层级/推断）────┤                        │
│                P1-07 → P1-08（接收方 nonce/交付）┤                        │
│                                                 │                        │
├─ V1  验证基准：P1-09 组合负对照 ────────────────┤                        │
│                P1-11 证明路径 DoS ──────────────┤                        │
│                P2-03 差分模糊测试 ──────────────┤                        │
│                                                 │                        │
├─ B1  信任/签发/基线：P1-10 网关验签 ────────────┤                        │
│                       P1-12 跨系统/TEE 基线 ────┤                        │
│                       P1-13 签发/透明日志 ──────┘                        │
│                                                                          │
├─ X1  [CLOUD] P0-06 groth16 → P0-07 隐私面 → P0-08 规模 ──→ 标题 / §5 ───┤
├─ X2  [GPU/API] P0-09 实测 k → P0-10 端到端 ─────────────────→ §5.6 ────┤
└─ X3  [GPU/CLOUD] P2-01 真语义 / P2-02 真推理 ────────────────→ §7 ─────┘
                                                                          │
                                                              P2-05 论文重写
                                                                          │
                                                              P2-06 artifact/DOI
```

**关键路径**：`X1（groth16）` 与 `X2（真实 LLM）` 是最长杆；`C1（证书层）` 是本地最长杆；
`P2-05` 是唯一的最终串行点。

---

## 2. 工作流工作表

> **资源**：`[LOCAL]` 本机；`[CLOUD]` 64–128 GB / 32+ vCPU；`[GPU/API]` 24 GB GPU 或 API；
> `[CLOUD-OPT]` 本机起步、完整结论需云机。

| ID | 工作流 | 任务 | 依赖 | 资源 | 文件所有权 | 冲突风险 |
|---|---|---|---|---|---|---|
| **T1** | 理论 A/B | 三难 + 泄漏剖面：陈述、证明、反例 | M1 | `[LOCAL]` | `docs/proofs/theorem-a-b.md` | 低（只写自己的 proof 文件） |
| **T2** | 理论 C/E/F | 交付绑定、组合、签发：陈述、证明、紧致性 | M1 | `[LOCAL]` | `docs/proofs/theorem-c-e-f.md` | 低 |
| **T3** | 理论 D/G | D-privacy + 带盐承诺证明；NFA 编译器正确性 | M1 | `[LOCAL]` | `docs/proofs/theorem-d-g.md` | 低 |
| **C1** | 证书层 | P1-05 披露层级 → P1-06 策略推断 → P1-07 接收方 nonce → P1-08 交付实验 | M1 | `[LOCAL]` | `policydsl/evidence/cert.py`、`policydsl/privacy/`、`scripts/verify/verify_cert.py`、`scripts/verify/verify_session.py`、`bench/bench_policy_infer.py`、`bench/bench_delivery.py` | **高（串行内部）** |
| **V1** | 验证基准 | P1-09 组合负对照；P1-11 证明路径 DoS；P2-03 差分模糊 | 现有 compose | `[LOCAL]`+`[CLOUD-OPT]` | `bench/bench_compose_controls.py`、`bench/bench_dos.py`、`tests/test_fuzz_*.py` | 低 |
| **B1** | 信任/签发/基线 | P1-10 网关验签；P1-12 跨系统/TEE 基线；P1-13 签发/透明日志 | 现有 trace/anchor | `[LOCAL]`+`[CLOUD-OPT]` | `bench/bench_gateway_sig.py`、`bench/bench_baselines.py`、`policydsl/evidence/transparency.py`、`bench/bench_issuance.py` | 低-中（`anchor.py` 只由 P1-13 动） |
| **X1** | 云机证明 | P0-06 groth16/plonk → P0-07 隐私面 → P0-08 规模 | 云机 | `[CLOUD]` | `bench/bench_scale.py`、`bench/bench_privacy_surface.py`、`bench/results/scale*`、`privacy_surface*` | 与本地无冲突 |
| **X2** | 真模型 | P0-09 采样 + 实测 `k` → P0-10 端到端 | GPU/API | `[GPU/API]` | `bench/bench_k_entropy.py`、`bench/bench_real_llm_e2e.py`、`bench/results/k_entropy*`、`real_llm_e2e*` | 与本地无冲突 |
| **X3** | 语义/推理 | P2-01 真语义模型；P2-02 真推理证明 | GPU/云 | `[GPU/CLOUD]` | `semantic/`、`circuits/infer-program/`、`bench/bench_semantic_real.py` | 与 X1 抢 GPU/云；二选一优先 |
| **P** | 论文 | P1-04 §3/§4 初稿；P0-11 引文核实；P2-05 最终重写；P2-06 artifact | 所有实验结果 | `[LOCAL]` | `paper/tdsc-paper.tex`、`docs/paper-inputs/*.md`、`docs/citation-audit.md` | **单 owner** |

---

## 3. 三波并行

### Wave 1：现在就能开（不需要云/GPU）

建议 **6 个 agent**：

| Agent | 任务 | 产出 | 验收 |
|---|---|---|---|
| **T1** | 定理 A + B | `docs/proofs/theorem-a-b.md` | 陈述与框架文档一致；证明无 `TODO`；反例可手算 |
| **T2** | 定理 C + E + F | `docs/proofs/theorem-c-e-f.md` | 紧致性/分离/反例/不可能性各一节 |
| **T3** | 定理 D + G | `docs/proofs/theorem-d-g.md` | D-privacy 游戏 + 混合论证；NFA 正确性 |
| **C1** | P1-05 → P1-08（串行） | 披露层级、推断攻击、接收方 nonce、delivery 结果 | 每步先跑自己的测试再进下一步 |
| **V1** | P1-09 + P1-11 + P2-03 | 三份 bench/test + 结果 | 组合四格、DoS 曲线、0 mismatch |
| **B1** | P1-10 + P1-12 + P1-13 | 三份 bench + 透明日志原型 | 成本表、基线表、检出曲线 |

> **Wave 1 的 6 个 agent 互不抢文件**：T1/T2/T3 各写自己的 `docs/proofs/*.md`；
> C1 独占证书层；V1/B1 只写新 bench/test。唯一共享的是 `docs/plan-parallel.md`
> （只读）与 `bench/results/` 目录（各自写自己的文件名）。

### Wave 2：资源到位后开

| Agent | 任务 | 资源 | 前置 |
|---|---|---|---|
| **X1** | P0-06 → P0-07 → P0-08 | `[CLOUD]` | 云机开通；SP1 v6.7.0 |
| **X2** | P0-09 → P0-10 | `[GPU/API]` | GPU/API 配额 |
| **X3** | P2-01 / P2-02 | `[GPU/CLOUD]` | 与 X1/X2 协调资源 |

> **X1/X2 可以在 Wave 1 就“预启动”**：先写 provisioning 脚本、bench 骨架、数据集下载，
> 不跑重任务。这样资源一到就能直接跑。

### Wave 3：最终串行

| Agent | 任务 | 前置 |
|---|---|---|
| **P** | P2-05 论文重写 + P2-06 artifact | Wave 1/2 的结果文件全部到位；P1-04 初稿已合并 |

---

## 4. 文件所有权与合并协议

### 4.1 所有权表

| 文件 / 目录 | Owner | 其他 agent |
|---|---|---|
| `docs/certificate-binding-framework.md` | T1/T2/T3 共同只读；**P 合并** | 不许直接改；证明写 `docs/proofs/*.md` |
| `docs/proofs/theorem-a-b.md` | T1 | — |
| `docs/proofs/theorem-c-e-f.md` | T2 | — |
| `docs/proofs/theorem-d-g.md` | T3 | — |
| `policydsl/evidence/cert.py` | **C1 独占** | 不许其他人改 |
| `policydsl/privacy/challenge.py`、`policy_commit.py` | **C1 独占** | M1 已完成，C1 只扩展 |
| `scripts/verify/verify_cert.py`、`verify_session.py` | **C1 独占** | 不许其他人改 |
| `policydsl/evidence/anchor.py`、`transparency.py` | **B1 独占** | 不许其他人改 |
| `bench/bench_policy_infer.py`、`bench_delivery.py` | C1 | — |
| `bench/bench_compose_controls.py`、`bench_dos.py` | V1 | — |
| `tests/test_fuzz_*.py` | V1 | — |
| `bench/bench_gateway_sig.py`、`bench_baselines.py`、`bench_issuance.py` | B1 | — |
| `bench/bench_scale.py`、`bench_privacy_surface.py` | X1 | — |
| `bench/bench_k_entropy.py`、`bench_real_llm_e2e.py` | X2 | — |
| `semantic/`、`circuits/infer-program/` | X3 | 与 X1 协调 GPU/云 |
| `paper/tdsc-paper.tex` | **P 独占** | 其他 agent 只写 `docs/paper-inputs/*.md` |
| `docs/citation-audit.md` | P | — |
| `docs/plan-bhv.md`、`docs/plan-parallel.md` | 协调者 | 只读 |

### 4.2 合并顺序

```
T1/T2/T3（proof 文件） ─┐
C1（证书层） ───────────┼─→ 先合并 T*，再合并 C1，再合并 V1/B1，再合并 X1/X2/X3
V1/B1（bench/test） ────┤
X1/X2/X3（结果文件） ───┘
                              ↓
                         P 合并 paper + citation
```

**为什么先 T\* 后 C1**：C1 的 §4 需要引用定理 D 的最终陈述；如果 T3 先定稿，C1 的代码
字段名与论文口径可以一次对齐。若 C1 先动，也不阻塞，但 merge 时要复核 `policy_nonce`
与 D-privacy 的措辞。

### 4.3 每个 agent 的提交纪律

1. 在自己的 worktree/branch 上做（`isolation: "worktree"` 或 `bhv/<id>`）；
2. 每完成一个任务，先跑该任务的验收命令，再提交；
3. 不跑全量 `unittest discover`（会互相抢 `scripts/examples/out/` 与 Rust target 锁）；
   只跑自己的子集；合并前由协调者跑一次全量；
4. 不 `git push`；只提交到本地分支，由协调者按 §4.2 顺序合并后统一 push。

> **为什么不让 agent 自己 push**：多 agent 同时 push 同一分支会互相覆盖；
> 且全量回归需要一个统一的“合并后”状态。仓库的固定工作方式（每个改动验证通过后
> 单独提交推送）在**单 agent** 下成立；多 agent 下改为“分支提交 + 协调者合并推送”。

---

## 5. 外部资源串行化

| 资源 | 规则 |
|---|---|
| 云机（`[CLOUD]`） | **一次只跑一个证明进程**。每个 `core` 证明 ~10 GiB，groth16 更高；并发会 OOM。X1 内部串行 P0-06 → P0-07 → P0-08 |
| GPU/API（`[GPU/API]`） | X2 独占；采样任务不并发（API 限流 + 显存）。X3 若也要 GPU，与 X2 排期 |
| 本地 Rust target | `cargo build` 有目录锁；B1（P1-10）与 X3（P2-02）不要同时在同一 target 上构建。用独立 worktree 或 `CARGO_TARGET_DIR` |
| 本地集成测试 | `tests/test_demo_e2e.py` 会写 `scripts/examples/out/`；多 agent 同时跑会互相覆盖。各自用自己的 `--out-dir`，或由协调者串行跑 |
| API key | `OPENAI_API_KEY` 当前无效；X2 需要用户提供有效 key 或本地模型 |

---

## 6. Agent 配置建议

### 6.1 最小并行集（5 个 agent）

| Agent | 覆盖 | 适合 |
|---|---|---|
| **A：Theory** | T1+T2+T3（定理 A–G） | 一个理论强的人/agent 独占理论线，避免证明口径漂移 |
| **B：Certificate** | C1（P1-05→P1-08） | 证书层单 owner，避免 `cert.py` 冲突 |
| **C：Verification** | V1（P1-09/11 + P2-03） | bench/test 只写新文件 |
| **D：Trust/Issuance/Baseline** | B1（P1-10/12/13） | 新模块/新 bench |
| **E：Paper** | P1-04 初稿 + P0-11 引文 | 单 owner 改 `tdsc-paper.tex` |

云机/GPU 到位后加 **X1/X2**；语义/推理按需加 **X3**。

### 6.2 全并行集（8–10 个 agent）

| Agent | 覆盖 |
|---|---|
| T1 / T2 / T3 | 理论拆三份 |
| C1 | 证书层（内部串行） |
| V1 | 验证基准 |
| B1a / B1b | 网关验签 / 签发+基线（可拆） |
| X1 | 云机证明 |
| X2 | 真模型 |
| X3 | 语义/推理 |
| P | 论文/引文/artifact |

> **不建议再拆 C1**：`cert.py` + `verify_cert.py` + `verify_session.py` 是一组强耦合文件，
> 拆两个 agent 的冲突成本高于收益。证书层内部 P1-05→P1-08 本来就是串行依赖。

---

## 7. 现在就能开的任务（Wave 1）

按“无外部资源 + 无文件冲突”筛出来的：

- [ ] **T1**：定理 A（三难）+ B（泄漏剖面）证明
- [ ] **T2**：定理 C（交付绑定）+ E（组合）+ F（签发）证明
- [ ] **T3**：定理 D（D-privacy + 带盐承诺）+ G（NFA 正确性）证明
- [ ] **C1**：P1-05 披露层级 → P1-06 推断攻击 → P1-07 接收方 nonce → P1-08 delivery
- [ ] **V1**：P1-09 组合负对照；P1-11 证明路径 DoS；P2-03 差分模糊
- [ ] **B1**：P1-10 网关验签；P1-12 跨系统/TEE 基线；P1-13 签发/透明日志
- [ ] **P**：P1-04 §3/§4 初稿（基于已冻结的定理陈述）；P0-11 引文核实

**预启动（资源未到也能做）**：

- [ ] **X1**：写云机 provisioning 脚本 + `bench_privacy_surface.py` 骨架
- [ ] **X2**：写 `bench_k_entropy.py` 骨架 + 数据集下载/授权检查
- [ ] **X3**：评估真实语义模型/推理证明的可行性，写选型报告

---

## 8. 必须等的任务

| 任务 | 等什么 |
|---|---|
| P0-06/07/08 | 云机开通；SP1 v6.7.0；≥64 GB |
| P0-09/10 | GPU 或有效 API key |
| P2-01/02 | GPU/云；且 P2-02 可能最终降级为机制演示 |
| P1-04 最终版 | T1/T2/T3 证明定稿（初稿可先写） |
| P2-05 论文重写 | 所有实验结果 + P1-04 |
| P2-06 artifact | P2-05 |

---

## 9. 风险与防冲突规则

1. **同文件冲突**：只允许 owner 改；其他 agent 写“输入文件”（`docs/paper-inputs/*.md`）。
2. **重复实现**：开 agent 前先冻结接口（例如 P1-05 的 `PrivateViolation` 字段名、
   P1-07 的 `challenge` 字段名），否则两个 agent 会各写一套。
3. **测试互相踩**：不要并发跑全量套件；每个 agent 只跑自己的子集；集成测试由协调者串行跑。
4. **Rust 构建锁**：独立 worktree 或 `CARGO_TARGET_DIR=/tmp/<agent>`。
5. **云/GPU 费用重复**：一个资源一个 owner；X1/X2/X3 不并发抢同一台机器。
6. **git 冲突**：agent 只提交本地分支，不 push；协调者按 §4.2 顺序合并。
7. **口径漂移**：所有 agent 以 `docs/certificate-binding-framework.md` 的定义为准；
   若证明中发现陈述需要改，先改框架文档（P 审批），再改证明与代码。

---

## 10. Agent 启动 prompt 模板

给每个 agent 的 prompt 建议包含六项：

```text
任务：<ID + 一句话>
边界：只改 <文件列表>；不要改 <共享文件>；不要 push。
输入：docs/certificate-binding-framework.md（定义以它为准）、docs/plan-bhv.md §3。
产出：<文件路径 + 结果格式>。
验收：<命令 + 期望输出>。
失败时：先迭代到通过；若被外部资源阻塞，写阻塞原因到 docs/blockers/<id>.md。
```

示例（T1）：

```text
任务：T1 — 证明定理 A（BHV 三难）与定理 B（泄漏剖面）。
边界：只写 docs/proofs/theorem-a-b.md；不要改框架文档、代码、paper；不要 push。
输入：docs/certificate-binding-framework.md §3–§5、docs/security-model.md §4.5、
      docs/sp1-zk-audit.md §2–§4。
产出：定理陈述、证明、反例、与 T1/T3 的对应表；若陈述需要改，写 docs/blockers/T1.md。
验收：陈述与框架文档逐字一致；证明无 TODO；反例可手算；Run `python3 -m unittest
      tests.test_doc_links` 通过（新增链接不悬空）。
```

---

## 11. 与 `plan-bhv.md` 的关系

- `plan-bhv.md`：**任务是什么、什么时候做、验收什么**（纵向计划）。
- 本文件：**哪些能并行、谁和谁抢文件、怎么开 agent**（横向执行）。
- 两者冲突时，以本文件的**文件所有权**为准；任务优先级仍以 `plan-bhv.md` 为准。
