# Proof-of-Policy · 代码开发计划（dev plan）

> 维护中 · 对应 8 周计划《方向2_Proof-of-Policy_8周计划_v2_零基础版.md》与《调研与项目计划.md》
> 文档定位：**按代码板块 × 阶段**组织，作为逐周编码 checklist。勾选即验收。

---

## 0. 当前基线（2026-09-10 实测）

- 工具链已装：Rust stable 1.98、SP1 cargo-prove **6.7.0**（+ succinct rustc 1.94 toolchain）、Go 1.25（gnark native 证明需）、protoc、cargo=rsproxy 镜像、GitHub 克隆=gh-proxy 镜像（仓库局部）。
- WSL 内存已提至 12GB（真实 CPU Core 证明峰值 ~9–10GB，原 7.6GB OOM）。
- Python 参考层 `policydsl/`：W2 三规则已实现 + 11 单测全绿；`format_check`/`tool_arg_guard`/`budget_bound` 为 stub。
- `circuits/` 骨架（Cargo.toml 按 **v3 过时注释**，不可构建）→ **Phase 0 先对齐 v6**：**已完成**（SP1 v6.7.0 workspace + 占位出证/验证跑通，2026-09-10）。
- 参考模板：`~/sp1test/fibonacci`（v6 工程，出证命令 `SP1_PROVER=cpu` 已验证）。

## 1. 代码板块

- **板块 A · Python 参考层** `policydsl/`：作者/编译/黄金判定（契约单一来源）。
- **板块 B · 策略包与规则数据** `policy_packs/` + `tests/fixtures/`。
- **板块 C · SP1 证明层** `circuits/`：program（zkVM 内判定）+ script（出证/验证）。
- **板块 D · 私有模式 + Agent + 证书**（W5–W6）。
- **板块 E · 评测 + 安全模型 + 发布**（W7–W8）。

---

## 2. 阶段与 Checklist

### Phase 0 · 工程对齐 SP1 v6 ✅ 完成
- [x] 工具链就绪（本文件 0 节）
- [x] `circuits/` 重构为 v6 workspace（program/script + vendored tempfile patch + rust-toolchain）
- [x] 占位 program 出证 + 验证跑通（仓库内）——n=42 Core 证明 ~72s 生成+验证成功

### Phase 1 · 规则原语补全（W2 收尾）✅ keyword/length 已闭环
- [x] C：SP1 program 内 keyword_block / length_bound 判定（新增 `circuits/types` 共享 ProofRequest/ProofOutput）
- [x] Python 与 SP1 交叉验证一致：`scripts/cross_validate.py`，**5/5 向量匹配**（clean/命中/大小写/超长/超短）
- [x] A：`format_check`/`tool_arg_guard`/`budget_bound` 的 Python 校验+参考判定已实现（新增 `Transcript`/`ToolCall` 结构化输入，23 单测全绿）；**入电路留待 Phase 2/3**

### Phase 2 · 字符串/PII + NFA（W3）✅
- [x] A：`policydsl/nfa.py` 最小正则→NFA 引擎（子集+ASCII；Thompson→可序列化 spec；Pike VM unanchored search）；不支持语法 fail-fast；NFA vs `re.search` **264 项语料全一致**
- [x] A：`compile.py` pattern→NFA 写入 ConstraintSpec；`evaluate.py` pattern_block 改用 NFA 判定
- [x] B：PII 规则（email/phone/secret_key/bearer_token）+ IBAN MOD-97 参考校验 → `policydsl/pii.py`，策略包 `pii_redaction_v1.json`（由 canonical 生成）
- [x] C：Rust no_std NFA 匹配器（`types::nfa_match`）+ `PatternBlock` 入 `types::evaluate`；guest 只 read→evaluate→commit
- [x] 交叉验证：host-check **7/7** + 真实证明 **7/7**（含 email/secret 命中/洁净）
- 注：MVP 走「zkVM 内跑自实现最小 NFA」保证健全性（计划允许该路线）；zk-regex 式「离线 witness 路径」留作 E4 性能优化。
- 单测：38 全绿（新增 NFA/PII 用例）

### Phase 3 · 策略编译器 + 透明模式 MVP ★ 必达（W4）✅
- [x] A：DSL→ConstraintSpec→ProofRequest 编译框架（新增 `policydsl/serialize.py`，keyword/length/pattern 单一来源映射，其余 kind fail-fast）
- [x] C：ProofRequest serde；`types::evaluate` 全约束判定（keyword/length/**pattern(NFA)**）+ commit；script 出证 + 宿主 verify；`--check` 宿主快速路径
- [x] 端到端 demo：`scripts/prove_policy.py`（pack+response → golden → host check → 真实 SP1 证明 → verify → 比对）
- [x] `eu-ai-act-v1`(合规 pass) 与 `finance-redaction-v1`(含凭证 violate) 各出证 **PASS**（0 与 1 违规，均与 golden 一致）
- [x] 单测 40 全绿（含 serialize 映射）
- ⏳ 链上 verify / REST：按计划归 Phase 5（W6），MVP 以 SP1 宿主验证为验收

**MVP 验收记录（对照 8 周计划 W4★）**
| 验收标准 | 结果 |
|---|---|
| 真实响应 → 生成证明 | ✅ eu-ai-act-v1 / finance-redaction-v1 均生成 Core 证明（~70s） |
| 独立验证 | ✅ `pop-script` 用 vkey verify；ProofOutput 与 Python golden 一致 |
| 违规定位 | ✅ 违规证明含 rule+kind+evidence（如 no_credentials/pattern_block） |
| 回归矩阵 | ✅ fast-host 9 组合跨 3 包全部一致（含 keyword+pattern、三路 PII 等**多违规**） |
| 交付 PoP v0（透明模式） | ✅（链上/证书属 Phase 5，私有模式属 Phase 4） |

### Phase 4 · 私有模式 + 选择性披露（W5）✅
- [x] A：`policydsl/commit.py`——SHA-256 承诺、canonical 证据串、mask 生成（NFA 命中片段）、redact、`private_output` golden（与 Rust 严格对齐）
- [x] B：`pop-types` 加 `Job/Outcome`、`PrivateRequest/PrivateOutput`、`sha256_hex`、`redaction_ok`、`evaluate_private`、`run_job`；program 读 Job 分发；script 支持 `private`/`mask`/`redacted` 向量
- [x] 违规定位与证据披露：只公开 `rule + kind + evidence_commitment`，**不泄露证据片段**
- [x] redaction-with-proof（VDR 式）：证明脱敏版与原版**仅在掩码位不同**（掩码位为 `*`）
- [x] Leak 实验：公开值不含响应/证据文本（仅 64-hex 承诺）；Binding/不可伪造：承诺确定性、异输入不同、掩码外篡改被拒
- [x] 私有真实证明 **PASS**（commitment/违规/脱敏与 golden 一致）；public 回归 host **7/7** + prove **7/7**
- 单测：**47 全绿**（新增 `tests/test_commit.py`）

**Phase 4 验收（对照 8 周计划 W5）**
| 标准 | 结果 |
|---|---|
| 验证者看不到全文，但能确认「违反规则 X」 | ✅ 公开 `rule/kind` + 证据承诺；响应仅承诺 |
| 泄露实验通过 | ✅ 公开输出无响应 token / 无证据明文 |
| 不可伪造/绑定 | ✅ 承诺确定性且随输入变化；篡改脱敏被拒 |
| redaction-with-proof | ✅ 简化版：仅掩码位不同（`mask_count`/`redaction_ok`/`redacted_commitment`） |

**边界增强（P4E）**
- [x] 掩码 ⊆ 命中：`mask_covered` —— 见证 spans 在电路内逐一验证为**真实匹配**，再验 `mask ⊆ spans`（越界掩码被拒；负例已验证）
- [x] 证据开示：`open_evidence`/`evidence_bundle`/`verify_bundle` —— 授权方向审计者开示证据片段并核对其承诺（篡改被拒）
- [x] 单测 52 全绿；host 与真实证明均含 `mask_covered` 字段并与 golden 一致

**边界**：掩码「⊇ 命中」未强制（允许只遮蔽部分命中）；证据片段的链上开示流程 → Phase 5。

### Phase 5 · Agent 集成 + 合规证书（W6）✅
- [x] 证书规范：`policydsl/cert.py` —— payload `{cert_version, policy(id,version), policy_hash, mode, outcome, binding{vkey_hash, proof_sha256}, ai_act, ts}` + **DSSE 信封**（HMAC-SHA256 demo 签名，可换 Ed25519）+ 稳定 `cert_digest`
- [x] 证明持久化 + 独立验证：`pop-script --proof-out`（证明+vkey meta）、`pop-script --verify --proof`（**重新从 ELF 派生 vkey 并密码学验证**）
- [x] 锚定：`policydsl/anchor.py` —— 追加式、哈希链式防篡改账本（file backend，可离线验证）；`anchor_on_chain` RPC 钩子显式未配置即报错（不假装已上链）
- [x] Agent 插桩：`policydsl/agent.py` `AgentMonitor.on_generate/on_tool_call`（框架无关钩子）+ `mock_agent()` 会话；`langgraph_adapter.py` 懒加载、缺依赖时明确报错
- [x] 端到端：`scripts/issue_cert.py`（pack+response → 证明 → 证书 → 锚定）与 `scripts/verify_cert.py`（第三方：签名/policy_hash/锚定链/证明）
- [x] 测试：**65 全绿**（+test_cert/test_anchor/test_agent）
- 与计划的偏差（已记）：LangGraph 未安装 → 提供框架无关钩子 + 适配器桩（可执行可测）；链上锚定 → file 账本后端（离线可验），RPC 后端留接口

**Phase 5 验收（对照 8 周计划 W6）**
| 标准 | 结果 |
|---|---|
| 证书规范 `{π版本, 电路hash, 响应承诺, 证明, ts}` | ✅ `policy_hash`≈电路/策略绑定；`binding.proof_sha256`+`vkey_hash`；`outcome` 含响应承诺(私有) |
| 第三方用证书独立验证通过 | ✅ 见 `scripts/verify_cert.py`：签名+策略绑定+锚定链+**SP1 证明密码学验证**全 PASS |
| Agent 生成路径 + 工具调用出证 | ✅ `AgentMonitor` 两条路径均产证书（工具路径标注 `zk:false`） |
| EU AI Act Art.12/13 | ✅ 证书携带 `ai_act.art12_record_keeping/art13_transparency`，映射见 `docs/eu-ai-act-mapping.md` |

### Phase 6 · 评测 + 安全模型 + 发布（W7–W8）
- [ ] bench/：成本曲线 + NFA/DFA 消融 + 四象限表
- [ ] docs/security-model.md（健全性/隐私/不可伪造）
- [ ] 论文初稿 + README 复现指南

---

## 3. 关键路径与优先级

```
P0 ─► P1 ─► P2 ─► P3(透明MVP★)
                 ├─► P4 ─► P5 ─► P6
```
- 里程碑硬优先级：**P3 透明模式 MVP 必达**。
- 砍单顺序：P4 私有模式 → P5 Agent 深度 → P6 消融。
- 每阶段完成把基线写入 `roadmap.md` 勾选清单。

## 4. 已知环境对策（详见记忆 zk-policy-env-setup）

- 出证 `SP1_PROVER=cpu`（v6 合法值 cpu/cuda/mock/light/network）。
- sp1-prover 6.7.0 需 `TempDir::keep()` → 本仓库 vendored `circuits/patches/tempfile`（`[patch.crates-io]`），勿直接用官方 tempfile 3.x。
- Go/GOPROXY 需在构建环境生效（native-gnark）。
