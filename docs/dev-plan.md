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
- [x] Agent 插桩：`policydsl/agent.py` `AgentMonitor.on_generate/on_tool_call`（框架无关钩子）+ `mock_agent()` 会话
- [x] 端到端：`scripts/issue_cert.py`（pack+response → 证明 → 证书 → 锚定）与 `scripts/verify_cert.py`（第三方：签名/policy_hash/锚定链/证明）
- [x] 测试：**81 全绿（1 skip=设计内「依赖缺失」用例）**（+test_cert/test_anchor/test_agent/test_frameworks）
- [x] **框架适配（LangChain + LangGraph）**：`langchain_adapter.py` `PoPCallbackHandler`（`on_llm_end`/`on_tool_start`/`on_tool_end`，二者共用 LangChain 回调）+ `langgraph_adapter.py` `attach`/`guard_node`/`LangGraphGuard`；`requirements-frameworks.txt` + `scripts/install_frameworks.sh` / `retry_install_frameworks.sh`（带锁、自愈）
- [x] **依赖已安装并验证（2026-09-10）**：langchain **1.4.0** / langchain-core **1.6.2** / langgraph **1.2.11** / mcp **2.2.0**，经清华 PyPI 镜像 + wheel 引导 pip 装入用户目录；真实框架测试通过：假模型回调出证（合规/违规）、**真实 Tool 回调**、真实 LangGraph `StateGraph` 节点包装
- [x] **框架侧扩展（P5G）**
  - **流式增量出证**：`PoPCallbackHandler.on_llm_new_token` 累积响应前缀，**判定变化即发部分证书**（`streaming.partial`），`on_llm_end` 发权威证书并清理流状态；离线假 token + **真实流式模型**（`GenericFakeChatModel`）双验证
  - **真实 MCP 工具**：`policydsl/mcp_adapter.py` `MCPGuard`（调用前判定参数出证；`block_on_violation=True` 时**预检拦截违规格调用**，不触达工具）；`tests/mcp_echo_server.py` 真实 stdio MCP 服务器端到端测试（会话初始化→列工具→经护栏调用→证书标注违规）
  - 测试：**100 全绿（1 skip=设计内「依赖缺失」用例）**（含 P5G/P5H 新增用例）
- [x] **框架侧再扩展（P5H）**
  - **MCP 响应侧出证**：`MCPGuard(result_monitor=…)` 对工具返回文本按内容规则判定，产出 `tool-result` 证书（`tool.phase=result`）；`block_on_result_violation=True` 时在调用后拒绝违规结果（`MCPBlocked(phase="result")`）；真实 MCP 服务器 `dump_config` 返回 `sk-…` 被标记 `no_secret`
  - **流式早停证书链**：每张流式证书带 `streaming.chain={index,prev}` 形成哈希链，`verify_chain()` 校验（可检测重排/插入/篡改）；`stop_on_violation=True` 在首次违规即发 `streaming.stop` 证书并**停止后续出证**
  - **LangGraph 全事件出证**：`LangGraphEventCertifier` 消费 `astream_events`，对 chat-model 完成与工具调用分别出证，可选把 token 块喂给 `PoPCallbackHandler` 产生增量证书；真实图端到端验证（同时产出 public 与 tool-call 证书）
- [x] **一键端到端 demo（P5I）**：`scripts/demo_e2e.py` —— 真实会话（LLM 流式链+早停、真实 MCP 参数/响应侧、含预检拦截）→ 12 张证书 → 锚定账本 →（可选）**真实 SP1 证明**；`scripts/verify_session.py` 第三方独立验证
  - 验证结果：`ledger_chain / certificates_signature / certificates_policy_hash / certificates_anchored / stream_chains(2 runs) / zk_proof` **全 PASS**（zk 分支为 SP1 证明密码学验证 outcome/vkey/hash）
  - 集成测试 `tests/test_demo_e2e.py`（`--no-prove` 秒级跑通并验证）；单测合计 **101 全绿（1 skip=设计内）**
- [x] **演示材料（P5J）**：`scripts/make_shots.py` 一键生成 `docs/demo/` 报告与截图（HTML/SVG，Pillow PNG，无需浏览器）；**复现指南** `docs/reproduce.md`（环境 → 一次合规证明 → 验证 → 故障排查），README 已链接
- 与计划的偏差（已记）：LangChain/LangGraph 适配与真实框架测试均已就绪；链上锚定 → file 账本后端（离线可验），RPC 后端留接口

**Phase 5 验收（对照 8 周计划 W6）**
| 标准 | 结果 |
|---|---|
| 证书规范 `{π版本, 电路hash, 响应承诺, 证明, ts}` | ✅ `policy_hash`≈电路/策略绑定；`binding.proof_sha256`+`vkey_hash`；`outcome` 含响应承诺(私有) |
| 第三方用证书独立验证通过 | ✅ 见 `scripts/verify_cert.py`：签名+策略绑定+锚定链+**SP1 证明密码学验证**全 PASS |
| Agent 生成路径 + 工具调用出证 | ✅ `AgentMonitor` 两条路径均产证书（工具路径标注 `zk:false`） |
| EU AI Act Art.12/13 | ✅ 证书携带 `ai_act.art12_record_keeping/art13_transparency`，映射见 `docs/eu-ai-act-mapping.md` |

### P7 · 收尾增强（A/B/C 三项均已交付）
- [x] **P7-a verifier-only 审计路径**：`pop-verify`（仅 `sp1-verifier`，免构造证明器）+ `--proof-mode compressed`（默认仍 core）+ 验证边车 + 证书 `public_values_sha256`；快路径选择已单测。**内存结论：compressed 与 groth16 均 OOM（峰值 11.0 / 11.07 GB，本机 12 GB）→ 采用选项 B**：fixture 交 ≥16 GB 机器/CI（`scripts/make_audit_proof.sh`），用例自动跳过；已加 `.github/workflows/ci.yml`（跑快测）
- [x] **P7-b format/budget/tool 规则入电路**：请求扩展「响应+工具轨迹」；`FormatCheck`（json/int/float 规范子集）/`ToolArgGuard`（含 tools 限定）/`BudgetBound`（calls/tokens）在 `pop-types::evaluate` 判定；跨层证据串逐字一致；`AgentMonitor` 工具路径 `zk:true`；`tests/test_rules_incircuit.py`(8) + cross_validate **14 向量（host 14/14 + 真实证明 14/14 PASS）**
- [x] **P7-c 链上锚定 RPC 后端**（2026-09-10 完成，foundry 1.8.1 装好、真跑本地 Anvil 端到端 PASS）
  - 合约：`contracts/Anchor.sol`（`anchor(bytes32)` 首次即最终 + `anchoredAt/anchoredBy/isAnchored/count` + `Anchored` 事件，链上只存 32 字节摘要）；`contracts/Anchor.json`（abi+bytecode）**入库** → 运行期部署**不需要 solc/forge**
  - 后端抽象：`AnchorBackend` / `FileLedgerBackend`（默认，离线可验）/ `RpcAnchorBackend`（幂等；链上成功后回写 `meta.on_chain={tx_hash,block,chain_ts}` 到本地哈希链账本）；`backend_from_env()`；`CastRpc`（foundry `cast`，**不引入 web3.py 依赖**，可注入以便离线单测）
  - 工具：`scripts/deploy_anchor.py`、`scripts/anchor_e2e.sh`（起 anvil → 部署 → 12 张证书全部上链 → 第三方 `verify_session --rpc` → 反例对照）；`issue_cert.py`/`demo_e2e.py`/`verify_cert.py` 均支持 `--rpc/--contract`
  - 真跑修复：`pop-script --proof-out` 对 **core 也会写边车**，导致「verifier-only 快路径」误判 core（`pop-verify` exit 3）→ 抽出 `policydsl/verifier.py::prefer_verifier_only`（二进制+边车+模式∈{compressed,groth16,plonk}）并补单测
  - 验证：`scripts/anchor_e2e.sh` **ALL PASS**（`chain_anchored 12/12` + 反例 0）；`--prove` 变体真实 Core 证明上链且第三方验证 PASS；`tests/test_anchor_chain.py` 22 例全绿（无 anvil 自动 skip）
  - 边界（保留）：本地 Anvil/自备 RPC，未接公共测试网；上链用明文私钥参数（demo 用 Anvil 公开测试键），生产需 keystore/HSM

### Phase 6 · 评测 + 安全模型 + 论文（W7–W8）✅
- [x] **评测基础设施**：`pop-script --execute`（zkVM 执行、报周期数，不出证）；`PatternBlock.mode ∈ {pike,naive}` 消融开关（跨层一致，`tests/test_ablation.py`）
- [x] **成本曲线**：`bench/bench_cycles.py`（20k 字符 × 6 规则 ≈ 1.12e8 周期；字符串规则 ≈ 4.2k 周期/字符）、`bench/bench_proofs.py`（真实证明：**98–141 s / 2.7 MiB / 峰值 ~10 GB**）、`bench/bench_verify.py`（**纯验证 89.8 ms**，vkey setup 1.6 s）
- [x] **NFA 消融**：自然文本 pike ≈ 1.8× naive；**对抗输入**（a×n vs `a+b`）比值 24.5×→49.4×→99.1×（二次退化证据）
- [x] **信任-成本四象限**：`docs/quadrant.md`（ZK/TEE/形式验证/hash-chain）
- [x] **对标 zkAgent（ePrint 2026/199）**：`bench/comparison_zkagent.md` —— 二者**正交可组合**；PoP 在**低一个数量级硬件**（24 核/12 GB vs 32 核/512 GB）下：证明时间同量级（98–141 s vs 99–194 s）、证明大小相当（2.7 MiB vs LogUp 3.1 MiB）、纯验证 ~90 ms（vs 38 ms–0.42 s），并额外提供**承诺式隐私**（口径见 `bench/comparison_zkagent.md` §4.4 —— 「不公开明文」，非「内容不可恢复」）
- [x] **安全模型**：`docs/security-model.md`（完备性/健全性/内容隐私/脱敏健全性/证据不可伪造/绑定/记录完整性 + 对应实验 + “为何违规轨迹无法通过验证”）
- [x] **论文初稿**：`paper/proof-of-policy.md`（威胁模型/系统/安全模型/实验含对标/相关工作四派定位/局限）
- [x] **发布材料**：README 一键 demo + `docs/reproduce.md` 复现指南 + `scripts/make_shots.py` 截图；测试 **102+ 全绿（1 skip=设计内）**
- ⏳ 待办（延伸）：verifier-only 二进制（免构造证明器，降低验证冷启动）；链上锚定 RPC 后端；format/budget/tool 规则入电路

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
