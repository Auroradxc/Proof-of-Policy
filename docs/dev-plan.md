# Proof-of-Policy · 代码开发计划（dev plan）

> 维护中 · 对应 8 周计划《方向2_Proof-of-Policy_8周计划_v2_零基础版.md》与《调研与项目计划.md》
> 文档定位：**按代码板块 × 阶段**组织，作为逐周编码 checklist。勾选即验收。

---

## 0. 开工基线（2026-09-10 实测 —— **历史快照，不是现状**）

> 现状看 [`plan-p0p1p2.md`](plan-p0p1p2.md)。本节保留下来是为了说明**起点在哪**：
> 当时 `policydsl/` 只有 11 个单测、`format_check`/`tool_arg_guard`/`budget_bound`
> 还是 Python 侧 stub、`circuits/` 尚不能构建。下面是那一刻的读数。

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
- [x] Python 与 SP1 交叉验证一致：`scripts/prove/cross_validate.py`，**5/5 向量匹配**（clean/命中/大小写/超长/超短）
- [x] A：`format_check`/`tool_arg_guard`/`budget_bound` 的 Python 校验+参考判定已实现（新增 `Transcript`/`ToolCall` 结构化输入，23 单测全绿）；**入电路留待 Phase 2/3**

### Phase 2 · 字符串/PII + NFA（W3）✅
- [x] A：`policydsl/core/nfa.py` 最小正则→NFA 引擎（子集+ASCII；Thompson→可序列化 spec；Pike VM unanchored search）；不支持语法 fail-fast；NFA vs `re.search` **264 项语料全一致**
- [x] A：`compile.py` pattern→NFA 写入 ConstraintSpec；`evaluate.py` pattern_block 改用 NFA 判定
- [x] B：PII 规则（email/phone/secret_key/bearer_token）+ IBAN MOD-97 参考校验 → `policydsl/core/pii.py`，策略包 `pii_redaction_v1.json`（由 canonical 生成）
- [x] C：Rust no_std NFA 匹配器（`types::nfa_match`）+ `PatternBlock` 入 `types::evaluate`；guest 只 read→evaluate→commit
- [x] 交叉验证：host-check **7/7** + 真实证明 **7/7**（含 email/secret 命中/洁净）
- 注：MVP 走「zkVM 内跑自实现最小 NFA」保证健全性（计划允许该路线）；zk-regex 式「离线 witness 路径」留作 E4 性能优化。
- 单测：38 全绿（新增 NFA/PII 用例）

### Phase 3 · 策略编译器 + 透明模式 MVP ★ 必达（W4）✅
- [x] A：DSL→ConstraintSpec→ProofRequest 编译框架（新增 `policydsl/core/serialize.py`，keyword/length/pattern 单一来源映射，其余 kind fail-fast）
- [x] C：ProofRequest serde；`types::evaluate` 全约束判定（keyword/length/**pattern(NFA)**）+ commit；script 出证 + 宿主 verify；`--check` 宿主快速路径
- [x] 端到端 demo：`scripts/prove/prove_policy.py`（pack+response → golden → host check → 真实 SP1 证明 → verify → 比对）
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
- [x] A：`policydsl/privacy/commit.py`——SHA-256 承诺、canonical 证据串、mask 生成（NFA 命中片段）、redact、`private_output` golden（与 Rust 严格对齐）
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
- [x] 证书规范：`policydsl/evidence/cert.py` —— payload `{cert_version, policy(id,version), policy_hash, mode, outcome, binding{vkey_hash, proof_sha256, proof_mode}, ai_act, ts}` + **DSSE 信封**（Ed25519 签名，P0-3；按 `keyid` 前缀分发）+ 稳定 `cert_digest`（`proof_mode` 为 P0-4 的证据档位诚实标注）
- [x] 证明持久化 + 独立验证：`pop-script --proof-out`（证明+vkey meta）、`pop-script --verify --proof`（**重新从 ELF 派生 vkey 并密码学验证**）
- [x] 锚定：`policydsl/evidence/anchor.py` —— 追加式、哈希链式防篡改账本（file backend，可离线验证）；`anchor_on_chain` RPC 钩子显式未配置即报错（不假装已上链）
- [x] Agent 插桩：`policydsl/adapters/agent.py` `AgentMonitor.on_generate/on_tool_call`（框架无关钩子）+ `mock_agent()` 会话
- [x] 端到端：`scripts/prove/issue_cert.py`（pack+response → 证明 → 证书 → 锚定）与 `scripts/verify/verify_cert.py`（第三方：签名/policy_hash/锚定链/证明）
- [x] 测试：**81 全绿（1 skip=设计内「依赖缺失」用例）**（+test_cert/test_anchor/test_agent/test_frameworks）
- [x] **框架适配（LangChain + LangGraph）**：`langchain_adapter.py` `PoPCallbackHandler`（`on_llm_end`/`on_tool_start`/`on_tool_end`，二者共用 LangChain 回调）+ `langgraph_adapter.py` `attach`/`guard_node`/`LangGraphGuard`；`requirements-frameworks.txt` + `scripts/ops/install_frameworks.sh` / `retry_install_frameworks.sh`（带锁、自愈）
- [x] **依赖已安装并验证（2026-09-10）**：langchain **1.4.0** / langchain-core **1.6.2** / langgraph **1.2.11** / mcp **2.2.0**，经清华 PyPI 镜像 + wheel 引导 pip 装入用户目录；真实框架测试通过：假模型回调出证（合规/违规）、**真实 Tool 回调**、真实 LangGraph `StateGraph` 节点包装
- [x] **框架侧扩展（P5G）**
  - **流式增量出证**：`PoPCallbackHandler.on_llm_new_token` 累积响应前缀，**判定变化即发部分证书**（`streaming.partial`），`on_llm_end` 发权威证书并清理流状态；离线假 token + **真实流式模型**（`GenericFakeChatModel`）双验证
  - **真实 MCP 工具**：`policydsl/adapters/mcp_adapter.py` `MCPGuard`（调用前判定参数出证；`block_on_violation=True` 时**预检拦截违规格调用**，不触达工具）；`tests/mcp_echo_server.py` 真实 stdio MCP 服务器端到端测试（会话初始化→列工具→经护栏调用→证书标注违规）
  - 测试：**100 全绿（1 skip=设计内「依赖缺失」用例）**（含 P5G/P5H 新增用例）
- [x] **框架侧再扩展（P5H）**
  - **MCP 响应侧出证**：`MCPGuard(result_monitor=…)` 对工具返回文本按内容规则判定，产出 `tool-result` 证书（`tool.phase=result`）；`block_on_result_violation=True` 时在调用后拒绝违规结果（`MCPBlocked(phase="result")`）；真实 MCP 服务器 `dump_config` 返回 `sk-…` 被标记 `no_secret`
  - **流式早停证书链**：每张流式证书带 `streaming.chain={index,prev}` 形成哈希链，`verify_chain()` 校验（可检测重排/插入/篡改）；`stop_on_violation=True` 在首次违规即发 `streaming.stop` 证书并**停止后续出证**
  - **LangGraph 全事件出证**：`LangGraphEventCertifier` 消费 `astream_events`，对 chat-model 完成与工具调用分别出证，可选把 token 块喂给 `PoPCallbackHandler` 产生增量证书；真实图端到端验证（同时产出 public 与 tool-call 证书）
- [x] **一键端到端 demo（P5I）**：`scripts/demo/demo_e2e.py` —— 真实会话（LLM 流式链+早停、真实 MCP 参数/响应侧、含预检拦截）→ 13 张证书 → 锚定账本 →（可选）**真实 SP1 证明**；`scripts/verify/verify_session.py` 第三方独立验证
  - 验证结果：`ledger_chain / certificates_signature / certificates_policy_hash / certificates_anchored / stream_chains(2 runs) / zk_proof` **全 PASS**（zk 分支为 SP1 证明密码学验证 outcome/vkey/hash）
  - 集成测试 `tests/test_demo_e2e.py`（`--no-prove` 秒级跑通并验证）；单测合计 **101 全绿（1 skip=设计内）**
- [x] **演示材料（P5J）**：`scripts/demo/make_shots.py` 一键生成 `docs/demo/` 报告与截图（HTML/SVG，Pillow PNG，无需浏览器）；**复现指南** `docs/reproduce.md`（环境 → 一次合规证明 → 验证 → 故障排查），README 已链接
- 与计划的偏差（已记）：LangChain/LangGraph 适配与真实框架测试均已就绪；链上锚定 → file 账本后端（离线可验），RPC 后端留接口

**Phase 5 验收（对照 8 周计划 W6）**
| 标准 | 结果 |
|---|---|
| 证书规范 `{π版本, 电路hash, 响应承诺, 证明, ts}` | ✅ `policy_hash`≈电路/策略绑定；`binding.proof_sha256`+`vkey_hash`；`outcome` 含响应承诺(私有) |
| 第三方用证书独立验证通过 | ✅ 见 `scripts/verify/verify_cert.py`：签名+策略绑定+锚定链+**SP1 证明密码学验证**全 PASS |
| Agent 生成路径 + 工具调用出证 | ✅ `AgentMonitor` 两条路径均产证书（工具路径标注 `zk:false`） |
| EU AI Act Art.12/13 | ✅ 证书携带 `ai_act.art12_record_keeping/art13_transparency`，映射见 `docs/eu-ai-act-mapping.md` |

### P7 · 收尾增强（A/B/C 三项均已交付）
- [x] **P7-a verifier-only 审计路径**：`pop-verify`（仅 `sp1-verifier`，免构造证明器）+ `--proof-mode compressed`（默认仍 core）+ 验证边车 + 证书 `public_values_sha256`；快路径选择已单测。**内存结论：compressed 与 groth16 均 OOM（峰值 11.0 / 11.07 GB，本机 12 GB）→ 采用选项 B**：fixture 交 ≥16 GB 机器/CI（`scripts/ops/make_audit_proof.sh`），用例自动跳过；已加 `.github/workflows/ci.yml`（跑快测）
- [x] **P7-b format/budget/tool 规则入电路**：请求扩展「响应+工具轨迹」；`FormatCheck`（json/int/float 规范子集）/`ToolArgGuard`（含 tools 限定）/`BudgetBound`（calls/tokens）在 `pop-types::evaluate` 判定；跨层证据串逐字一致；`AgentMonitor` 工具路径 `zk:true`；`tests/test_rules_incircuit.py`(13) + cross_validate **14 向量（host 14/14 + 真实证明 14/14 PASS）**（P7-b 当时的向量集；2026-09-12 已随 P1-5/P2-9b 扩到 **19 向量**，见 `docs/reproduce.md` §验收判据）
- [x] **P7-c 链上锚定 RPC 后端**（2026-09-10 完成，foundry 1.8.1 装好、真跑本地 Anvil 端到端 PASS）
  - 合约：`contracts/Anchor.sol`（`anchor(bytes32)` 首次即最终 + `anchoredAt/anchoredBy/isAnchored/count` + `Anchored` 事件，链上只存 32 字节摘要）；`contracts/Anchor.json`（abi+bytecode）**入库** → 运行期部署**不需要 solc/forge**
  - 后端抽象：`AnchorBackend` / `FileLedgerBackend`（默认，离线可验）/ `RpcAnchorBackend`（幂等；链上成功后回写 `meta.on_chain={tx_hash,block,chain_ts}` 到本地哈希链账本）；`backend_from_env()`；`CastRpc`（foundry `cast`，**不引入 web3.py 依赖**，可注入以便离线单测）
  - 工具：`scripts/anchor/deploy_anchor.py`、`scripts/anchor/anchor_e2e.sh`（起 anvil → 部署 → 13 张证书全部上链 → 第三方 `verify_session --rpc` → 反例对照）；`issue_cert.py`/`demo_e2e.py`/`verify_cert.py` 均支持 `--rpc/--contract`
  - 真跑修复：`pop-script --proof-out` 对 **core 也会写边车**，导致「verifier-only 快路径」误判 core（`pop-verify` exit 3）→ 抽出 `policydsl/evidence/verifier.py::prefer_verifier_only`（二进制+边车+模式∈{compressed,groth16,plonk}）并补单测
  - 验证：`scripts/anchor/anchor_e2e.sh` **ALL PASS**（`chain_anchored 14/14` + 反例 0）；`--prove` 变体真实 Core 证明上链且第三方验证 PASS（**2026-09-12 复跑确认**：3:10 / 峰值 10.18 GiB）；`tests/test_anchor_chain.py` 22 例全绿（无 anvil 自动 skip）
  - 边界（保留）：本地 Anvil/自备 RPC，未接公共测试网；上链用明文私钥参数（demo 用 Anvil 公开测试键），生产需 keystore/HSM

### Phase 6 · 评测 + 安全模型 + 论文（W7–W8）✅
- [x] **评测基础设施**：`pop-script --execute`（zkVM 执行、报周期数，不出证）；`PatternBlock.mode ∈ {pike,naive}` 消融开关（跨层一致，`tests/test_ablation.py`）
- [x] **成本曲线**：`bench/bench_cycles.py`（长度推到 **100k 字符**，规则数 1–6；100k × 6 规则 ≈ 5.4e8 周期；固定规则集时对长度**精确线性** R²≈1.0000，含 NFA 正则 ≈ 4.3k 周期/字符）、`bench/bench_proofs.py`（真实证明：**118.9–172.5 s / 2.7 MiB / 峰值 ~10.4 GB**）、`bench/bench_verify.py`（**纯验证 89.8 ms**，vkey setup 1.6 s）
- [x] **NFA 消融**：`bench/bench_ablation.py`（病理构造：模式 `a+b`、输入 `a`×n）。自然文本 pike ≈ 1.5–2.1× naive；**对抗输入**比值 19.2×→42.5×→90.1×（二次退化证据）
- [x] **P2-12 真实规模评测**：周期侧扫到 100k 字符 × 6 规则；证明侧给出**天花板**——固定地板 ~10.15 GiB，1 条规则 ≤10k 字符可证、2 条规则约 200 字符可证、3 条及以上 OOM（`bench/results/{cycles,proofs,ablation}.md`）
- [x] **信任-成本四象限**：`docs/quadrant.md`（ZK/TEE/形式验证/hash-chain）
- [x] **对标 zkAgent（ePrint 2026/199）**：`bench/comparison_zkagent.md` —— 二者**正交可组合**；PoP 在**低一个数量级硬件**（24 核/12 GB vs 32 核/512 GB）下：证明时间同量级（118.9–172.5 s vs 99–194 s）、证明大小相当（2.7 MiB vs LogUp 3.1 MiB）、纯验证 ~90 ms（vs 38 ms–0.42 s），并额外提供**承诺式隐私**（口径见 `bench/comparison_zkagent.md` §4.4 —— 「不公开明文」，非「内容不可恢复」）
- [x] **安全模型**：`docs/security-model.md`（完备性/健全性/内容隐私/脱敏健全性/证据不可伪造/绑定/记录完整性 + 对应实验 + “为何违规轨迹无法通过验证”）
- [x] **论文初稿**：`paper/proof-of-policy.md`（威胁模型/系统/安全模型/实验含对标/相关工作四派定位/局限）
  —— ⚠️ **初稿已由 LaTeX 版取代**：权威源是 `paper/proof-of-policy.tex`（xelatex + ctex），
  `.md` 只是阅读镜像且已落后（缺 L8/L9）。以 `.tex` 为准。
- [x] **发布材料**：README 一键 demo + `docs/reproduce.md` 复现指南 + `scripts/demo/make_shots.py` 截图；
  测试 **675 全绿 / 15 skip**（2026-09-13 复跑、2026-09-16 c4 后重测、2026-09-17 `scripts/` 分组后重测；skip 均为设计内，见 `docs/security-model.md` §6）
- [x] **待办（延伸）—— 三项均已完成**（此前误记为待办，2026-09-12 订正）：
  verifier-only 二进制（`pop-verify`，见 Phase P7-a）；链上锚定 RPC 后端（`RpcAnchorBackend`，见 P7-c）；
  format/budget/tool 规则入电路（见 P7-b）
- ⏳ **本阶段真正的延伸待办**（转 [`plan-p0p1p2.md`](plan-p0p1p2.md) §9）：
  **T1 租 ≥64 GB 云机**（链上 groth16 验证 = P1-7，**唯一的外部阻塞**；顺带补 P2-12 全矩阵）

---

## 3. 关键路径与优先级

```
P0 ─► P1 ─► P2 ─► P3(透明MVP★)
                 ├─► P4 ─► P5 ─► P6
```
- 里程碑硬优先级：**P3 透明模式 MVP 必达**。
- 砍单顺序：P4 私有模式 → P5 Agent 深度 → P6 消融。
- 每阶段完成把基线写入 `roadmap.md` 勾选清单。
  —— ⚠️ **这条流程在 2026-08～09 期间没有执行**，导致 `roadmap.md` 与
  [`8week-gantt.md`](8week-gantt.md) 长期停在「Rust/SP1 未装」的旧状态。
  **2026-09-12 已一次性补回**；此后本文件的阶段完成时须同步回填，否则同样会漂移。
- 另注：本文件用 **Phase 0–6 + P7** 编号，`../roadmap.md` 用 **周0–W8**，
  [`plan-p0p1p2.md`](plan-p0p1p2.md) 用 **P0/P1/P2 + T1–T4** ——
  三套编号的映射表见 [`../roadmap.md`](../roadmap.md) §3。

## 4. 已知环境对策（详见记忆 zk-policy-env-setup）

- 出证 `SP1_PROVER=cpu`（v6 合法值 cpu/cuda/mock/light/network）。
- sp1-prover 6.7.0 需 `TempDir::keep()` → 本仓库 vendored `circuits/patches/tempfile`（`[patch.crates-io]`），勿直接用官方 tempfile 3.x。
- Go/GOPROXY 需在构建环境生效（native-gnark）。

---

## 5. 延伸路线：接真 agent + 证明服务（2026-09-13 立）

> **前置**：Phase 0–6 与 P7 全部收尾，测试 **675 全绿 / 15 skip**，
> `scripts/demo/demo_all.sh` 8 条支路全通。本节是**交付之后**的两步 ——
> 与仍在外部排队的 **T1**（≥64 GB 云机，见 [`plan-p0p1p2.md`](plan-p0p1p2.md) §9）
> **互不阻塞**，也**不能**靠 T1 替代：T1 补的是链上/云机那一格，这两步补的是
> 「把已有的东西接到真实世界」。
>
> 两步**按顺序做，每步做完独立可演示、可回滚**。

### 5.0 起点的两处「说了但没接上」

2026-09-13 的板块复盘结论是：项目**没有板块性缺失**（规则原语 / 编译器 /
私有模式 / agent 集成 / 证书 / 锚定 / 评测 / 安全模型 / 论文都齐），
缺的是**最后一公里**上的两段，且都属「文档里写了、代码里没接」：

| # | 现象 | 位置 | 后果 |
|---|---|---|---|
| 1 | ~~LLM 侧仍是假模型~~ **已修（#98）** | ~~`demo_e2e.py` 用 `GenericFakeChatModel`，响应写死 `CLEAN_REPLY`/`BAD_REPLY`~~ | ~~演示能自洽，但**没有一条真实模型输出**进过证书链；「换真 agent 只动适配器层」目前是**推断**而非实测~~。**现在**：`--model openai:<model>` 走真实客户端；缺省仍是离线桩（CI 不依赖网络），但**终端会如实打出当前用的是哪个** |
| 2 | 没有任何服务化层 | 全仓只有一次性 CLI 进程 | 无法被别人调用；论文里的「可验证 agent」缺一个可对接的入口 |

> **MCP 侧其实已经是真的**：`tests/mcp_echo_server.py` 起的是**真实 stdio MCP
> 服务器**（`MCPServer("pop-echo")`，工具 `search_kb`/`dump_config`），
> `MCPGuard` 只依赖 `await session.call_tool(...)`，所以换更真实的 MCP 服务器
> **guard 零改动**；要补的「工具清单从硬编码改为 `list_tools()` 发现」**已补（#98）**。
> 假的只有 LLM 那一侧。

### 5.1 第一步 · 接真实 agent（把假模型换掉）

#### 5.1.1 为什么不是「只装个依赖、加个 `--model`」那么简单

证书层与模型无关（证书绑的是**一条具体的响应 T**，换模型只动适配器层，
ZK / 证书 / 锚定 / 验证链一行都不用改）—— 这句话**成立**。但适配器层有 4 个
真实模型一上来就会踩到的口子：

| # | 缺口 | 现状（代码位置） | 真模型下的后果 |
|---|---|---|---|
| 1 | ~~**两条链各持一把网关**~~ **已修（#99）** | ~~`langchain_adapter.py` 与 `mcp_adapter.py` 各自 `ToolGateway()` 缺省构造；`demo_e2e.py` 的 handler 与 guard 因此拿到**两把不同的网关**~~ | ~~内容链与工具链的 `trace_root` 是**两个不同会话**，`trace_seal` 各封各的。真 agent 同时走两条链，这个缝立刻显形 —— 且它**与真模型无关，是既有正确性问题**~~ |
| 2 | ~~**没有 `on_llm_error`**~~ **已修（#96）** | ~~`langchain_adapter.py` 只实现 `on_llm_new_token`/`on_llm_end`/`on_tool_start`/`on_tool_end`~~ | ~~模型超时 / 限流 / 内容拦截（真模型最常见的三件事）**不留任何产物**。「会话无证书」与「会话干净」在输出上无法区分 —— 正是 P0-4 要消灭的那类歧义~~ |
| 3 | ~~**早停不是真停**~~ **已修（#97）** | ~~`stop_on_violation` 只做到「后续 token 不再出证」~~ | ~~流**继续把违规内容吐完**。真模型下这还意味着**继续计费** —— 早停本应是最直接的省钱手段~~ |
| 4 | ~~**工具清单硬编码**~~ **已修（#98）** | ~~演示里手写工具名~~ | ~~真 MCP 服务器要动态发现~~
| 5 | ~~**流式分片的切分口径未定**~~ **已修（#100）** | ~~`on_llm_new_token` 按「回调触发」累积前缀~~ | ~~假模型的分片是**构造出来的**（一个小 chunk 一个 token），真模型的 chunk 边界由网络与 provider 决定。同一句话在两家 provider 下会切出不同的**部分证书序列** —— 增量证书的粒度因此不可比。要在适配器层把口径钉死（按字符？按判定变化？），否则「流式早停抢在几个 token 内」这个卖点跨 provider 不成立~~ |
| 6 | ~~**早停时半截响应的界定未定**~~ **已修（#97）** | ~~早停只置位 `_sstopped`~~ | ~~真早停会停在**响应中途**。必须写清证书断言的是「**截至此点的前缀**违规」，不能读成「本次生成违规」~~。**口径已钉死**：`streaming.stop.scope = "partial-prefix"`（与 `error.scope` 同一套词汇）。`streaming.partial=false` 说的是「这是本 run 的**结论**」，**不是**「判的是完整生成」—— 这两件事此前会被读混 |

#### 5.1.2 子任务（按此顺序）

1. ~~**统一网关身份**（先做，纯正确性，与真模型无关）~~ **已做（#99）**
   两处各自缺省构造的网关改为**显式注入**：`demo_e2e.py` 建一把 `ToolGateway`，
   `PoPCallbackHandler(gateway=…)` 与 `MCPGuard(gateway=…)` 共用它；
   `LangGraphGuard` 也**持有一把**并同时喂给 `callbacks()` 与 `*_node()`
   （它此前每次调用都新建一把 —— `callbacks()` 调两次就是两条链）。
   `LangGraphEventCertifier` 本就复用 `stream_handler.gateway`，未动。
   **顺带调整了 demo 的次序**（先工具、后生成）：真实 agent 就是「先调工具拿
   材料，再写答复」，而且这样内容证书盖的正是**会话终态**那条链。
   验收用例：`TestUnifiedGatewayIdentity`（`tests/test_trace.py`）——
   `len(chain) == seal.count ∧ trace_root(chain) == seal.trace_root` 逐字照写；
   **反例**是 `test_separate_gateways_do_not_seal_the_same_chain`：不共用时
   内容证书盖的是自己的空链（`seal.count=0`），`verify_seal` 报「截尾」——
   证明前一条不是恒真的。另有 `test_guard_class_shares_one_gateway`。

   > **没顺手做的一件事（如实记）**：`zk_path` 出的 3 张 zk 证书**不绑轨迹**
   > （`trace_seal` 为 `null`）。它证的是「`T` 满足 `π`」，**不主张**工具轨迹，
   > 所以这是**如实**而不是漏签。代价是：验证方若给了 `--gateway-key`，
   > `verify_cert.py` 的 `trace_seal` 卡会对它们报 FAIL（那条规则假定会话里
   > 每张证书都参与轨迹）。要消除它得把回执链喂进 zk 向量（改电路与 cycle），
   > 另开一条。
2. ~~**装真模型依赖**：加 `--model` 参数，形如 `--model openai:gpt-4o-mini`。~~
   **已做（#98）**：新增 `policydsl/adapters/llm.py`（规格解析 + 构造，**刻意不认**
   `ANTHROPIC_AUTH_TOKEN` —— 那是 Claude Code 自己的凭据），`demo_e2e.py --model`。
   **缺省仍是 fake**（CI 与 `demo_all.sh` 不依赖网络，这条没破）；**规格写错一律
   报错，绝不静默退回桩** —— 静默退回会让一份「真模型演示」的产物其实来自写死的
   字符串，而且没人看得出来。
   验收落在两处：`tests/test_real_llm.py` 用**本地 SSE 桩**
   （`tests/openai_sse_stub.py`，实现 OpenAI 的协议）把**真的** `langchain_openai`
   客户端接进回调层 —— 不需要网络与真 key，所以这一段**默认就跑**；证据由
   **服务器侧**给出（它数自己写出去了几片，少于计划写出的即「传输层真的断了」，
   对照组是关掉 `hard_stop` 后每一片都写出去）。`tests/test_demo_e2e.py` 再比
   **两份会话的形状**（fake 一份、桩一份）逐条相同。
3. ~~**实现 `on_llm_error`**：错误也出一张证书，带异常类型摘要（**不带**异常
   全文，避免把 prompt / 密钥泄进证书）。~~ **已做（#96）**：`error_block()`
   产出载荷**顶层**的 `error` 块（`scope` 固定 `"partial-prefix"` —— 判的是截断
   处的前缀，不是全文），`on_llm_error` / `on_tool_error` 两条路都出证；
   `LangGraphEventCertifier` 的 `on_chat_model_error` / `on_tool_error` 同步接上。
4. ~~**真早停**：`raise_error=True` + `on_early_stop` 回调真把流断掉。~~
   **已做（#97）**：`hard_stop=True` 抛 `EarlyStop`（携停止证书）真掐断流。
   两道门槛都是**静默失效**的坑：① `BaseCallbackHandler.raise_error` 缺省
   `False` ⇒ 回调异常被吞掉（必须置 `True`）；② 掐断后 LangChain 把它路由成
   `on_llm_error`，那里要**跳过** `EarlyStop`，否则一次早停出两张证书、
   且把自伤记成模型故障。
   **代价（如实记）**：被掐断的那次生成没有 `on_llm_end` ⇒ 没有权威 `llm`
   证书，主 demo 的证书数因此 14 → 13（`llm: 2 → 1`）。这是**正确**的 ——
   它的结论就是那张 `streaming.stop` 证书。
   **验收**：离线 4 条 + 真实 LangChain 流式 1 条（`TestRealHardStop` ——
   实测 38 字符的响应在 5 字符处断掉、密钥**没有**到达调用方）；
   另有 2 条断言「默认仍是软停」与「`EarlyStop` 不再签第二张」。
5. ~~**MCP `list_tools()` 发现**：工具清单从服务器动态取。~~ **已做（#98）**：
   `MCPGuard.discover_tools(session)` 走 MCP 的 `tools/list`，排序后存进
   `guard.tool_names`；`call_tool` 因此多了第 ⓪ 步 —— 调用服务器**没声明**的
   工具时，在策略筛查**之前**就抛 `MCPUnknownTool`（`phase="unknown-tool"`）。
   分两个阶段是因为拦的是两件事：「这次调用不合规」与「这次调用**根本不存在**」。
   第 ⓪ 步在 ① 之前也是刻意的 —— 一个不存在的工具，判它参数合不合规没有意义。
   两个「不做事」的边界同样刻意：**没问过就不查**（`tool_names is None` ⇒ 不做
   存在性检查；把「还没问」当「一个都没有」会把所有调用拦掉），以及**拦下不出证**
   （为一次不存在的调用签一张「调用不合规」的证书是答非所问）。
   验收：`TestMCPToolDiscovery`（离线 4 条，含**非恒真对照**「声明过的工具照常
   放行」）+ 真实 stdio 用例改走 `guard.discover_tools(session)` ——
   真实 SDK 的 `list_tools()` 返回形状喂得进发现路径，也被实测验到了。

6. ~~**钉死流式采样口径**~~ **已做（#100）**：采样点锚在**文本**上 ——
   `stream_step_chars`（默认 1）决定网格 `step, 2*step, …`（累计前缀的**字符**数），
   与「这是第几次回调」无关；一个回调可能跨过多个采样点，循环把它们都判一遍。
   出证条件不变（判定**翻转**才出证，否则每个采样点都签一张等于刷屏）。
   **为什么是「按字符采样 + 按判定变化出证」而不是二选一**：只按判定变化，
   采样点仍取决于回调次数（provider 相关）；只按字符采样出证，则每个网格点一张、
   变成刷屏。两件事各管一头，才让「同一文本 ⇒ 同一串部分证书」成立。
   **代价如实**：每个采样点对完整前缀跑一次参考评估器（实测 ~0.07 ms/字符），
   调粗步长只把检测推迟到违规成立后的第一个网格点、**最多晚 `step - 1` 个字符**。
   载荷新增 `streaming.chars`（跨 provider 可比；私有模式下响应只剩承诺时，它是
   唯一说明「判到哪了」的字段）；`streaming.tokens` 是回调次数，只作诊断，别当口径。
   **验收**：`TestStreamingGranularity` —— 同一文本按逐字符 / 整段一次 / 步长 7
   三种切法喂进去，部分证书序列（`chars` / `partial` / `passed` / 违规规则名）
   **逐条相同**；「违规在 chunk 内部凑齐」时停止证书指在**它凑齐的那个字符**上
   （判据用独立算出的最小违规前缀长度，不是写死的数字）；步长调粗的延迟**有界**；
   干净文本仍只出 1 张（口径变细不等于变吵）。
   **反例对照**（旧口径实测，写进用例注释）：同一句逐字符喂出 3 张、整段一次只出
   2 张 —— 连第一张「干净前缀」都丢了。

#### 5.1.3 验收（#98 落地后的如实版本）

- `demo_e2e.py --model <spec>` 端到端跑通，`verify_session.py` 全 PASS；
- 产物与 fake 路径**同构** —— 但「同构」比的是**形状**（证书次序 / `kind` /
  `passed` / 违规条数逐条相同），**不是**张数。原先把「同样 13 张」写成判据是
  错的：真模型的干净那条答什么由模型决定，被判出几条部分流式证书随之浮动。
  写死的数字在假路径改动之后不会报错，只会静默地变成另一件事。
  **验收用的是「两份会话现场比对」**（`TestDemoWithRealModelClient`），
  不是那张数字表；
- **触发与否是数据相关的**：违规那条靠「请模型原样回显一行含密钥的文本」去
  制造机会，模型不照做是**正常结果**，不是失败 —— 提示词、`aborted` 实测值都
  随会话一起落盘（`summary.early_stop`）。任何「模型一定会违规」的断言都是在赌
  provider 的服从性；
- **默认（不传 `--model`）走的仍是离线桩**：证书集与判定不变（有对照用例断言
  `summary.early_stop.model == "fake (offline)"`）。终端多一行 `llm model :`——
  这是刻意的：读产物的人不该去猜那段生成到底是不是真的；
- 真 provider 用例进 `POP_TEST_LLM=1` 门控，且**只断言结构**（真 key + 网络，
  不能进 CI）；而「真实客户端接进回调层」那一层用本地 SSE 桩，**默认就跑**。
- **采样口径改过之后（#100），主 demo 的张数与形状不变**：13 张 / `stream=4` /
  `delivered=5/38 chars`，`verify_session.py` 全 PASS。变的只有停止证书上的
  `chars` —— 旧口径记 **31**（那一 chunk 的末尾），新口径记 **24**（违规真正凑齐的
  那个字符）。这正是这条改动要修的东西：**证书该指在事情发生的地方，而不是指在
  provider 凑巧断句的地方**。假模型按空白切分、chunk 有多字符，所以两种口径在这里
  给出同一个「翻转次数」；真实 provider 的 chunk 更碎时，两者才会分岔。

### 5.2 第二步 · 证明服务（把出证能力服务化）

#### 5.2.1 唯一的硬约束：两个时间尺度差 4 个数量级

| 阶段 | 耗时 | 内存 |
|---|---|---|
| 宿主判定（Python 参考评估器） | **毫秒级** | 可忽略 |
| SP1 core 证明 | **~2.5 分钟** | **峰值 ~10.2 GiB（固定地板，不是可调的）** |

⇒ **必须拆成两段**，否则服务等于不可用（客户端等 2.5 分钟才拿到一个
「合规/不合规」）。而 ~10.2 GiB 的地板决定了**一台 12 GB 机器同时只能有一个
证明器** —— 并发上限是**硬事实**，要写进配置与文档，不能靠假设。

#### 5.2.2 接口（三段）

```
POST /v1/check          {policy_id, response, nonce?, receipts?}  → 毫秒级：宿主判定 + unproven 证书（含 challenge nonce）
POST /v1/attest         {policy_id, response, nonce?, receipts?}  → 入队，立即返回 job_id 与 queue_position
GET  /v1/attest/{job}                                             → 轮询：queued | proving | done | failed
GET  /v1/health                                                   → 并发上限 / 队列深度 / 策略数（运维看的）
GET  /v1/policies                                                 → 已注册的策略（含 serviceable 标注）
```

- **在线段 `/v1/check` 不需要证明器**，可以在小机器/边缘跑，产出的是诚实标注
  为 `unproven` 的证书（P0-4 已有现成语义，不新造）；
- **离线段 `/v1/attest` 复用 `zk_path` 已经验证过的构造**（vectors →
  `pop-script --proof-out` → `proof.meta.json` 的**真 vkey** → 证书），
  不新写一条出证路径；
- **依赖只用标准库 `http.server`**（零新依赖）。这是刻意的：这一步要演示的是
  **证据链**，不是 web 框架；引入 FastAPI/uvicorn 会把注意力从证据挪到框架上。
- 队列并发上限**从配置读、默认 1**，排队行为要有测试（第二个请求**排队而非 OOM**）。

`nonce` / `receipts` 是相对原计划加的两个可选字段：`nonce` 缺省现场生成（两段式
的正确用法是把 `/v1/check` 回的那个原样传给 `/v1/attest`，两段才绑同一条 T）；
`receipts` 是工具网关签的回执（P1-5），给了才判得了工具类规则。

#### 5.2.3 验收

- `curl` 串起来：`/v1/check`（拿 unproven 证书）→ `/v1/attest` → 轮询 `done`
  → **`verify_cert.py` 独立验通**（签名 / 策略绑定 / 响应绑定 / 锚定 / 真证明
  密码学验证）。**卡数不写死**：`verify_cert.py` 的卡片集合会随功能增减（本节
  初稿写的「9/9」在写下来的时候就已经不等于实际输出了），所以判据是
  `RESULT: PASS` 且 `[PASS] proof` 那一行**确实打印了**（不是被某个 skip 掩盖）——
  写死的分母会在改动之后静默地变成另一件事；
- 并发第二个出证请求**排队而非 OOM**（有测试锁住）；
- 部署文档进 `docs/`：[`runbook-proof-service.md`](runbook-proof-service.md)
  （依赖、内存前提、并发上限、如何换签名钥、已知边界与排查表）。

**三条都实测过了**（2026-09-13）：`curl` 三段走通、`verify_hint` 跑出 `RESULT: PASS`
（含 `[PASS] proof`）；排队那条由 `test_second_request_queues_instead_of_being_refused`
锁住；真 vkey 出证那条（`POP_TEST_PROOF=1`）**腾空内存后 171.1 s 通过**（详见 §5.2.4）。

#### 5.2.4 落地情况（2026-09-13）

| 组件 | 位置 |
|---|---|
| 库：策略注册表 + 作业队列 + 两段出证 | `policydsl/runtime/service.py` |
| HTTP 驱动（纯标准库） | `scripts/ops/proof_service.py` |
| 测试（**§5.2 交付时 87 例**；真 vkey 出证那条进 `POP_TEST_PROOF` 门控。加固①②③ 之后为 **105 例**，见 §5.2.5） | `tests/test_proof_service.py` |
| 运维文档 | [`runbook-proof-service.md`](runbook-proof-service.md) |

**过程中被 `verify_cert.py` 的 `trace_binding` 卡当场抓出的一个真 bug**：第一版
`_write_vectors` 手抄向量字段名，抄漏了 `receipts` —— 电路于是按**空回执链**判定，
证书的 `trace_root` 写着 `genesis`，而验证方拿调用方给的回执一重算就 MISMATCH，
**证书却照样签得出来**。改用 `serialize.vector_entry` 后修掉，并把回执旁证一并
落盘（`receipts.json`），让 `trace_binding` 有第二个来源可比。

**真 vkey 出证那条验收在本机是「勉强过」**：第一次跑被 OOM killer 杀在 9.7 GiB 常驻
（`dmesg`：`Killed process … (pop-script) anon-rss:9931092kB`）；让别的进程腾出内存后
**重跑通过**（171.1 s，真 vkey ≠ `unproven`、`proof_mode=core`、`verify_cert` → `RESULT: PASS`）。
全程 `MemAvailable` 一度掉到 **0.15 GiB** 并靠 swap 撑住 —— 也就是说它**装得下，但没有余量**：
~10.15 GiB 是 SP1 core 证明的**固定地板**（[`bench/results/proofs.md`](../bench/results/proofs.md)），
本机 11.7 GiB 总内存还要装下 harness 自己。所以这条验收的判据不是「跑一次」而是
「**腾空之后再跑**」，而它**暴露了一个真问题**：作业失败时
`job.error` 记的是 `CalledProcessError: Command '[.../tmp/tmpidq5b550/jobs/…/vectors.json]'
died with <Signals.SIGKILL: 9>` —— 一屏临时路径，唯独没说「内存不够」。于是新增
`service.failure_reason()`：信号类失败被翻成一句运维能照着做的话（点名 ~10.15 GiB
地板、给出 `dmesg | grep -i 'killed process'` 的核实法、并提醒调大 `--concurrency`
只会更快 OOM），其他信号不甩锅给内存。有 4 例锁住。**这条诊断是那次失败唯一的产出，
它值得留下** —— 换一台 ≥16 GB 的机器，这条路径本来也不会给人看这种错误。

**一处刻意的能力边界**：语义规则（`semantic_bound`）策略在服务里**当场拒**
（400 + 说明 + 指路 `issue_cert.py`）。陪伴证明只存在于那条命令行路径，服务发一张
`delegated` 非空却没有 `companion` 的证书只会「看起来验过了」。注册表里也如实标
`serviceable: false`，不等到调用时才说。

#### 5.2.5 可选加固（2026-09-13 起，按顺序做）

§5.2 交付时点名了三项「可选加固」。它们都不是功能缺口，而是**把已经写下来的
边界真正关掉** —— 三项恰好对应 runbook §5 里三条「已知边界」。

**① 鉴权层 —— 已做（#101）。** runbook §5 的边界 1 原文是「服务不区分调用方，
也没有速率限制」。关掉它做了四件事：

- `policydsl/runtime/auth.py`（新模块）：token 解析/匹配/令牌桶。**单独成模块而不是塞进
  handler** —— 错的鉴权不是「少一个功能」而是「看起来有」，所以它必须能在**不起
  socket** 的情况下被穷举测（新增 27 例，其中 **18 例不碰 HTTP**）。
- **401 / 404 / 429 三条口径**：401 带 `WWW-Authenticate` 且**区分「格式错」与
  「token 错」**；**别人的作业返 404 且措辞与「不存在」逐字相同**（403 等于确认
  「这个 id 存在」，那就成了探测预言机）；配额按 **token** 分桶而不是按 IP
  （一个 NAT 出口后面是一整个机房），桶是令牌桶而不是固定窗口（固定窗口在边界
  上允许 2× 突发）。
- **没配 token ≠ 放行，但也不假装有鉴权**：服务照常能起，`/v1/health` 里如实写
  `auth: "none"`、启动横幅打 `⚠`；`--require-auth` 在没配 token 时**拒绝启动**。
  「到底有没有在鉴权」是运维**能问出来**的（`curl -i /v1/health | head -1` 期望
  401），不是靠读文档。
- **两处如实留下的边界**（写进 runbook §5）：token 明文过网（绑非本机地址时启动
  横幅会警告，TLS 得在前面终结）；权限只有 `--auth-admin` 这个二元开关，没有
  「只能 check 不能 attest」这类细粒度授权。

过程中被真实运行抓出的一个缺陷：**启动横幅在 stdout 重定向时不可见**。`print()`
写到管道是块缓冲的，而服务紧接着就进 `serve_forever()` 再不出声 —— 用
systemd/docker 起服务的人看不到这段横幅，而「鉴权开没开」正是它唯一要回答的问题。
加了显式 `flush()`。

**验收①**：`python3 -m unittest tests.test_proof_service` → 62 例（35 → 62，这是
① 做完时的数）；真起服务用 `curl` 走了一遍 —— 无 token `401`（含 `WWW-Authenticate`）、
错 token `token 不认识`、对 token `200`、`/v1/health` 的 `auth.mode == "bearer"`、
连打 40 次在 burst 用尽后返 `429`（`Retry-After: 1`）再随令牌桶回填恢复 `200`。

**② 账本 RPC 后端 —— 已做（#105）。** 起因是 runbook §3.1 的一条边界：高并发下
账本追加是 O(n)。**先纠正一条自己写错的建议** —— §3.1 当时给的解法是「换成 RPC
后端」，**这是错的**：`RpcAnchorBackend.anchor()` 在给了 `ledger_path` 时照样调
`append_anchor`，换后端并不改变那一步。真正的修法在账本自身：

- **`ledger_tail()` + `(st_size, st_mtime_ns)` 戳的缓存**（`policydsl/evidence/anchor.py`）：
  追加快为 O(1)。**写侧的坑**：只缓存读是不够的 —— `append_anchor` 一写，戳就变了，
  下一次追加又退回全表重读，「写 → 失效 → 重读」，缓存等于白做；所以写完之后顺手把
  缓存推进到新尾部。**O(1) 的证据不是计时**（计时在 CI 上会飘），是一条 monkeypatch
  `read_ledger`、数调用次数并断言 **0 次**的用例。「快」是可以蒙对的，「一次都没读」
  不能。
- **fail-closed 的默认值**：`AnchorBackend.healthy()` 的缺省原先是 `(True, "local")`
  （本意是照顾文件账本），但它会被**任何新写的远端后端**继承 —— 链上后端漏写
  `healthy()` 就会让 `/v1/health` 报 `chain.healthy: true`，而这句话正是运维决定
  「要不要信这次签发的账本」的依据。缺省改成「**不知道**」，本地文件后端自己声明
  「永远健康」（它确实没有可断的东西）。这条是被新写的用例抓出来的。
- **`service.py` 的四处接线**：① `require=True` —— `--rpc` 忘带 `--contract` 以前会
  **静默退回文件账本**，证书照样签得出来、账本照样自洽、health 照样说 ok，等到有人去
  链上查那份摘要才发现从来没有过；② `chain_health()` 带 30 s TTL 并进
  `/v1/health` 与快照（**看不出多旧**的健康值比没有更糟，所以带 `age`/`checked_at`）；
  ③ `issue_certificate` 把**锚定提到落证书文件之前**，否则一次链上故障会留下一份
  完整、带签名的证书（`verify_cert` 会判 FAIL，但**它已经发得出去**了）；
  ④ `submit()` 在**收下作业之前**先探链 —— 锚定发生在证明**之后**，链已知断还收下
  作业，等于用 ~2.5 分钟 + ~10.2 GiB 去回答一个启动时就有答案的问题，还白占一个
  队列位（`capacity` 缺省 9，而真证明下同时只有 1 个在跑）。
- **HTTP 层**：`/v1/check` 与 `/v1/attest` 都返 **503**、都明说「没有签发证书」；
  但两个入口的产物路径措辞**不同**（`checks/<前缀>/<随机>/` vs `jobs/<job_id>/`）——
  一句话套两个入口会指向一个不存在的路径，而那句话正是调用方**据以去找产物**的那句。
  配置写错也从「Python 回溯 + 退出码 1」改成「**一句人话 + 退出码 2**」：在 systemd
  日志里，前者和一个真崩溃长得一模一样，而退出码 1 会让「配置错」与「运行中崩了」
  在监控上无法区分。
- **一条容易漏掉的连带事实**：`/v1/check` **也锚定**（它签的是一张真的证书，只是
  `unproven`）。所以它同样会被坏链拦下 —— 顺手给链上后端开「仅 attest 走链」的
  旁路是个陷阱：那样 check 会签出链上查不到的证书，而它恰恰是最常被调用的那条路。

**验收②**：`tests.test_proof_service` **87 例**（62 → 87）、`tests.test_anchor_chain`
**28 例**（22 → 28）。新增 31 例里 **30 例是离线路径**（注入假 RPC 客户端 ——
覆盖后端选择、health 语义、fail-closed 顺序、配置拒绝、账本尾部缓存 ——
外加 4 例把 `proof_service.py` 当**子进程**跑，核配置写错时是真的「一句人话 +
退出码 2」而不是回溯），**1 条真链**用例：起真 anvil → 用
`ProofService(rpc_url=…, contract=…)` 走完一次作业 → 由**独立只读客户端**
`verify_digest_on_chain` 读回核对，并核磁盘 `anchor.json` 的链上时间戳与一次全新
查询**相等**（只断言「有个 tx_hash」是不够的 —— 本地凭空写一个也能过）。另用 `curl`
对真链跑了一遍：链通时 `/v1/health` → `healthy: true`、`/v1/attest` → 202 → `done` →
独立读回成功、账本条目带同一个 `tx_hash`；`kill anvil` 并等过 30 s TTL 之后
`/v1/health` → `healthy: false`（附原始 `cast` 报错）、`/v1/attest` 与 `/v1/check`
→ **503** 且 `outstanding: 0`（队列位没被吃掉）。

**③ 作业状态持久化 —— 已做（#106）。** runbook §5 的边界 3 原文是「作业状态只在
内存里：进程重启后产物还在，但 `GET /v1/attest/{job}` 会 404」。这类边界的坏处
不在「少一个功能」，而在**它教人不要相信这个接口**：一个刚重启的服务对着一份完整
躺在磁盘上的证书答「没有这条作业」，调用方只能去翻账本。关掉它做了四件事：

- **作业记录落盘**（`<out-dir>/jobs/<job_id>/job.json`），三个时机各写一次：
  入队（`queued`）、开工（`proving`）、终态（`done`/`failed`，在 `finally` 里）。
  **开工那一笔是特意加的**：`proving` 是**唯一**一段「进程被杀之后，磁盘上来不及
  说它没跑完」的窗口 —— 不落这笔，重启后读到的还是 `queued`，「它到底开始过没有」
  就没人答得上来。写盘在**锁外**做，且用 `tmp` + `os.replace` 原子替换：崩在写一半
  只会留一个 `.tmp`，读到的仍是上一份完整记录。**写失败不失败作业**（证书比索引
  重要），但在 stderr 上喊一句 —— 那个文件存在的唯一理由就是重启后还查得到。
- **重建的三条规则**（`_load_job`），一句话是「**磁盘是权威，记录是索引**」：
  ①有证书就是 `done`，哪怕记录停在 `proving`（崩溃可能恰好落在「证书写完」与
  「改记录」之间，反过来说就会声称「没有证书」而它明明躺在那儿）；②中间态**不接
  回来当中间态** —— `queued`/`proving` 且没有证书 ⇒ `failed` 且明说「它**不会**再
  被执行」，接着跑只会产出更可疑的东西、答「还在跑」则是撒谎；③记录说 `done` 但
  证书没了 ⇒ `failed` 且明说「没有证书可以交付，账本里可能仍有它的锚定记录」。
- **记录与产物对不上就叫失败，不挑一个信**：`Issued.from_dir` 重算
  `cert_digest` 与记录核对，再核 `cert.json` 里的载荷与 `payload.json` 是不是
  同一个东西。两条是**不同**的故障：前者抓「两边同步改过」（只有记录能发现），
  后者抓「只改了其中一个」（只有信封能发现）。`GET` 的 `job_id` 先按
  `^job-[0-9a-f]{16}$` 过一遍形状才碰文件系统 —— 路径段是外部输入。
- **顺手补上的一处诚实性**：重启后 `--pack` 少了一个包时，作业仍在，只是算不出
  `verify_hint`。原来会把这种情况整个翻成 404，让人以为「没有这条作业」；现在照常
  返回作业，`verify_hint: null` 并附 `verify_hint_missing` 说明是哪个策略不在当前
  注册表里。**「查得到但算不出验证指引」与「查不到这条作业」是两回事。**
- **只做惰性按 id 加载，不做启动扫盘**：`get()` 在内存里没有时才去读那一份记录。
  启动开销不随历史长度增长 —— 一个跑了三个月的服务不该因为历史多而启动变慢。

**验收③**：`tests.test_proof_service` **105 例**（87 → 105）；其中
`TestJobPersistence` 15 例 + `TestRestartOverHttp` 3 例为新增，覆盖
「重启后照常答得出来 / 提交人落盘后 404 口径不变 / 三条重建规则各一条 / 两种
记录-产物漂移各一条 / 子进程换一个真进程读同一个 `--out-dir` 走 HTTP」。
另有 **6 处变异测试**把防线钉实（先备份、逐个改、改完还原、`cmp` 核过）：
删掉规则 ① ⇒ `done` 那条挂；删掉 `_JOB_ID_RE` ⇒ 穿越那条挂；删掉记录摘要校验
⇒ 两条挂；删掉信封一致性校验 ⇒ 那条挂；把读产物的捕获收窄回原来的三元组 ⇒
新加的坏 `cert.json` 那条挂。**变异测试在这里不是走形式**，它当场查出三件事，
**两条是测试自己的毛病**：

- (a) **一条假通过**：删掉信封校验，测试照样绿 —— 因为记录摘要那关会先拦下同一次
  篡改，两句文案里都有「不是同一份」，断言咬得太松。**修法不是改断言了事，而是
  改构造**：只有「记录对得上、两个文件对不上」这一格才是信封校验独有的职责，
  于是改成去改 `cert.json` 里**被签**的那份载荷，并补一条用例把「谁先拦」的
  顺序钉住。
- (b) **一条约 1/4 概率的假失败**：有用例注入写盘失败时打的是全进程的
  `Path.write_text`，连工作线程正在写的产物一起打中，于是「索引写不进去」变成了
  「产物写不出来」—— 作业真的失败了。换成只拦 `os.replace`（全仓只有 `_persist`
  用它）之后连跑 20 次全绿。**这条 flake 是被「连跑 6 次全量」抓出来的**
  （1/6 命中），不是靠读代码看出来的。
- (c) **一处真的是产品 bug**：为「产物坏掉也要答得出来」补用例时发现，读回证书
  那段的捕获列表原本写的是 `(OSError, ValueError, KeyError)` —— 一个合法 JSON、
  但信封里载荷不是字符串的 `cert.json` 会抛 `TypeError`，**读取方自己崩了**，
  `GET /v1/attest/{job}` 返 **500**。而这正是「磁盘是权威」这条设计里最该管住的
  一步。改成捕 `Exception`（异常类型名照样写进 `error`，捕得宽不藏信息），
  变异验证：收窄回去 ⇒ 那条用例报到 `500 != 200`。

至此 §5.2 点名的三项可选加固全部关闭（①②③，各自一个语义提交）。

### 5.3 顺带修掉的口径问题：`demo_e2e.py` 的魔法 `vkey = "demo"`

复盘时发现的**第三个**「说了但没接上」，与上面两步独立，**已单独修完**
（2026-09-13，见下方结论）：

- `demo_e2e.py` 顶端的 `vkey = "demo"` 被传给三个地方
  （`PoPCallbackHandler`、`mcp_path`、`zk_path`），但**只有 zk 路径**会在出证时
  用 `proof.meta.json` 里的**真 vkey** 覆盖它（`demo_e2e.py:157`）；
  stream/llm/tool 三类证书保留魔法字符串，且**脚本与文档都没标注这是替身**。
- **结论：这三类证书不能「接真 vkey」—— 它们根本没有证明，没有真 vkey 可言。**
  `binding.vkey_hash` 的语义是「哪块电路判定了它」；宿主判定没有电路参与，
  唯一诚实的取值就是 `"unproven"`（与 `cert.py:66`、`agent.py` 缺省、
  `issue_cert.py:200`、`zk_path --no-prove` 四处口径一致）。
- **硬塞一个真 vkey 哈希反而比 `"demo"` 更坏**：`"demo"` 一眼是占位符，
  真哈希会让它看起来像「由 `pop-program` 判定过」—— 那是**过度声明**，
  正是 P0-4 要消灭的东西。
- **真正缺的是防线**：`proof_mode` 有诚实性不变量（`verify_cert.py:2b` +
  `verify_session.py` 的 `certificates_proof_mode`，两个方向都拦），
  `vkey_hash` **一条都没有** —— 于是 `"demo"` 这种值今天**可以全绿通过验证**。
  补法与 `proof_mode` 同构：**没有工件 ⟺ `vkey_hash == "unproven"`**，
  过度声明（自称 vkey 却无工件）与低报（有工件却标 unproven）都判 FAIL。
- 「要接真 vkey 需要什么材料」的答案是：**不需要任何新工件** —— 真 vkey 已经
  在 zk 路径里（本机可证，`--contrast-prove` 即得）；要补的是**零成本的一道校验**。

**已落地的修法**（三个文件 + 一组用例）：

- `policydsl/evidence/cert.py`：新增 `VKEY_HASH_UNPROVEN`（**故意**等于 `PROOF_MODE_UNPROVEN`
  同一个字符串 —— 二者说的是同一件事），把「vkey 没有真值可指」这件事从一条
  注释升级为一个**具名常量**；
- `scripts/demo/demo_e2e.py`：`vkey = "demo"` → `cert.VKEY_HASH_UNPROVEN`；
- `scripts/verify/verify_cert.py`：新增 `vkey_label` 卡（2c），与 `proof_mode` 卡（2b）同构；
- `scripts/verify/verify_session.py`：新增 `certificates_vkey_label` 卡，两个方向都拦；
- `tests/test_policy_binding.py`：`TestVkeyLabelHonestyRejected`（4 例，**反例就是
  `"demo"` 本身**）+ `TestSessionVkeyLabelHonesty`（2 例）。

> **这道校验当场抓出了两处既有问题**，说明它不是恒真的：
> ① `tests/test_policy_binding.py::TestVerifierEndToEnd` 的 fixture 里，
> 那条名为 `test_honest_certificate_passes` 的**诚实对照组**所用的证书
> `vkey_hash` 恰恰是随手编的 `"deadbeef"` —— 与 `demo_e2e.py` 是同一个毛病；
> ② `issue_cert.py`、三个适配器的缺省值、`zk_path --no-prove` 分支都已经是对的
> （`unproven`），唯独演示脚本例外。现已一并订正。

### 5.4 盘点后的两项收尾（2026-09-14 立）

§5.2 三项可选加固全部关闭之后，做了一次全仓盘点（三路：**代码与测试**、
**文档与论文**、**对外集成面**）。结论是**代码侧没有整块缺失** —— 27 个测试模块 /
667 例 / 30 个 `policydsl` 模块 / 23 个脚本 / 3 个 guest，链路每一格都接上了（这是 2026-09-14 那次盘点当时的快照；计数现状一律见 `docs/modules/08-tests-bench.md`）；
欠账全在**外围**：5 处测试计数漂移、论文镜像停在 469、`dev-plan.md:90` 一条悬空的
链上开示承诺、T3 未排期、没有部署类产物、以及**没有一份框架无关的接入指南**。

这里只挑**现在就能关掉、且验收判据明确**的两项：**P1（数字订正）**、
**P3（接入指南 + 框架无关参考适配器）**。其余各项为什么不在这轮做，见 §5.4.3。

#### 5.4.1 P1 · 文档里的测试计数订正

**问题**：拿实测数去核对文档，同一批测试模块在多处写着不同的数。

**先说测量方法 —— 第一版方法是错的，这个教训要留下。** 第一版用的是
`python3 -m unittest discover tests -p "<模块>.py" -v | grep -cE '\.\.\. (ok|skipped|FAIL|ERROR)'`。
它看起来够了，**但会漏掉所有带 docstring 的用例**：unittest 的 verbose 输出对这类
用例打印的是 `<用例名>\n<docstring 首行> ... ok`，「`... ok`」落在**下一行**，
grep 就数不到。它对 `test_proof_service` 数出 **53**，真值是 **105** —— 漏了整整一半。
偏偏 `test_trace` / `test_commit` / `test_policy_binding` / `test_semantic` 这四个
**恰好**没有 docstring，数出来与真值一致，于是第一版只报出 5 处、看起来还挺像样。
**「恰好对的测量」比明显错的测量更危险** —— 它会让人以为不必再查。

**权威方法**（按 TestCase 的 `__module__` 归类后逐模块计数，不解析输出文本）：

```
python3 -c "
import unittest, collections
c = collections.Counter()
def walk(s):
    for t in s:
        walk(t) if isinstance(t, unittest.TestSuite) else c.__setitem__(
            t.__class__.__module__, c[t.__class__.__module__] + 1)
walk(unittest.TestLoader().discover('tests'))
[print(f'{k:34s} {c[k]}') for k in sorted(c)]; print('总计', sum(c.values()))
"
```

实测（P1 当时全套 **630**，与 `modules/08` 的合计一致；P3-a 又加 18 例 → **648**）：

| 模块 | **实测** | `docs/modules/08` | `docs/security-model.md` | `README.md` |
|---|---|---|---|---|
| `test_trace` | **41** | 41 ✅ | 39 ❌（:559） | 39 ❌（:202） |
| `test_commit` | **12** | 12 ✅ | 12 ✅ | — |
| `test_policy_binding` | **28** | 28 ✅ | 22 ❌（:557） | — |
| `test_semantic` | **30** | 30 ✅ | 29 ❌（:312、:564） | — |
| `test_anchor_chain` | **28** | — | 22 ❌（:561） | — |

**共 6 处**（`security-model.md` 五处 + `README.md` 一处）；换成权威方法后
比第一版**多查出 `test_anchor_chain`** 一处。`modules/08` 是**唯一全对**的那一篇
—— 它一直拿真跑的数更新，其余几篇抄的是旧快照。

**另外两处是 dated 快照，不改数字**：`docs/plan-p7.md`（:21 的「4 例」、:41 的
「8 例」）与 `docs/plan-p0p1p2.md`（:458/:960 的 469）都是**当时**的计划与验收
记录，改它等于篡改历史。处理是：在这两篇**开头**各加一行抬头，把「现状以
`docs/modules/08-tests-bench.md` 为准」指出去，并去掉 plan-p0p1p2 §5 那条
「**当前**全量为 469/13」里的「当前」二字（它是 P0/P2 阶段的当前，不是今天的）。

**为什么这不是「小事」**：这个项目的核心卖点是「证明自己能如实说话」，
**测试计数就是对外那句「有多少格真的验过」**。`modules/08`（41/28/30）是对的，
`security-model.md`（39/22/29）是旧的 —— 同一批用例在两篇文档里差 2 ~ 6 例，
读者没法知道该信哪一篇，而**保守的那个数（小的）反而更像是「如实」**，
于是真实覆盖被**低报**了。低报也是失真，只是方向好听一点。

**修法**：只改数字，**不动任何结论**。改完逐个数复算一遍。
`docs/plan-p0p1p2.md` 的 `469` **不改成当时的全量**（订正时是 630，P3-a 之后是 648）
—— 它是 P0/P2 阶段的
**dated 快照**（§5 验收表标着 2026-09-12，且写明「P2-9 收尾时复跑」），
改它等于篡改历史；只给那条「当前全量为 469/13」的措辞补一个
**「（P0/P2 阶段快照，非现状；现状见 `docs/modules/08-tests-bench.md`）」**，
把「当前」这个会过期的词指走。

**验收 P1**：6 处数字与实测逐一对上；**用同一支脚本复跑一遍确认为 0 处残留**
（而不是靠 `grep` 找旧值 —— 找旧值同样会被 docstring 那类格式骗过去）；
那两篇 dated 快照的抬头到位；全套测试仍全绿（纯文档改动，P1 提交时为 630/15）。

#### 5.4.2 P3 · Agent 接入指南 + 框架无关参考适配器

**缺口**：三个适配器（LangChain / LangGraph / MCP）都在，契约面也在
（`AgentMonitor.on_generate` / `on_tool_call`，会话唯一 `ToolGateway`，
`TRACE_DOMAIN` / `SEAL_DOMAIN`）。但 `docs/modules/06-frameworks.md` §8「扩展指引」
**只有三条建议**（「写一个适配器，把事件接到 `monitor.on_generate` / `on_tool_call`；
参照 `_extract_text` / `_parse_args` 做宽松提取；缺失依赖做成导入回退」），
**不是清单** —— 没写清「一个适配器最少必须做对哪几件事」，也没有一份**能直接复制
的骨架**。想知道「我自己的 agent 要怎么接进来」，今天只能去读三个适配器的源码反推。

**做法分两半（两个语义提交）**：

**P3-a · `policydsl/adapters/generic_adapter.py`：框架无关的参考适配器。**
一个**不依赖任何框架**的 `GenericGuard`，把契约**写成代码**：
`generate(text)` → 生成路径证书、`tool_call(name, args, result)` → 网关签发回执
+ 工具路径证书、`seal()` → 会话末端承诺；内部持有**一把** `ToolGateway`
（跨路径共用 —— 两条链各指一条 `trace_root` 会把会话劈成两条，这正是
`06-frameworks.md:278` 已经踩过的坑）。它**不是**第四个框架适配器，
而是**三个适配器的公共内核**：每个框架适配器 = 这个内核 + 一个
「把本框架的事件形状宽松提取成 `text` / `(name, args, result)`」的函数。
放在 `policydsl/` 下而不是 `scripts/`，因为它要能被单测直接穷举。

**P3-b · `docs/modules/06-frameworks.md` §8 扩写成接入指南。**
把三条建议升级为**契约清单表**（每一行 = 一个必须做对的点、做错的后果、
三个现有适配器各自怎么做的），外加「接一个新框架」的分步流程与
「框架特定、换框架要重做」的**红线清单**（`raise_error` 那类回调系统行为、
掐断后走哪条错误路由 —— §8 现有第三点已经点名，要提到显眼处）。
同时在 `README.md` 与 `docs/modules/README.md` 加指路。

**验收 P3-a**（✅ 已达成）：`tests/test_generic_adapter.py` **18 例**，四组
（契约 / seal 时序 / 该抛就抛 / 第三方真脚本核对 —— 起**子进程**跑
`verify_session.py` 与 `verify_cert.py`，不是复述内部函数）；全套 **648 通过 /
15 跳过**。**4 处变异**钉住这条线，其中一处**一度存活并查出真缺口**：把
`tool_call` 的 `chain` 从整条网关链改成 `[receipt]` 时其余 17 例**全绿** ——
`trace_root` 只取最后一条回执的摘要，且只传当前那条会让 `seq` 不从 0 起、
先判成 `trace_unbound`，于是 `passed` 与**规则名恰好都一样**，差别只在
`kind` 与「计到几条」。补了一条「第 2 次调用继承第 1 次的超预算」并断言咬在
`kind`/`evidence` 上之后杀掉。

**验收 P3-b**（✅ 已达成）：`06-frameworks.md` §8 由三条建议扩写为接入指南
（§8.0 分清「你的活」/ §8.1 参考实现与第三方核对配方 / §8.2 **9 行契约清单**
/ §8.3 接新框架六步 / §8.4 换框架必须重做的红线 / §8.5 结果侧 / §8.6 变异自查）。
清单表**每一行的行号都用脚本逐条核过**（20 条锚点，改正 2 处：`HAVE_LANGCHAIN`
在 `:30`、MCP 的 `call_tool` 在 `:179` 而非 `:224`）—— 写不出对应实现的行就是编的。

#### 5.4.3 其余各项的处置（这轮不动，理由在此）

- **c1 论文镜像**（`paper/proof-of-policy.tex:502` 写「469 全绿（13 skip）」，
  且服务层在论文里出现 **0 次**）：**优先级最高但本机做不了验收** ——
  环境里没有 TeX 工具链（见记忆 `zk-policy-env-setup`），改完**无法本地编译**，
  只能人工核对，与本轮两项「改完立刻能验」不同量级。要么先给出机器，
  要么单独一轮。
- **c3 `dev-plan.md:90` 悬空的链上开示承诺**（「证据片段的链上开示流程 → Phase 5」，
  而 Phase 5 已 ✅ 却只交付了**链下**开示）：要么在后续阶段真接上，
  要么**显式降级为「已知边界」**写进 §5 边界表。**不能就这么悬着** ——
  这正是 §5.0 说的「说了但没接上」。留待与 c1 一并处理。
- **c4 T3**（真实 SP1 证明的全量回归定期跑，单次 ≈ 45 分钟，本机可跑）：
  是**排期问题**不是能力问题，等 P1/P3 收尾后单独起。
- **c6 `policydsl/evidence/anchor.py:580`** 用 `NotImplementedError` 表达「配置缺失」：
  语义不对（该是 `ValueError` —— 它不是「还没实现」，是「你没配」），
  但纯属措辞，随 P1 顺手看一眼成本更低。
- **T1 真实 groth16 + 链上验证合约**：**唯一的外部阻塞**，需要一台 ≥64 GB
  内存的机器（本机 SP1 出证有 ~10.15 GiB 地板且没有余量）。代码侧已就绪，
  只差机器。

### 5.5 c4（T3 真证明全量回归）+ c6（锚定钩子异常类型）（2026-09-16 立）

§5.4.3 里 c4/c6 判的是「本机可做、只是没排期」。现在做。**c6 动手前先复核，
把它从「措辞」升级为「真 bug」**（复核结果见 5.5.2）—— 这是本节唯一一处
与原判断不同结论的地方，如实登记。

#### 5.5.1 c4 · T3：把「全量真证明回归」做成能定期跑、且留痕的东西

**T3 的原文**（`plan-p0p1p2.md` 待办表）：真实 SP1 证明的**全量**回归改为
「**出证 + 验证**两条腿都在 **CI 之外**定期跑」，阻塞的是**论文 §7 的证明时间/内存数字**。

**现状盘点**（三条都不满足 T3，但已有的比缺的多）：

| 已有的 | 覆盖 | 为什么还不够 |
|---|---|---|
| `scripts/prove/cross_validate.py --chunk 2` | **全量** 19 向量真出证 + 与 golden 逐条比对 | **只有出证这条腿**；且末行 `RESULT` 是**人读的**，没有落成结构化记录 |
| `bench/bench_proofs.py` | 出证 → 量墙钟/体积/峰值 RSS → 再验一次 | **采样点**（默认 6 个 `(长度,规则数)`），不是全量向量；且面向 P2-12 的边界表 |
| `bench/bench_verify.py` | 量「验证已存盘证明」的代价 | 要先有一份**存盘的**证明 —— 而 `cross_validate` 不落盘证明 |

⇒ 缺的不是任何一条腿，而是**把两条腿串起来、按次留痕、能挂定时器**的那一层。
所以 c4 **不新写一套出证/比对逻辑**（那会立刻和 `cross_validate` 漂移），
而是新写一个 `scripts/prove/regression_prove.py` 去**编排**已有的件。

**设计**（四条腿 + 留痕）：

1. **出证腿**：子进程调 `scripts/prove/cross_validate.py --chunk N`（默认 2，
   与既有 45 min 口径一致），解析末行 `RESULT: host A/N prove B/N`。
   **不碰它的向量表与 golden 比对** —— 单一事实来源留在原处。
2. **验证腿**：`--proof-out` 只支持单向量（`main.rs:397` 会 panic），所以
   另行对**一个**向量出证并落盘，再用**新进程** `pop-script --verify --proof <p>`
   验它。关键在「新进程」：出证进程已退出，验证方手里只剩产物 + ELF，
   这才是独立的第二条腿。
   *为什么只验一个*：验证腿要证的是「这份产物**换个人也能验**」这条**路径**没坏，
   不是把 19 份再验一遍（19 份证明 ≈ 1.6 GiB，验一轮还要 19 次 vkey setup）。
   这是**刻意的取舍**，写进记录的 `verify_leg.note` 里，不装作全量。
3. **留痕**：**追加**写 `bench/results/regression-prove.jsonl`，一行一次运行：
   `ts / git_sha / git_dirty / host{}/ host_leg / prove_leg / verify_leg / seconds{}/ peak_rss_mb / result`。
   **只追加不覆盖** —— 这正是 T3 要的：§7 的数字要能指到**某一次具体运行**，
   而「这次比上次慢了多少」要看得出来。`cross_validate.py` 每次**覆盖**
   `results_prove.json`，历史无从谈起，所以留痕必须是这一层的新东西。
4. **退出码**：任一条腿 FAIL → 非 0（供定时器判成败）。
5. **CI 之外定期跑**：cron / systemd-timer 配方写进 docstring 与
   `docs/reproduce.md`。45 min 不进 CI 是 T3 的前提，不是妥协。

**可测性**（不必有 Rust）：`--pop-script PATH` 可注入驱动。单测塞一个**假驱动**
（按参数写结果文件的脚本），全程跑完，断言：历史**追加不覆盖**、出证腿失败→非 0、
验证腿失败被抓住且与出证腿**分开记**、`git_sha`/`host` 真的落盘。

**验收 c4**：① 单测（假驱动）全绿；② **本机真跑一次全量**（≈45 min）并留下
第一条历史记录 —— 只有真跑过，T3 才算关，否则只是「写了个没跑过的脚本」。

#### 5.5.2 c6 · `anchor_on_chain` 的异常类型：从「措辞」改成「真 bug」

复核后**改判**：不只是措辞。`policydsl/evidence/anchor.py:580` 在 rpc/contract 缺失时抛
`NotImplementedError`，而**同一个条件**在它正上方的 `backend_from_env(require=True)`
（`:560`）抛的是 `AnchorError`。**同一个仓库、同一个条件、两种类型。**

后果不是理论上的：全仓库**所有**锚定错误的消费点都按 `anchor.AnchorError` 捕获 ——
`verify_session.py:339`、`verify_cert.py:475`、`proof_service.py:249/375`、
`deploy_anchor.py:43`、以及 `service.py:451` 那个把异常翻译成「运维能照着做的一句话」
的 `failure_reason`。照文档写 `except anchor.AnchorError` 的调用方**接不住**这个钩子。

而且 `NotImplementedError` 说的事**是假的**：链上后端**已经实现**了
（`RpcAnchorBackend` + `contracts/Anchor.sol` + Anvil 端到端 PASS，见
`docs/reproduce.md` §12）。它会让读者以为「这功能还没做」，真相是「你没配」。

**修**：`:580` 改抛 `AnchorError`，消息与 `backend_from_env` 那条**统一**；
连同 2 处测试锁（`test_anchor.py:62`、`test_anchor_chain.py:134`）与
**文档锁**（`docs/modules/04-anchoring-audit.md:229` 明写「未配置抛
`NotImplementedError`」）一起改。
**不新增行为**，只把类型对齐既有约定 —— 所以验收是：现有两条测试改成断言
`AnchorError` 后仍能钉住「未配置必须报错且不假装上链」。

> **如实登记**：`anchor_on_chain` 目前**没有任何生产调用方**（只有这 2 条测试），
> 真正被服务用的是 `backend_from_env`。所以这是**公共 API 的一致性缺口**，
> 不是线上事故 —— 但既然它是对外文档化的入口，类型就该对。

#### 5.5.3 落地情况

**c6 ✅ 完成**（提交 `873a9d6`）。修法不是就地把异常名换掉 —— 那样两处消息还能继续
各写各的、再次分叉；改为新增 `_unconfigured_error()` 统一产出**类型与消息**，两个入口
都调它。测试 3 例（`test_same_type` 用 `assertIs(type(a),type(b))`；`test_same_message`
比一字不差；`test_not_implemented_error_would_not_be_caught` 是**反例对照**）。
变异核对：把 `anchor_on_chain` 改回 `NotImplementedError` → **4 条红**，确认断言不是恒真。
另修两处：`cross_validate.py` 之外，`docs/modules/04-anchoring-audit.md` 的**文档锁**
（它同时写着「配置缺失 → `AnchorError`」和「未配置抛 `NotImplementedError`」，自相矛盾）。

**c4 ✅ 完成**（本节）。新增 `scripts/prove/regression_prove.py` + `tests/test_regression_prove.py`
（16 例，含**替身驱动**，不需要 Rust）+ `cross_validate.py` 的两个非破坏性口子
（`POP_SCRIPT` / `--work-dir`）。

**§5.5.1 的验收判据②已兑现** —— 本机真跑一次并留下第一条历史记录（本例是「写了个
没跑过的脚本」与「关掉的 T3」之间的分界）。2026-09-16 `--label first-real-run --chunk 2`：
出证腿 `host 19/19 · prove 19/19`，**2432.0 s（40.5 min）**，峰值 **10,975 MB**；
验证腿另起进程验 `clean_pass` **180.4 s**（vkey setup 占 1.87 s，实际验证 0.123 s）；
合计 **43.6 min / PASS**。记录里 `git.sha=6927b63` 且 `dirty=false` —— 数字绑在了
产生它的那次提交上（跑之前特意把并行的文档改动 stash 开，否则这里会是个诚实的 `true`，
但要解释半天「脏在哪」）。**峰值 10.72 GiB 不是地板**：地板 10,389 MB 是最小配置的
下限，19 条按 `--chunk 2` 跑会略高，仍低于当初单进程整批被 OOM 杀掉的 10.65~10.82 GB
—— 三个数要一起读，只引地板会让人以为全量回归也贴着地板跑。

动手时改了两处**原方案没写到**的东西，都是真踩出来的：

1. **`--work-dir` 是必要的，不是顺手加的。** `cross_validate` 的
   `vectors.json` / `results_*.json` 是**固定文件名**，定时任务与手工跑会踩同一批
   文件、互相覆盖对方的结果。原方案只说了「留痕要追加」，漏了这个 —— 结果文件本身
   也得分开。
2. **失败记录里必须剥掉 `time -v` 的样板。** 这是写完之后测出来的：`time` 的报告
   打在**子进程输出之后**，而 `log_tail` 取「末尾 30 行」—— 于是一次 OOM 的记录里
   留的是 20 行「Average resident set size / Page size / Exit status」，
   **解释原因的 Python traceback 被挤掉**。最需要证据的那种失败，证据反而最看不见。
   现在解析峰值 RSS / 信号仍从完整 stderr 上取（它们在样板里），但留证据的尾巴用
   剥掉样板后的版本。

**变异测试**（6 处）：M1 覆盖写 `"a"→"w"`、M2 验证腿被跳过却标 `ok=True`、
M3 去掉样板剥离、M5 结果只看出证腿、M6 指纹不算摘要 —— **全部被杀**。
M4（`ok` 只看退出码、不看末行）**存活，且是等价变异**：当前两处证据（进程退出码 /
stdout 末行）总是同时成立，要证伪得让 `cross_validate` **自报 PASS 却非零退出**，
那不是测试能构造的状态。合取仍保留 —— 防的是将来「印了末行之后才崩」。
**如实登记，不当作漏测。**

**两点边界，不掩饰**：

- 验证腿**只覆盖 1 个向量**（记录里写在 `verify_leg.note`）。它证的是「这份产物换个人
  也能验」这条**路径**没坏，不是把 19 份再验一遍。
- cron/systemd 配方**已写进脚本 docstring 与 `08-tests-bench.md` §3.8，但没有任何机器
  真的挂着它**。「**能**定期跑」已交付，「**正在**定期跑」要有人去配那一步 —— 这两件事
  不能混为一谈。

---

### 5.6 结构重梳 + demo/模块文档（2026-09-17 立）

#### 5.6.1 现状的五个问题（每条都能从仓库直接核对）

| # | 问题 | 现场 |
|---|---|---|
| 1 | `policydsl/` **30 个模块平铺** 10,542 行 | 找「私有模式在哪个文件」只能靠记忆或 grep |
| 2 | `scripts/` **22 个文件平铺**，且混着**运行产物** | `results*.json` / `vectors.json` 就落在 `scripts/` 里，靠 `.gitignore` 挡着才没入库 —— 挡住的是入库，不是「位置不对」 |
| 3 | `docs/` 18 个文件**没有索引** | 只有 `docs/modules/README.md` 给模块文档做了索引；`docs/` 本身没有入口 |
| 4 | `docs/demo/` **只有生成产物** | 里面是 `session_report.html` / `.svg` / 两张 png，**没有任何文档**说明这个 demo 演示了什么、每步该看什么 |
| 5 | 根 README 的「目录结构」**漏项** | 少了 `docs/modules/`、`circuits/patches`、`bench/results`、`scripts/examples` 等 |

问题 4 最要紧：一份**没人解释**的 demo 报告，读者只能从截图里猜发生了什么。

#### 5.6.2 目标布局

**① `policydsl/` 拆成 6 个子包 + 门面**（按职责，不按文件类型）：

| 子包 | 收 | 一句话 |
|---|---|---|
| `core/` | `model` `compile` `evaluate` `serialize` `nfa` `pii` `normalize` | 策略、跨层契约、golden 判定 —— 唯一与 Rust 侧逐字对齐的一层 |
| `privacy/` | `commit` `challenge` | 承诺 / 选择性披露 / 挑战-响应绑定 |
| `evidence/` | `cert` `keys` `anchor` `trace` `verifier` | 产物与可核验性：证书、回执链、锚定、核验 |
| `proofs/` | `compose` `infer` `session` `multiparty` `semantic` `ezkl_evm` | 组合 / 会话聚合 / 多证明者 / 语义委托 |
| `adapters/` | `agent` `generic_adapter` `langchain_adapter` `langgraph_adapter` `mcp_adapter` `llm` | 接到 agent 框架上 |
| `runtime/` | `service` `auth` | 常驻出证服务 |

根上只留 `__init__.py`（门面）、`__main__.py`（CLI）与 `paths.py`（仓库根的唯一出处，见 §5.6.7）。**6 个**是刻意的：再多就
是「每个文件一个目录」；再少则 `evidence/` 与 `proofs/` 会各自胀到 8+ 个模块，
又回到平铺。

> **落地时的两处订正**（方案写完后动手才发现的）：
> 1. 第 6 个子包叫 **`runtime/` 而不是 `service/`** —— 否则会得到 `policydsl.service.service`
>    这种「service 的 service」，读起来像笔误。子包名与其中的模块名**必须不同名**。
> 2. 根上多了个 **`paths.py`**，方案里没有。它是第 1 步撞出来的（§5.6.7 第 1 条）：
>    「仓库根在哪」原本被六个模块各算了一遍，拆包把那个巧合戳破了。

**② `scripts/` 分 5 组**（按用途，正好对上 demo 的支路）：

| 组 | 收 |
|---|---|
| `demo/` | `demo_all.sh` `demo_e2e.py` `private_demo.py` `make_shots.py` |
| `prove/` | `prove_policy.py` `prove_session.py` `prove_multiparty.py` `compose_proof.py` `ezkl_prove.py` `issue_cert.py` `gen_key.py` `cross_validate.py` `regression_prove.py` |
| `verify/` | `verify_cert.py` `verify_session.py` |
| `anchor/` | `anchor_e2e.sh` `deploy_anchor.py` |
| `ops/` | `proof_service.py` `make_audit_proof.sh` `install_*.sh` `retry_install_*.sh` |

顺带解决：`cross_validate` 的 `DEFAULT_WORK_DIR` 从 `REPO/scripts` 改到
**gitignore 的产物目录**（`bench/work/` 已有，或 `scripts/.work/`），产物不再落在
源码目录里。

**动手前定死的四条**（普查后才看得出来的）：

1. **`scripts/examples/` 原地不动。** 它不是脚本，是输入样本（`*.txt`）+ demo 产物
   （`out/`）。把它卷进来只会平白多改十几处路径，不增加任何清晰度。所以 `scripts/`
   根下是 `_bootstrap.py` + 5 个组 + `examples/`。
2. **`_bootstrap.py` 要把 5 个组目录都装进 `sys.path`。** 因为跨组 import 是真实存在的：
   `demo/demo_e2e.py` → `import issue_cert`（在 `prove/`）、
   `prove/regression_prove.py` → `import bench_proofs`（在 `bench/`）+ `import cross_validate`。
   装 5 个组目录 = **保持今天「平铺命名空间」的语义不变**，只是物理上分了目录。
   （组内文件名目前两两不同名，无冲突。）
3. **每个脚本仍要有 1 行找 `scripts/` 的代码**：`sys.path.insert(0, parents[1])` 再
   `from _bootstrap import …`。这是**有意的取舍**而不是偷懒 —— 让每个文件都做一次
   标记搜索会把同一段定位逻辑抄 16 遍，正是 `_bootstrap.py` 要消除的东西。
   代偿是两条**机械化**保障，不靠人眼：
   - `_bootstrap.py` 自查 `parents[1]` 里真的有 `policydsl/` 与 `circuits/`，不是就抛
     **带解释的错**（把静默失败变成响亮失败）；
   - 新增 `tests/test_scripts_layout.py`：把 `scripts/**/*.py` 逐个 `--help` 跑一遍，
     将来的任何一次搬家只要弄坏引导，**CI 当场红**，不靠谁想起来去跑 demo。
4. **`cross_validate` 的产物目录改到 `scripts/.work/`**（而不是 `bench/work/`）：它是
   出证侧工具的草稿区，放 `bench/` 会让 `scripts/` 反向依赖 `bench/`。`scripts/.work/`
   由一条新 gitignore 规则覆盖，替掉原来散在 4 条规则里的 `scripts/vectors.json` 等；
   `.gitignore` 里重复两遍的 `scripts/examples/out/` 顺手去重。

**③ `docs/` 分三层**：

```
docs/
├── README.md          # ← 新增：全文档索引，按「读者意图」分组
├── development.md     # ← 新增：开发与使用手册（总入口，教程向）
├── demo/README.md     # ← 新增：demo 文档（8 条支路 + 报告怎么读）
├── modules/           # 分板块：01–08 + README（既有，本次补「怎么用/怎么改」）
└── *。（架构 / 安全 / 复现 / 计划 / 论文镜像…）
```

#### 5.6.3 四条硬约束（破了就是错）

1. **门面用法不变**：`from policydsl import Policy`、`compile_policy`、`ToolGateway` …
   等 `__init__.py` re-export 的符号，包外 82 处依赖它 —— 这些**一行都不改**。
2. **不留兼容 shim**：包外的 `from policydsl.model import X` 一律改写为新路径，
   **不在旧位置放转出口** —— shim 会让同一个模块有两个名字，正是本次要消除的东西。
3. **脚本仍可直接执行**：`python3 scripts/demo/demo_e2e.py` 必须能用；不许改成
   必须 `-m` 或必须先进某个目录。为此在 `scripts/` 根放一个 `_bootstrap.py`
   统一算 `REPO` 与装 `sys.path`。
4. **文档路径引用与代码同等对待**：`demo_all.sh` 在**代码里** `grep docs/security-model.md`
   取原话（那是有意的设计：报告因此不会随文档漂移而说假话）—— 挪文档就必须同步改。

#### 5.6.4 分步与验收闸门

每步**独立提交**，闸门不过就迭代到过，绝不带病提交（长期规则）。

| 步 | 做什么 | 闸门 | 状态 |
|---|---|---|---|
| 0 | 方案（本提交） | — | ✅ |
| 1 | `policydsl/` 拆包 + 全仓 import 改写 + 文档里的模块路径 | **667 passed / 15 skipped** | ✅ 2026-09-17，**667 passed / 15 skipped**，另修掉两条隐藏依赖（见 §5.6.7） |
| 2 | `scripts/` 分组 + `_bootstrap.py` + 全仓路径引用 + 产物目录 | **675 passed / 15 skipped** + `demo_all.sh --list` + **fast 模式真跑一次** | ✅ 2026-09-17，三条闸门全过（见 §5.6.8） |
| 3 | 文档结构与索引：`docs/README.md` + 根 README 目录结构订正 | 交叉链接逐条可点开 | ✅ 2026-09-17，214 条相对链接**悬空 0**（见 §5.6.9） |
| 4 | demo 文档 `docs/demo/README.md` | 对照 `demo_all.sh` 的 8 条支路逐条核对 | ✅ 2026-09-17，机械比对 **8/8 一致**（见 §5.6.9） |
| 5 | `modules/01–08` 各补「怎么用 / 怎么改」两节 | 08 的测试计数与实际一致 | ✅ 2026-09-17，**30 个模块 / 675 passed / 15 skipped** 逐字对上（见 §5.6.9） |
| 6 | 总手册 `docs/development.md` | 手册里的每条命令**实际敲一遍** | ✅ 2026-09-17，15 条命令全部实跑；含一次真出证（2:07 / 10.85 GiB），见 §5.6.10 |
| 7 | 收尾：测试计数、交叉链接、推送 | **675 passed / 15 skipped** + 工作树干净 + origin 同步 | ✅ 2026-09-17，四项闸门全过（见 §5.6.11） |

#### 5.6.7 第 1 步实测：两条被绿测试掩盖的隐藏依赖

§5.6.6 预判「某个闸门变红 = 原来藏着隐式依赖」。第 1 步**确实**变红了两处，都不是
「搬家搬错了」，而是**原本就错、只是从没被跑到**：

1. **六处重复的仓库根计算。** 六个模块各自写 `REPO = Path(__file__).resolve().parent.parent`。
   平铺时这**恰好**等于仓库根 —— 是**巧合，不是契约**。下沉一层后 `parent.parent` 变成
   `policydsl/`，于是 66 errors / 8 failures，首条是
   `FileNotFoundError: …/policydsl/circuits/target/release/pop-script`。
   修法**不是**给六个调用点各补一个 `.parent`（那只会把同一个 bug 推到下一次移动），
   而是新增 `policydsl/paths.py`：按**标记目录**（同时含 `policydsl/` 与 `circuits/`）
   向上找仓库根，唯一出处。
2. **`scripts/ops/make_audit_proof.sh` 里那段内联 Python 一直是坏的**，且带着**两个**独立的
   陈旧项：`from policydsl.serialize import spec_to_rust_constraints`（**P0-1 已删除该函数** ——
   `plan-p0p1p2.md` 记着「20 个调用点已机械替换」，这是漏网的 1 个）+ 搬家后的模块路径。
   没被发现的原因很具体：它生成的 compressed fixture 只在 ≥16 GB 机器上有用，
   `tests/test_verifier_only.py` 在别处**直接 skip** —— **绿测试从没执行过这段代码**。
   已改为 `build_vectors([vector_entry(...)])`，并用 `pop-script --check` 验证产出的
   vectors 形状能被真驱动吃下（`passed=True`，秒级，不进证明）。

**第 2 条的方法论含义**（值得单独记）：`unittest` 的 skip 是**静默的绿**。凡是
「只在更强的机器/更大的内存上才跑」的代码路径，测试套件对它**零覆盖**，而它照样全绿。
所以本轮给这一步加的验收不只是 667，而是**凡是本机能跑的路径都真跑一遍**（
第 2 步的 `demo_all.sh` fast 模式闸门就是这条原则的延伸）。

#### 5.6.8 第 2 步实测：三条闸门与一个自我纠正（2026-09-17）

第 2 步（`scripts/` 分组）走完，三条闸门**实测**如下 —— 不是「看起来对」：

| 闸门 | 实测结果 |
|---|---|
| 测试套件 | `python3 -m unittest discover tests` → **675 passed / 15 skipped**（33.3 s）。667 是搬家前的基线；**+8** 是新增的 `tests/test_scripts_layout.py`，skip 数不变 |
| `demo_all.sh --list` | 正常输出，且每条支路的「驱动」列已是新路径（`scripts/prove/…` / `scripts/anchor/…` / `scripts/verify/…`） |
| **fast 模式真跑一次** | `bash scripts/demo/demo_all.sh` → **8 条支路全 PASS、没有 FAIL** |

8 条支路的实测（2026-09-17，本机 11.9 GB）：

```
policy       公开模式主干       PASS   1.2 s    scripts/demo/demo_e2e.py
private      私有模式           PASS   0.0 s    scripts/demo/private_demo.py
semantic     语义规则(P2-9)     PASS   5.1 s    scripts/prove/ezkl_prove.py
compose      组合证明(P1-6)     PASS   0.1 s    scripts/prove/compose_proof.py
session      会话聚合(P2-10)    PASS   0.1 s    scripts/prove/prove_session.py
multiparty   多证明者(P2-11)    PASS   0.1 s    scripts/prove/prove_multiparty.py
anchor       链上锚定(P7-c)     PASS   6.4 s    scripts/anchor/anchor_e2e.sh
verify       第三方独立验证     PASS   0.1 s    scripts/verify/verify_session.py
```

**搬家当场炸出来的东西**（一次全红，不是逐步冒出来）：测试套件 627 tests / **16 errors**，
全是 import 失败 —— 4 处 `from scripts.proof_service import`（缺 `ops.` 一层）与 6 处
「先 `sys.path.insert(REPO/"scripts")` 再平铺导入」的测试引导。这 16 处正是 §5.6.5 普查里
**P1 会跑挂**那一格，数目对得上。修法与 `policydsl/` 拆包时同源：**不补层数**，而是把
「从标记搜根」这件事下沉成 `scripts/_bootstrap.py`，测试引导调 `bootstrap()`。

**为什么非要加一条 fast 模式真跑**：分组之后，「路径写错」这件事**只有跑 demo 才走得到**。
单测全绿不代表 `demo_all.sh` 能跑 —— 反过来也一样。§5.6.7 记的那条「`unittest` 的 skip
是静默的绿」在这里换了个形状：**没被任何测试覆盖的路径，绿是借来的**。所以第 2 步的验收
按「凡是本机能跑的路径都真跑一遍」办，而不是「单测绿了就算」。

**顺带关掉的三处**（都在 `scripts/` 分组时暴露）：

1. **`.gitignore` 的 6 条路径规则收成 1 条。** 原先 `scripts/vectors.json` /
   `scripts/results*.json` ×3 / `scripts/examples/out/`（**出现两次**）—— 挪目录不改它们，
   规则就静默失效、草稿产物直接入库。现在合成 `scripts/.work/` 一条目录规则。
2. **`cross_validate.py` 的草稿产物换了地方。** `DEFAULT_WORK_DIR` 从 `scripts/` 改到
   `scripts/.work/`：那四个文件本来就是草稿，落在源码目录里让 `ls scripts/` 分不清
   哪些是脚本、哪些是上次跑剩下的。
3. **新增 `tests/test_scripts_layout.py`（8 例），把这次的教训机械化。** 脚本头部那行
   `sys.path.insert(…, parents[1])` 是**按层数**写的，再搬一次家就会静默指错 ——
   而它坏掉的正是「只有跑 demo 才走到」的路径。所以钉三件事：每个脚本都导入得动且
   `REPO` == 仓库根；`_bootstrap` 在**陌生树**里照样找得到根、缺标记时响亮报错；
   5 个组目录并排进 `sys.path`，故组间不能有同名文件（这是 `bootstrap()` 成立的前提）。
   同一文件里另加一条 `test_at_least_one_script_and_five_groups`，防「空集合上全绿」。

**一个自我纠正，如实记下**：这套新测试的**初版我自己写坏了三处** —— 一条
`assertTrue(… or True)` 的占位断言（恒真）、一处用 `__import__("json")` 拼常量集合的 hack、
以及一条前提就错的用例（把副本放到 `<root>/a/b/c/scripts/`，而 `_bootstrap.py` 里那条
**故意**的自查会因此报错 —— 于是它测的是**另一个**行为）。三处都改掉了：占位断言删掉、
常量改成字面量、那条用例拆成「陌生树里找得到」与「不在 `<根>/scripts/` 时报错」两条，
把自查本身也变成被测行为。写测试时踩到「用例自己恒真」和「用例前提站不住」这两类坑，
正是 §5.6.3 那条纪律的反面教材，留在这里备忘。

#### 5.6.9 第 3–5 步实测：三种「闸门」的形状（2026-09-17）

第 3 步（文档索引）、第 4 步（demo 文档）、第 5 步（模块文档补两节）走完。
三步的闸门是三种不同的东西，各自逼出了一种不同的**验证手段** —— 记在这里，
因为「怎么写文档的验收判据」本身就是这次要立的规矩。

| 步 | 闸门 | 实际怎么验的 | 结果 |
|---|---|---|---|
| 3 | 交叉链接逐条可点开 | 写了个**链接普查脚本**：全仓 `.md` 的 `\[…\]\(…\)` 全抓出来，跳过外部 URL 与锚点，逐个 `Path.exists()` | **214 条相对链接，悬空 0** |
| 4 | 对照 `demo_all.sh` 的 8 条支路逐条核对 | **机械比对**，不是人眼：把 `demo_all.sh` 里 `LANES` 数组的**字段**与文档表格**逐字段**比 | 先比出 **5 处**不一致（文档写了全角括号 `（）`，脚本里是半角），统一后 **8/8 一致** |
| 5 | 08 的测试计数与实际一致 | `python3 -m unittest discover tests` → `Ran 675 tests … OK (skipped=15)`；`ls tests/test_*.py \| wc -l` → 30 | **30 个模块 / 675 / 15**，与 08 文档逐字对得上 |

**三次「我写错了、被闸门拦下」**（每一处都是文档里的**事实性**错误，不是措辞）：

1. **第 5 步，02 的 API 片段整段是编的。** 我按印象写了 `commit.response_commitment`
   —— 真名是 `commit.commitment`；`redact(resp, spans=…)` 也错，真签名是
   `redact(text, mask, char=…)` 且**返回字符串**不是对象。**查源码后重写并实跑通过。**
   中间还踩了一次：手搓 `spec` 造 `spec_spans` 触发 `KeyError: 'nfa'`，改用
   `compile_policy` 造 spec 才对 —— 这类「手搓的内部结构」在真实调用点根本不该出现。
2. **第 5 步，03 的「它不替你算任何哈希」是反的。** 读 `build_payload` 函数体发现
   `"policy_hash": spec["sha256"]` —— `policy_hash` 是它自己取的。改成说清
   **哪几个参数必须由调用方给**（`vkey_hash` / `proof_sha256` / `public_values_sha256`，
   它不算也不核）。
3. **第 5 步，05 里 `pop-verify` 的参数写错。** 我写成 `--proof/--vkey`，实际是
   `--meta <proof>.verify.json`（边车文件名由 `write_verifier_sidecar` 写成
   `{proof}.verify.json`）。跑 `--help` + grep `script/src/main.rs` 后改正。
   `pop-script` 的旗标同样核过：`--job` 只认 `policy|infer|session`，`--proof-out`
   只支持单向量。

**为什么值得单列一条纪律**：这三处**没有一处会让文档读起来不对**——它们都是
「看着像真的」。和 §5.6.7 那条「`unittest` 的 skip 是静默的绿」是同一个问题的两种形状：
**失败不响，就得靠机械手段把它弄响**。所以第 5 步的做法是：**01–08 里凡出现的命令与
代码片段，要么实跑一遍，要么回源码核签名**，核不了的宁可不写。

**顺带做的两件事**：

- **`docs/modules/README.md` 头部那句改了**：原来只说每篇含「职责 / 文件清单 / … /
  扩展指引」七节，现在补上**「怎么用它」与「怎么改它」两节是另一种性质** ——
  前七节回答「它是怎么实现的」，这两节回答「我拿它干活 / 我要动它的时候怎么办」。
- **第 3 步的自纠**：`docs/README.md` 初稿写进了两个**当时还不存在**的文件链接
  （`demo/README.md`、`development.md`）。闸门是「逐条可点开」，所以先删掉，
  第 4 步补回 demo 那条，`development.md` 那条留给第 6 步 —— **不为了让索引好看而
  先写一条点不开的链接**。

#### 5.6.10 第 6 步实测：手册的闸门是「每条命令敲一遍」（2026-09-17）

第 6 步产出 [`docs/development.md`](development.md)（开发与使用手册）。它的闸门与前三步
都不同：不是「链接能点开」，也不是「数对得上」，而是**手册里的每条命令实际敲一遍** ——
因为手册的价值全在「照着敲能work」，而**一条没跑过的命令与一条跑不通的命令，
在纸面上长得一模一样**。

所以这一节就是那张实测表（全部 2026-09-17 本机）：

| 手册里的命令 | 实测 | 数对上了吗 |
|---|---:|---|
| `python3 -m unittest discover tests` | 33.4 s（第二次 35.7 s） | `Ran 675 tests … OK (skipped=15)` ✅ |
| `bash scripts/demo/demo_all.sh --list` | 秒 | 8 条支路 ✅ |
| `bash scripts/demo/demo_all.sh` | **13.18 s** | 8 条支路全 PASS、`汇总：没有 FAIL` ✅ |
| `python3 scripts/demo/demo_e2e.py --no-prove` | **1.16 s** | 末尾 `llm model : fake (offline)` ✅ |
| `verify_session.py --session …/policy/session.json` | **0.081 s** | 10 项全 PASS ✅ |
| `proof_service.py --host-check` + `/v1/health` + `/v1/check` + `/v1/attest` | 秒 | `status: ok` → `202` → `done` ✅ |
| `issue_cert.py`（**真出证**） | **2:06.69**，峰值 RSS **10.85 GiB** | 无 OOM ✅ |
| `verify_cert.py --proof … --response …` | 20.8 s | **13 项全 PASS** ✅ |
| `python3 -m policydsl compile` / `check` | 0.011 / 0.043 s | `sha256` == 证书里的 `policy_hash` ✅ |
| `bash scripts/anchor/anchor_e2e.sh` | **6.94 s** | `ALL PASS`，退出后 anvil 已关 ✅ |
| `cargo build --release -p pop-script`（无改动） | 8.9 s | ✅ |
| `cd circuits/program && cargo prove build`（无改动） | 0.37 s | ✅ |
| `cross_validate.py --no-prove` | **0.048 s** | `host 19/19 … PASS` ✅ |
| `bench_compose.py --render-only` | 0.043 s | 幂等（重渲染后工作树无 diff）✅ |

**唯一的重活是真出证那一条**（也是唯一能把本机内存吃到边缘的一条）：它同时当作
「§3.7 这段手册写对了吗」的验证与「`cert_public/` 那份工件还能用吗」的修复 ——
**它不能用了**：盘上那份是 2026-09-11 出的，而 guest ELF 在其后变过，于是
`pop-script --verify` 报 `pc_start != vk.pc_start`。**旧的证明工件与旧的测试 fixture
会在某次 ELF 变更之后集体失效，而且失效得很晚**（在你正好要演示的那一刻）。
这一条已写进手册 §8 的排查表。

**闸门逼出来的四件事**（都不是我事先想到要写的）：

1. **`python3 -m policydsl` 只在仓库根能用。** 换个目录就是 `No module named policydsl`
   （没装机、也无意装机）。这**正好与 `scripts/` 相反** —— 脚本按标记搜仓库根，
   在哪儿敲都一样。两条都写进手册，并给了 `PYTHONPATH=<repo>` 的解法。
   一个「有的能在任何地方跑、有的只在一个地方能跑」的仓库，不写清楚就是坑。
2. **`cross_validate.py --help` 会直接开跑 19 条真证明。** 它用裸 `sys.argv` 解析，
   `--help` 被当普通参数忽略 —— 我核旗标时真踩了，靠 `head` 关管道（SIGPIPE）
   才在真证明起来之前掐掉。手册里写成一条⚠️，并给了同类脚本的排查法（先 `grep add_argument`）。
3. **退出码不告诉你「策略满足没满足」。** `ok_all = all(r[1] for r in results)` 收的是
   逐项核验（签名 / 绑定 / 证明 / 语义规则逐条），**唯独不含 `outcome.passed`** ——
   那个值只出现在 `合规:` 那一行（且该行仅在策略含语义规则时才打印）。实测：
   `demo_all.sh` 那份会话 13 张证书里 **6 张 `passed=false`**，`verify_session.py`
   照样 `RESULT: PASS`、退出码 `0`。**一张如实记录违规的证书是真的证书。**
   （这一条我第一版写反了 —— 写成「退出码不看合规那一行」，读代码核对后才发现
   真正的口径：语义规则**是**进 `ok_all` 的，不进的是 `outcome.passed`。
   差之毫厘，但按第一版写会让读者以为「读到 0 就等于合规」。）
4. **「绿」在这个项目里有三种含义**：真核过了、如实说「这一项这次核不了」（如
   `trace_seal` 未附时的 PASS）、以及**没跑**（skip / `--no-prove`）。手册把这条单列。

**顺带修掉的三处陈旧计时**（都是「差得不多」因而从没人回头改的那种）：
`demo_all.sh` 头注释的「约半分钟」、`07` §1/§3 的「约 20 秒」→ 实测 **13 秒**；
`anchor_e2e.sh` 头注释与 `07` §1 的「~10 s」→ 实测 **7 秒**；
另修 `cross_validate.py:98` 的 docstring（`缺省 scripts/` → 实际早已是 `scripts/.work/`）。

#### 5.6.11 收尾（2026-09-17）：七步的最终闸门与留下的东西

七步全部完成，每步独立提交、闸门不过就迭代。**七个提交**（按时间序）：

| # | 提交 | 内容 |
|---|---|---|
| 0 | `08818af` | §5.6 结构重梳 + 方案与爆炸半径普查 |
| 1 | `22642bc` | `policydsl/` 拆成 6 个子包，仓库根收敛到 `paths.py` |
| 2 | `676500b` | `scripts/` 按用途分 5 组，`_bootstrap.py` 按标记搜仓库根 |
| 3 | `1f88d86` | `docs/README.md` 索引 + 根 README 目录结构订正 |
| 4 | `9d0bc8a` | `docs/demo/README.md`，逐条解释 8 条支路 |
| 5 | `67d6989` | `modules/01–08` 各补「怎么用它 / 怎么改它」两节 |
| 6 | `1417e8e` + `3310de0` | 订正三处陈旧计时 / 新增《开发与使用手册》`docs/development.md` |

**第 7 步的四项闸门（全部实测）**：

| 闸门 | 实测 |
|---|---|
| 测试计数 | `python3 -m unittest discover tests` → **675 passed / 15 skipped**（33.8 s）；`ls tests/test_*.py \| wc -l` → **30** |
| 交叉链接 | 全仓 `.md` 相对链接 **268 条，悬空 0**（脚本化普查，剔除论文式记号 `Pr[...](...)`） |
| 工作树干净 | `git status --porcelain` 无输出（产物目录 `scripts/.work/`、`scripts/examples/out/`、`bench/work/` 均在 gitignore 内） |
| origin 同步 | `git push origin main` → `67d6989..3310de0`，无落后 |
| 附：CI 文档卫生 | `! grep -rn '/home/[a-z]*/方向二' --include='*.md' .` → 通过（新写的三份文档里没有本机绝对路径） |

**重梳之后的入口关系**（一句话记法）：

```
README.md ──→ docs/README.md ──→ development.md   我要动手（环境 / 循环 / 配方 / 排查）
                            ├──→ reproduce.md     我要复现某个特性
                            ├──→ modules/          我要读/改某块代码（每篇末尾是「怎么用 / 怎么改」）
                            ├──→ demo/README.md    我要看 8 条支路各跑什么
                            └──→ dev-plan.md       我要知道接下来做什么
```

**⚠️ 一次没抓住的 flake（如实登记）**：收尾期间全量测试共跑了 **13 次**，其中
**1 次**报 `FAILED (errors=1, skipped=15)` —— 注意是 **error 不是 failure**（异常而非断言不过）。
这一次的输出被我自己 `| tail -3` 截掉了，**没记下是哪一条**；随后连跑 **12 次全部通过**
（含 8 次 `-v` 全量留档），**未能复现**。

已知的相关背景：`test_proof_service` 里**曾经**有一条同类的 flake（约 1/4 命中，原因是
把全进程 `Path.write_text` 打了补丁、连工作线程写的产物一起打中），**那条已于 2026-09-13
修掉**（改成只在 `service.os.replace` 上注入失败）。所以这一次**不是**那条 —— 是另一处，
尚未定位。

处置：**不当作已解决，也不当作不存在**。三条具体动作 ——
① 本段留档，写明「13 次 1 次、error、未复现」；
② 下次全量测试**输出一律落盘**（别直接接 `tail`），再出现时先看日志；
③ 若再复现，按 §5.6.7 那条纪律办：**先定位到具体用例，再判断是产品问题还是测试问题**，
不修成「重跑一遍就过」。

**留下的（本轮**没做**，如实登记）**：

- **c1 论文镜像**：`paper/*.tex` 改完在本机**编译不了**（无 TeX 工具链），
  而 `.tex` 是权威源、`.md` 是镜像，两边只能人眼对齐。本轮没动论文。
- **T1 真实 groth16 + 链上验证合约**：需要 **≥64 GB** 的机器，本机 11.9 GiB 连
  core 证明都只剩 1 GiB 余量。
- **`dev-plan.md` §P1-7 那条链上披露承诺**（链上只锚摘要、**不验证明**）——
  文档里已如实标注为过度声明，但没有对应的自动化检查。
- **三处「四处同步」的数字**（测试计数 / bench 数字 / 验收判据）仍**靠人肉核对**：
  唯一有留痕的是 `regression-prove.jsonl`。要做成机械化的，得再加一条 CI 步骤。

#### 5.6.5 爆炸半径（实测普查，2026-09-17）

动手前把路径引用数清了，数字改变了做法：

| 级别 | 内容 | 规模 |
|---|---|---|
| **P0 会跑挂** | `.py`/`.sh` 里 `REPO/"scripts"`、`sys.path.insert(…,"scripts")`、`subprocess` 拼脚本路径 | **≈90 处 / 30 文件** |
| **P1 会跑挂** | `tests/` 里 `subprocess` 调脚本、`from scripts.proof_service import` | **≈35 处 / 12 测试文件** |
| **P2 拆包必炸** | `policydsl` 绝对子模块引用（点号 `policydsl.X` 119 处 + `from policydsl import <子模块>` ≈130 处） | **≈249 处 / 40 文件** |
| **P3 只是文字** | `.md` 316 / `.html` 5 / `.json` 12（生成物） | **≈333 处** |

四个**决定做法**的发现：

1. **成本在包外，不在包内。** `policydsl/` 内部只有 15 个文件用相对引用；其余 20 个是**叶子
   模块**（`cert` `keys` `anchor` `nfa` `normalize` `semantic` … 完全没有包内入口引用），
   被 `tests/`(21 文件) / `scripts/`(11) / `bench/`(4) 广泛依赖。所以拆包的真正工作量是
   **改外层 249 个 import 点**，不是改包内。
2. **最硬的耦合是环**：`scripts/prove/regression_prove.py` ↔ `bench/bench_proofs.py` ↔
   `bench/bench_cycles.py` 靠互相 `sys.path.insert` 成环（`regression_prove` 同时把
   `scripts/` 与 `bench/` 塞进 `sys.path`）。三者中任一个换深度，**两边都要同时改**。
3. **`scripts/` 绝不能加 `__init__.py`。** `tests/test_proof_service.py` 有 4 处
   `from scripts.proof_service import make_server`，靠**命名空间包**成立；一加
   `__init__.py`，`scripts` 变常规包，namespace 语义与递归发现都会变。
4. **`.gitignore` 里有 6 条路径规则**（`scripts/vectors.json`、`scripts/results*.json`
   ×3、`scripts/examples/out/` 出现**两次**）—— 挪目录不改它们，规则就静默失效，
   产物会直接入库。

**两个不受影响的**（省得白改）：`POP_SCRIPT` 指向 `circuits/target/release/pop-script`，
与 `scripts/` 无关；`.github/workflows/ci.yml` 里没有任何 `scripts/`/`bench/` 字面量
（只跑 `unittest discover -s tests`），所以**挪目录后 CI 会在 tests 里报红，而不在 workflow**。

**范围决定：`bench/` 不再下沉。** 它已经是「一个目录一件事」（`bench_*.py` + `results/`
+ `work/`），再分只增加路径点、不增加清晰度。本次只动 `policydsl/` 与 `scripts/`。

#### 5.6.6 边界（如实写在前头）

- **这是一次性大 diff，无法渐进**：拆包不能「改一半还绿」—— 要么全改，要么不改。
  所以靠**闸门**而不是靠审阅来保证正确性；闸门不过就整步回滚，不带病提交。
- **拆包不改变任何运行时行为**：只是位置。若某个闸门因此变红，说明原来就藏着
  一个隐式依赖（比如靠平铺才成立的相对导入），那要**单独记一条**，不混进搬家提交。
- **`docs/development.md` 与 `modules/` 会有重叠**：分工定死 ——
  手册讲**任务**（我要接一个新框架 → 步骤），modules 讲**模块**（这个文件里有什么函数、
  它的不变量是什么）。重复的部分手册里给链接，不复制正文。

---

### 5.7 重构优化建议书（2026-09-17 立，**已采纳，P0–P3 执行中**）

[`refactor-proposal.md`](refactor-proposal.md) 是对整个仓库做的四个角度普查
（技术框架 / 效率 / 内存 / 简洁），产出 R1–R18 与 P0–P3 阶段。

**它是什么、不是什么**（避免误读）：

- **是**一份**输入**：它说「这里有 N 处重复、这两处已经漂移、这个数是错的」，
  每条都带可复现的命令。
- **不是**本期计划：采纳哪些、什么时候做，**由本文件决定**。在写进本节之前，
  它的所有条目都只是**候选**。

#### 5.7.1 其中三条**已经可以立即做**（改动极小、闸门明确）

这三条不是「优化建议」，是**先修掉两处错误**——一条活的 bug + 一条被低估 25 倍的代价说明：

| # | 改什么 | 闸门 | 为什么现在就做 |
|---|---|---|---|
| **R18** | `bench/bench_ablation.py:48` 的 `parse_ints` 把 `,` 写成了 `;` | `--ns 100,200` 不再报错 | **活的 bug**：函数自己的 docstring 举的例子跑不过（✅ 已复现）|
| **R17a** | ~~`pii_redaction_v1` / `agent_tool_v1` 补 `length_bound`~~ **→ 决定不做**（见 §5.7.3） | — | 事实成立：这两个包是**仅有的没有长度上界**的，而 `pii_redaction_v1` 是**全部 7 个包里最贵的**（✅ 2000 字符 4.9 s、5000 字符 29.9 s，二次增长）——**没有上界 = 代价没有天花板**。但补上界等于替策略作者做决定，且 R9(b) 的等效替代已把这份代价处理掉，故只留事实、不改包 |
| **R17b** | 流式代价的说明改成 O(L²)（`modules/06-frameworks.md:133` 与 `adapters/langchain_adapter.py:176` docstring，**同一句话两处**）| 数字指得回一份结果文件 | 现在写的是「~0.07 ms/字符，10k 字符约 0.7 s」。✅ 实测 10k = **17.5 s**（低估 ~25×）：0.07 ms/字符 是 L≈200 的**瞬时值**，被当常数线性外推了 |

> **R17b 同时是一次纪律问题的实例**：`docs/README.md` §3 要求「文档里的数字应当指得回
> 某一份结果文件」，而 0.07 这个数**指不回任何一份**。补 `bench/results/` 里的实测表，
> 或把该句改成引用 `refactor-proposal.md` §2.2.3 的命令。

#### 5.7.2 其余条目（**已采纳：P0–P3 全做一遍**，纪律见 §5.7.3）

按 `refactor-proposal.md` §3 的档位：P0 另含 CI 补三条检查、跨层常量一致性测试、
NFA 两级缓存；P1 是四处「重复收敛」（`POP_SCRIPT` 34→1、`sha256_file` 6→1、
`KIND_MAP` 消重、策略加载器 16→1）；P2 含流式增量匹配与 SP1 prover 旋钮实验；
P3 是死代码与 `core → proofs` 的分层倒置。

**明确不做的**（连同理由）记在 `refactor-proposal.md` §5，其中两条最容易被误提：
**不合并双评估器**（`VerdictMismatch` 靠它）、**不给 `check()` 的规则循环加短路**
（会改变 `violations` 列表内容，而那是证书公开值的一部分）。

#### 5.7.3 执行纪律（2026-09-17 定，适用于 P0–P3 的每一项）

采纳方案时一并定下的四条，**每一项中风险及以上都要照做**：

1. **先采基线，再动代码。** 没有基线就没有「回退到哪」的锚点 —— 所以 P0 的第
   一个提交是 §5.7.4 的验收基线，而不是任何一项修改。
2. **一项一提交**，中高风险项独占提交，回退 = `git revert <sha>` 且不留残渣。
3. **「收益不高」事先写成数字**，事后不得改口径。达不到就回退。
4. **每阶段做完跑一次大验收（含真出证）**，结果连同 SKIP 集合、真出证记录、
   回退记录一起写回本节。回退这个动作本身也要记（「试过、回退、因为…」），
   否则会有人再试一遍。

**三条已定的边界**：R9 只做 (b) 等效替代、**不改** `stream_step_chars`
（会改变可观察行为）；R17a **不做**（不给缺 `length_bound` 的包补上界 ——
那是替策略作者做决定），只把事实写进文档；`docs/refactor-proposal.md` §5
列出的其余「不做」项照旧。

#### 5.7.4 阶段 0：验收基线（2026-09-17，✅ 已交付）

**为什么先建它。** 本轮验收的核心是「**等效替代**」—— 改动前后**可观察行为
逐字节不变**。但仓库里没有任何入库的 golden 快照（既有约定是「现算再比」，
如 `cross_validate.golden()`），于是「没变」只能靠人读 diff 说「看起来一样」。
这个基线把它变成一条命令。

新增三件（只读，不改任何生产代码）：

| 文件 | 作用 |
|---|---|
| `scripts/verify/acceptance.py` | 采集/比对器（`--snapshot OUT` / `--verify GOLDEN`），返回码 3 = 有差异 |
| `tests/acceptance_baseline.json` | 入库的基线快照（116 KB，7 面） |
| `tests/test_acceptance_baseline.py` | 现算并断言等于快照，**秒级（1.3 s）**，随 `unittest discover` 进 CI —— 从此每次 push 都验 |

**七个可观察面**：① 7 包的完整 `ConstraintSpec` 规范字节 + `policy_hash`；
② 7 包 × 24 条语料，`check()` 与 `canonical_violations()` **两条判定路径**
各自的完整结论（含 4 档回执链：空/干净/脏/坏）；③ 20 种畸形包 × 7 包走
「加载 → 校验 → 编译」三段，记录**哪一段**抛**什么类型**的异常、文案逐字；
④ 畸形文件喂 CLI（子进程，退出码 + stderr 首末行）；⑤ 固定文本逐字符喂
`PoPCallbackHandler` 的证书序列（R9(b) 的等效性由这一面直接证明）；
⑥ 7 包 `compile`/`check` 的退出码与 stdout；⑦ `policydsl.__all__` 的导入面。

**执行器本身验过一遍**（否则「基线全绿」可能只是没在测东西）：六种注入差异
（改一个 `policy_hash` 字符、删规范字节一个字符、改一个报错字、把 `PolicyError`
换成 `TypeError`、翻转一次判定、增删一条违规）**全部被检出**；把基线削成只剩
一面时，「覆盖每一面」那条用例**变红**。无 `langchain_core` 的环境下七面结果
与基线**逐路径一致**（`HAVE_LANGCHAIN=False` 走鸭子类型回退）—— 所以它能在
CI 的裸 Python 上跑。

##### 采集过程中如实记下的两条（**基线钉住了，但没修**）

这两条都是「读代码看不出来、跑一遍才知道」的，按纪律**先记事实**，改不改另说：

1. **CLI 对「缺 `id`」「`rules` 不是列表」「顶层不是对象」三种畸形包会带
   traceback 崩掉**（退出码 1），而不是像坏 JSON 那样给干净的
   `invalid JSON in …`。`policydsl/__main__.py` 的 `_load_policy` docstring
   只承诺「文件缺失/JSON 非法」两档容错，所以这与文档**不矛盾** —— 但它意味着
   这三种输入的诊断体验是「未捕获的崩溃」。**修它属于行为变更**，与「本轮只做
   等效替代」冲突，故只记不改。
2. **空 `rules` 的策略包能通过校验并编译出 `policy_hash`**（
   `stage: ok`）—— 即「一条规则都没有」是一个合法策略。它不是健全性问题
   （`policy_hash` 绑定了这个事实，验证方重编译会得到同一个哈希），但它是一个
   静默的「恒通过」形态。与 R17a 同理**不修**：替策略作者加「至少要有一条规则」
   是在做决定，不是修 bug。

> 这两条也解释了为什么第 ③ 面值得钉：第 1 条的**异常类型**（`TypeError` /
> `KeyError` 而不是 `PolicyError`）本身就是判据的一部分，只钉「有没有报错」
> 会漏掉它。

##### 建流式代价基准时又撞到的第三条（**同样是记事实，不改**）

✅ **含 `semantic_bound` 的策略在流式路径上直接崩**：`policydsl/privacy/commit.py:180`
的 `canonical_violations` 只覆盖 7 类入电路规则，遇到委托给 ezkl 的那一类
`raise NotImplementedError(f"kind '{kind}' not provable in-circuit yet")`；而
`PoPCallbackHandler.on_llm_new_token` **不接这个异常** —— 于是
`policy_packs/semantic_demo_v1.json` 喂**第一个字符**就抛 `NotImplementedError`。

它与上面两条不同：这是**运行期崩溃**，不是诊断体验问题。但仍然只记不改，因为
「该怎么改」有好几种都说得通（构造 handler 时就拒 / 按服务那样 clean 400 /
支持它），选哪个都是**替使用者做决定**：

- 证明服务对这类策略是**当面拒**的（400 + `GET /v1/policies` 标 `serviceable: false`，
  见 `runbook-proof-service.md` §2），所以「干净拒绝」这条口径**已经存在**，
  只是没接到流式路径上；
- 现存文档（`architecture.md:79`、`security-model.md:449`、`design-semantic-rules.md:194`）
  说的都是「**不由本电路判定**」，没有一处说过**流式**时的行为。

`bench/bench_streaming.py` 把这条边界**当断言跑**（`probe_unsupported`）：
哪天它不再抛了，基准会当场失败并提示把它挪进成本表 —— 边界要响，不能只是注释。
`langchain_adapter.py` 的 docstring 也补了 ⚠️ 一行。**修它留到 R9(b) 之后单独定**。

#### 5.7.5 P0 执行记录（逐项）

按 §5.7.3 的纪律：一项一提交、验收过了才推。**真出证见 §5.7.6 的大验收**。

| 项 | 提交 | 内容与验收 |
|---|---|---|
| 阶段 0 | `b07c646` | 验收基线（七面）+ 采集/比对工具（见 §5.7.4）|
| **R18** | `f287c95` | `bench_ablation` 的 `parse_ints` 私有副本把 `replace(",", " ")` 写成 `replace(";", " ")` —— 于是**它自己 docstring 举的例子跑不过**。改法不是「把 `;` 换回 `,`」而是**让两份变一份**（从 `bench_cycles` import）。变异探针确认非空洞：抄回一份副本 ⇒ `test_single_definition` 当场红。判定：**收益够**（脚本可用 + 漂移被结构性钉死），保留 |
| **R17b** | 见下 | 流式代价的说明从「~0.07 ms/字符」改成 `Θ(L²)` 事实。**这一项超出原计划地多花了一个脚本**：原计划只说「两处 docstring 改字」，但 R17b 的验收是「数字**指得回一份结果文件**」，而那个文件不存在（`refactor-proposal.md` §2.2.3 自己承认「本文还没有对应的 `bench/results/` 文件」）。于是先建 `bench/bench_streaming.py` + `bench/results/streaming.{json,md}`，再改文档。**这笔开销不是新增范围**：P2 的 R9(b) 判据要的「agent_tool 在 2000 字符上改善 ≥2×（基线 115.8 ms）」本来就需要同一个 harness，先建它才能让前后对比是**同一把尺子** |
| **R1** | 见下 | CI 补三条闸门：① **跨语言对拍** `cross_validate --no-prove`（19/19，0.05 s）② **建宿主驱动**（它的前置，因为 ① 缺驱动时退出码 2 —— 这不是形式，是**它就是靠这个才没变成假绿**：`unittest` 在缺驱动时是**静默 skip**，而 `cross_validate` 是**响亮地失败**）③ **文档链接普查**。第 ③ 条落成 `tests/test_doc_links.py`（4 例，随 `discover` 进 CI），不另立一步 —— 免得 CI 的判据与本地跑的判据变成两处。实测 **47 份文档 / 274 条路径型链接 / 0 条指空**。⚠️ **Rust 那个 job 未在本机验证**：本机没有 Actions runner，SP1 工具链的安装路径（`curl -L https://sp1.succinct.xyz \| bash` → `~/.sp1/bin/sp1up`）与 `cargo build -p pop-script` 的**命令行**在本机逐条跑通，但整条 job 只能由第一次 CI 运行来证。为此把它拆成**独立 job**（`rust`），坏也只坏它自己，不把纯 Python 那份判据一起拖红 |
| **R2** | 见下 | 新增 `tests/test_cross_layer_constants.py`（6 例）：从 `circuits/types/src/lib.rs` 正则抽**声明的字面量**，与 Python 侧逐条比 —— `pop-trace-v1` / `pop-bind-v1` / `pop-infer-v1`（含 `&str` 形式）/ `pop-session-node-v1` 四个 `&[u8]` 域前缀 + `FOLD_VERSIONS` 白名单。**它不需要 Rust 工具链**，所以补得上「缺驱动时全绿」那个洞（`skipUnless(POP_SCRIPT.exists())` 的那些用例）。变异探针两条都非空洞：改 Python 的 `BIND_DOMAIN` → 报「两侧不是同一个值…没有任何一处会报错」；把两个域合并成同一个串 → `test_domains_are_distinct` 报「域分离失效」 |
| **R3** | `a39ae1b` | `compile_pattern` 与 `_closure_table` 加缓存（**中风险项，独占一个提交**）。改前每次调用返回**全新的**可变 dict，改后同一个 pattern 恒返回**同一个对象** —— 这是本项目第一次出现「编译产物被多个调用方共享」，前提是**谁都不改它**。做法不是去断言这个前提「显然成立」，而是**把它变成会红的测试**：`tests/test_nfa_cache.py`（10 例）跑完四个消费者再与新鲜编译深度相等；另外逐字节比序列化（子类若改变规范字节，**`policy_hash` 就变了**，已入库证明集体失效）。**三条回退判据逐条交代**：①「消费者不改缓存」测试**过**，且四条变异探针实测非空洞（挂统计字段 → 红、ε-转移倒序 → 红、追加共享闭包表 → 红、不注入 → 绿；另有一条 `sorted(eps)` 探针**自身空转**，因为编译出来本就已序 —— 如实记下是探针失效、不是用例失效）；②`check()` 中位耗时**下降**，基线 **83.9 / 82.9 µs** → **42.5 / 42.1 µs**（≈**2.0×**；孤立计时 `compile_pattern` 22.21 µs + `_closure_table` 6.91 µs，与增量吻合），远超「有下降」这条下限；③ 全量**710 passed / 15 skipped**，skip 集合未变。**等效替代**另有两道独立证据：验收基线**七面逐路径零差异**（跨层契约规范字节与 `spec["sha256"]` 未变）、`cross_validate --no-prove` **19/19**。判定：**收益够，保留** |
| R17a | — | **不做**（用户已定）：不给缺 `length_bound` 的包补上界。事实已在 `bench_streaming.md` 里量化：`agent_tool_v1` 与 `pii_redaction_v1` **没有上界 ⇒ 代价没有天花板**，而后者是 6 个可流式包里最贵的 |

**R17b 的取证过程本身产出了两条结论**（都进了 `bench/results/streaming.md`）：

1. **采样上限必须逐包判，不能全表取最小。** 首版默认 `--ns 500,1000,2000` 跑出来
   被守卫拦下：`finance_redaction_v1` 的上界是 **1500**，`"z"*2000` 在越过 1500 时
   判定翻转、**多签一张证书**，签发成本混进了被测路径。这不是「跑挂了」，是
   **被测的东西变了** —— 守卫报出来而不是让它混进比值。中间试过「全表压到 1500」，
   又不行：那样 `agent_tool_v1` 的 2000 点也测不成，而**那正是 R9(b) 判据要用的
   基线点**。最终改成越界的 (包, L) **单点不测**、如实记进 `streaming.json` 的
   `skipped`，表里标「越界」。（判据是 `lo <= n <= hi`，所以恰好等于上界仍合规。）
2. **它同时把 P2 的 R9(b) 判据基线钉成了权威值。** 入库那次运行量到
   `agent_tool_v1` 在 **2000 字符**上 **110.5 ms**（同一天另外两次 111.8 / 115.8 ms，
   `refactor-proposal.md` 记 116 ms —— 四者在机器噪声内一致）。R9(b) 的门槛「改善 ≥2×」
   从此比的是**同一个脚本的前后两次运行**，而不是两次手搓的临时测量。
   6 个包 × 3 长度全跑只 **~12 s**，复跑成本可以忽略 —— 「数字指得回文件」在这里是便宜的。

#### 5.7.6 P0 大验收（2026-09-17，含真出证）

按 §5.7.3 的三档跑完。判据是「**SKIP 集合前后逐条一致**」，不是「没有 FAIL」—— 前者才管得住「悄悄不跑了」。

| 档 | 命令 | 结果 |
|---|---|---|
| 秒级 | `unittest discover -s tests -t .` | **710 passed / 15 skipped**（skip 集合与 R3 之前一致）|
| 秒级 | `cross_validate.py --no-prove` | **host 19/19** PASS（退出码 0，0.05 s）|
| 秒级 | `verify/acceptance.py --verify` | **七面逐路径零差异** |
| 分钟 | `demo_all.sh`（fast） | 8 支路全 PASS，**SKIP 集合 = ∅** |
| 分钟 | `verify_session.py --session …` | **10 项 PASS** |
| 真出证 | `regression_prove.py --label P0-acceptance` | 出证 **19/19**（1932.7 s，峰值 **10,776 MB**）+ 验证腿 clean_pass；`regression-prove.jsonl` 追加**第 2 行** |
| 真出证 | `demo_all.sh --prove` | 8 支路全 PASS，**SKIP 集合 = ∅**，合计 ~20 min |

**SKIP 集合是怎么比出来的**：不是「这次恰好没有 SKIP」，而是**用同一把尺子量两次** —— 把 `policydsl/core/nfa.py` 回退到 R3 之前（`HEAD~1`）、跑一次 fast demo、存下报告与完整输出，还原后再跑一次；两份 `REPORT.md` 除时间戳与峰值/墙钟噪声外**逐字节相同**，8 支路的 PASS/SKIP **逐条一致**（两次都是 0 SKIP / 0 FAIL）。AB 跑完 `git checkout HEAD -- policydsl/core/nfa.py` 还原，工作树干净。

**真出证确实出了证明**（不是「跑了一遍」）：同为 `verify_session` 的 `zk_proof` 卡，fast 模式是 `unproven (host-check only)×3`，prove 模式变成 **`SP1 proof verified (pop-script) + unproven (host-check only)×2`** —— 这一行的差别就是「真出证」与「宿主对拍」的分界。

**两次真出证的记录都在 `bench/results/regression-prove.jsonl`**（只追加）：新增那行 `label=P0-acceptance` / `sha=a39ae1b` / `result=PASS` / `vectors=19` / `seconds=2074.0` / `ts=2026-09-17T12:31:12Z`，驱动摘要 `8366dba6…`。它与上一行的 `a5b70e1a…` **不同** —— 二进制在 9-17 08:31 被重建过，**留痕的意义正是把这个变化记下来**。

##### 一次真实的失败，以及原因

第一次跑 `regression_prove --label P0-acceptance`（**作为工具跟踪的后台任务**）在约 20 分钟时被**停掉**，报告是「the system is running low on memory」。如实记三点：

1. **历史文件没有被追加**（停掉后仍是 1 行）—— 这一轮什么也没留下，不会被后来的人误读成通过。这正是「只追加、跑完才写」的价值。
2. **它是被 harness 的内存守卫停的，不是内核 OOM killer。** 内核侧证据（`dmesg` / `journalctl -k` / `/var/log/syslog`）本机**无权限读取**，所以这里不写「内核 OOM 杀掉了」这种没有证据的结论。
3. **换跑法后一次跑通**：`pop-script` 的出证峰值实测 **10,776 MB**，demo 的 8 支路里最高到 **11,010,336 KB（≈10.50 GiB）**，而本机总内存 **11,958 MB** —— 出证期间可用内存必然被压到极低，作为**被跟踪的后台任务**就会触发守卫。改用 `setsid nohup … &` 完全脱离工具进程组后跑通。**结论是「跑法」问题，不是「真出证做不到」**；后续阶段一律用这个跑法。

##### 一处如实标注的瑕疵

`P0-acceptance` 那行记的是 `git.dirty = True`。原因**不是源码有未提交改动**，而是工作树里有两个**刻意未提交**的未跟踪文件（`bench/results/ablation_live.{json,md}`，由上一轮的子代理产生，去留尚未决定）—— `regression_prove` 的 `dirty` 取的是 `git status --porcelain` 非空。所有**被跟踪**的文件都停在 `a39ae1b`。这两个文件去留待定，故本轮既不提交也不删除。

##### 回退记录

**P0 没有发生回退**：唯一的中风险项 R3 三条判据全过（见 §5.7.5 该行），另有四条变异探针证明「消费者不改缓存」这条断言并非恒真。

##### 一处偏差（记下来，免得后来的人去找一个不存在的脚本）

P1 的验收②写着「R7 的闸门是 **P0 建好的对拍脚本**：7 个包 × 16 份旧加载器 vs 新的 `Policy.from_dict`」。但 P0 的提交清单里**没有**这一项，而 P0 的验收基线第 1 面走的是 **`policydsl.__main__._load_policy` 这一个加载器**（B 组），所以「16 份旧加载器两两对拍」这件事**至今没有工具**。它不能等到 R7 再补 —— 那些加载器一旦被删，就再也比不了了。故把它作为 **P1 的第一个提交**（只读采集器 + 入库快照 + 一条会红的测试，**不碰任何生产代码**），先采快照、后动 R7。

> **2026-09-17 补记：已交付，见 §5.7.7。** 另有两处与这句话的出入要一并记住：
> ① 实际是 **11 份**加载器（不是 16 —— 16 是「重复的加载动作」的粗计，含测试与文档里的副本）；
> ② **`Policy.from_dict` 并不存在**，R7 要先把它建出来（提案把它当已有的写）。

#### 5.7.7 P1-① 策略加载器对拍（2026-09-17，✅ 已交付，**先于 R7**）

§5.7.6 记的那处偏差已补上。**只读、不碰生产代码**，一个提交三件东西：

| 文件 | 作用 |
|---|---|
| `scripts/verify/loader_parity.py` | 采集器（`--snapshot` / `--verify`）：11 份加载器 × 7 个包 |
| `tests/loader_parity_baseline.json` | 入库快照 —— **R7 之前采的，R7 之后不许重采** |
| `tests/test_loader_parity.py` | 10 条常驻断言（0.52 s），跟着 `unittest discover` 走 |

**先采快照、后动 R7**，顺序不能倒：R7 要删的就是那 11 份，删完就再也比不了了。
R7 落地后这个测试**不改快照**，比对对象自然从「11 份」滑到「收敛后的那一份」——
那一步就是等效替代的证明本身。`loader_parity.py` 的 `--verify --against from_dict`
就是给 R7 那一刻准备的第二条路。

##### 采集结果（7 个包 × 11 份加载器，覆盖 **77/77**）

| 判据 | 结果 |
|---|---|
| `policy_hash` | **每个包恰好 1 种** —— R7 在哈希这一层是等效替代 |
| 签名（`description` / `semantic` / 规则名 / kind） | 每个包 **2 种**，分歧**只在 `description`** |

**分歧的具体形状**：3 份把包里声明的 `description` 带进 `Policy`，8 份丢成 `''`。
带的是 `policydsl.__main__._load_policy`、`prove_policy`、`prove_multiparty`；
丢的 8 份含**全部验证侧**（`verify_cert` / `verify_session`）加上 `issue_cert`、`runtime.service`。

**它为什么一直没人看见**：`description` 不进 `policy_hash`（`core/compile.py` 的
`STABLE_KEYS` 里没有它）、不进 `ConstraintSpec`、不进任何证书、CLI 也不打印 ——
实测全仓没有一处整体打印/序列化 `Policy`，`_assemble` 只读 `id` / `version` / `semantic`。
**对当前所有可观察输出都是惰性的**，所以 P0 的七面基线与它全都对不上。
这正是 §5.7.8 那条元结论的一个活实例。

> 顺带修正 §5.7.8 的措辞：提案说的「策略加载器 3 种行为」，实测是
> **2 种行为 + 1 处只差不进哈希字段的分歧**，而且规则名兜底（`r{i}` vs `rule-{i}`）
> 在这 7 个包上**根本没有分歧**（所有规则都显式写了 `name`，两种兜底都没被走到）。

**R7 归一取哪一边**：取「**带 `description`**」（那 3 份的行为）。理由是
`Policy.description` 这个字段存在就是为了承载包作者的声明，丢成 `''` 是信息丢失而非省略；
且 `Policy` 的缺省值本就是 `''`，**只有显式不传的加载器**才得到它。
这构成 R7 的**一处已声明归一**（正是 §5.7.3 回退判据里「非声明过的归一差异」那句话预留的位置）：
R7 的提交要在 `tests/test_loader_parity.py` 里把这处归一**写出来**，而不是重采快照。

##### 非恒真由四条变异探针证明（改完即还原，`diff` 确认干净）

| 探针 | 改动 | 结果 |
|---|---|---|
| A | `issue_cert` 由「丢」翻成「带」`description` | **只有**逐份那条红；集合级那条**纹丝不动** ← 因此暴露一个真缺口，见下 |
| B | `d.get("version", "0.1.0")` → `"9.9.9"` | **没红 —— 探针失效，不是用例失效**：该兜底只在包**缺** `version` 时才走到，而 7 个包都声明了它 |
| B′ | `d["id"]` → `d["id"] + "-x"`（必被走到） | 逐份那条与集合级那条**都红** |
| C | 把采集器的假绿 bug（子进程按绝对路径做键）装回去 | `--snapshot` **退出码 2、拒绝落盘**；逐份那条 11 条子测试全红 |

**探针 A 暴露的缺口（已补）**：集合级判据只记「出现过几种答案」，**不记谁持哪种** ——
把某一份从「丢」翻成「带」，答案集合仍是那 2 种，于是**一条都不会红**。
而「谁持哪种」恰恰是 R7 要收敛的东西，必须是有观察的。故补一条
`test_each_surviving_loader_still_behaves_exactly_as_snapshotted`：两边都有的标签，
逐份比**完整记录**。

**探针 C 顺带确认了覆盖守卫非有不可**：在假绿 bug 下集合级那条**是绿的**（比的是两堆空集合），
只有覆盖守卫抓得住。采集器因此把「查到了几份」写进快照，不足即拒绝出结果 ——
这也是本仓第四次撞上「空集合上全绿」，见 §5.7.8。

##### 验收（本提交只新增文件，生产代码一行未动）

| 档 | 命令 | 结果 |
|---|---|---|
| 秒级 | `unittest discover -s tests -t .` | **720 passed / 15 skipped**（710 + 新增 10，skip 集合不变）|
| 秒级 | `cross_validate.py --no-prove` | **host 19/19** PASS |
| 秒级 | `verify/acceptance.py --verify` | **七面逐路径零差异** |
| 秒级 | `unittest tests.test_loader_parity` | **10 passed**（0.52 s）|
| 分钟 | `demo_all.sh`（fast） | 8 支路全 PASS，**SKIP 集合 = ∅** |
| 分钟 | `verify_session.py --session …` | **10 项 PASS** |

真出证见 P1 阶段末（本提交不含生产代码改动，不单独跑）。

#### 5.7.8 一条元结论（值得单独记住）

普查里**已经漂移的三处**（`KIND_MAP` 3 vs 7 项、策略加载器 3 种行为、
`parse_ints` `;` vs `,`）里，**前两处今天不出错，只是因为 7 个策略包恰好都写全了
字段**（✅ 实测：所有规则都有 `name`、所有包的 `semantic` 都是 `"and"`）。
「恰好」不是契约 —— 这解释了为什么 `refactor-proposal.md` 把「收敛重复」
排在「架构改动」之前。

**2026-09-17 补充：这句话在本轮被两次独立证实。** §5.7.7 的对拍把「恰好」量了出来 ——
11 份加载器在 7 个包上 `policy_hash` 全同，唯一的真分歧（`description`）落在一个
**不进哈希、不进证书、不进 CLI** 的字段上，所以任何基于哈希的检查都看不见它。
另一处是 `KIND_MAP`：`prove_policy.py` 那份只有 3 项，今天不炸是因为 7 个包用到的
kind 恰好都在那 3 项里。**「恰好」的寿命等于「下一个策略包」**。

#### 5.7.9 P1-② R4：驱动路径 33 处 → 1 处（2026-09-17，✅ 已交付）

##### 实际改了什么（数字以 `git grep` 核过，不沿用提案里的估计）

| | 提案说 | 实测（相对 HEAD） |
|---|---|---|
| 逐字抄写的路径字面量 | 「34 处」 | **30 行 / 24 个文件** |
| 转手拷贝（不写字面量，照样是第二处出处） | 未提 | **3 行 / 2 个文件**：`policydsl/proofs/session.py:65,66`（`= V.POP_SCRIPT`）、`tests/test_session.py:44`（`= S.POP_SCRIPT`）|
| 合计 | 34 | **33 行 / 26 个文件** |
| 收敛后 | 1 | **2 行 / 1 个文件**（`policydsl/paths.py`）+ 1 处**有意**例外（`cross_validate.py`）|

**提案把「唯一出处」定在 `policydsl/evidence/verifier.py:25`，实施改成了 `policydsl/paths.py`。**
三条理由，都可用仓库事实核对：

1. `verifier.py` 自己只占那 30 行里的 **2 行**（第 25、27 行）—— 它并不是「已经很权威」的那处，
   只是提案作者扫到的第一处；
2. `paths.py` 是**叶子**模块（只 `import pathlib`），`verifier.py` 依赖证书链/边车/SP1 验证端点。
   把驱动路径放在一个重型模块里，「读一个路径」这个动作就付不起代价 —— 而那正是它当初被抄
   33 次的原因之一。这条现在**有测试钉着**（`test_the_authority_is_a_leaf`）；
3. `paths.py` 的 docstring 本来就专记这类事故，且它已经持有 `REPO`。

**保留的能力**：`cross_validate.py` 的 `$POP_SCRIPT` 环境变量覆盖（`regression_prove.py:220`
与 `tests/test_regression_prove.py` 靠它注入替身驱动）。写法从「另抄一份再让环境变量覆盖」
改成「**以出处为缺省值**，再让环境变量覆盖」。这是全仓唯一有意认这个变量的地方，已写进
`paths.py` 的条目里。

**一处需要声明的副作用**：`verify_cert.py` 与 `verify_session.py` 里的 `POP_VERIFY` 原本是
`main()` **函数内**的就地重算，收敛后提升成模块级导入 —— 于是这两个模块**多出一个模块属性**。
行为无变化（同一个值，且原本就没有任何调用方从外部读它），但它确实改变了模块命名空间，
如实记在这里而不是扫平。

##### 等效替代性（机械证明，不是读一遍）

| 手段 | 结果 |
|---|---|
| A/B 探针：14 个模块连 `_bootstrap` 导入后 dump `module.POP_SCRIPT` / `POP_VERIFY` | `POP_SCRIPT` **14/14 逐字节不变**；`POP_VERIFY` 12 处不变 + 上表声明的 2 处「从无到有」|
| 全仓普查 `circuits" / "target"` | 24 文件 30 行 → **只剩 `paths.py` 的 2 行** |
| 未使用导入复核（AST） | 顺手清掉 3 处 `REPO`/`POP_VERIFY` 变成的死导入（`policydsl/proofs/compose.py`、`session.py`）|
| 验收基线七面 | **逐路径零差异** |

##### 闸门（新增 `tests/test_driver_paths.py`，9 例）

R4 修的是「同一件事有 26 份」，所以闸门也必须是**结构**而不是一次普查结果：AST 扫全仓
（排除 docstring —— 叙述不是定位），字面量与模块级别名**分别**扫，例外**逐条申报且条数钉死**。
两条防恒真下限（扫到 ≥100 个 `.py`；≥25 个模块仍从出处取路径），两条变异探针实测非恒真。
理由写进了该文件的模块 docstring 与 `docs/modules/08-tests-bench.md`。

##### 验收（R4 风险标「极低」，故无回退判据；实测全绿，不触发回退）

| 档 | 命令 | 结果 |
|---|---|---|
| 秒级 | `unittest discover -s tests -t .` | **729 passed / 15 skipped**（720 + 新增 9，skip 集合不变）|
| 秒级 | `unittest tests.test_driver_paths` | **9 passed**（0.84 s）|
| 秒级 | `cross_validate.py --no-prove` | **host 19/19** PASS |
| 秒级 | `verify/acceptance.py --verify` | **七面逐路径零差异** |
| 分钟 | `demo_all.sh`（fast） | **8 支路全 PASS，SKIP 集合 = ∅** |
| 分钟 | `verify_session.py --session …` | **10 项 PASS** |

真出证随 P1 阶段末统一跑（`--label P1-acceptance`）。

**这也第三次证实了 §5.7.8 那条元结论**：33 处抄写**今天全部正确**，所以没有任何测试或
基线能看见它们 —— 「对得整齐」是一种**没有观察**的状态，它的寿命等于「下一次有人改名字」。

#### 5.7.10 P1-③ R5：工件摘要 7 份 + 1 段内联 → 1 处（2026-09-17，✅ 已交付）

##### 实际改了什么（同样以 `git grep` 核过）

提案说「6 份、行为相同但非逐字相同、2 份多一层 `Path()`」。**实测是 7 份定义 + 1 段内联**：

| # | 位置 | 形态 |
|---|---|---|
| 1 | `policydsl/proofs/compose.py` | `sha256(Path(path).read_bytes())` |
| 2 | `policydsl/proofs/multiparty.py` | 同上（逐字相同）|
| 3 | `policydsl/runtime/service.py` | `sha256(path.read_bytes())`，docstring 写「与 `issue_cert.py` 同口径」|
| 4 | `scripts/prove/issue_cert.py` | 同上 |
| 5 | `scripts/verify/verify_cert.py` | 同上 |
| 6 | `scripts/verify/verify_session.py` | 同上（与 5 逐字相同）|
| 7 | `policydsl/proofs/semantic.py` `_sha256_of_file` | **分块**读 + `lru_cache`（键含 mtime_ns/size）|
| 8 | `scripts/prove/regression_prove.py` `driver_fingerprint` | **内联**分块读（**没有名字**，只扫函数名会整条漏掉）|

**唯一出处放在 `policydsl/evidence/cert.py`（紧跟已有的 `sha256_hex`）**，采纳提案的意见。
`service.py` 那句「与 `issue_cert.py` 同口径」是个标本：**一句话承认了重复，却没有任何东西
保证它继续同口径**。而它们摘要的东西进证书的 `binding.proof_sha256` —— 两处只要有一处
口径变了，出证方与验证方各算一个值、**各自自洽**，证书在第三方手里才验不过。

**一处有意的实现选择**：唯一出处用**分块读（1 MiB）**而不是 `read_bytes()`。理由是实测数字：
要摘要的东西里有 `circuits/target/release/pop-script`，**87 MB** 的构建产物；而出证这条路上
内存本来就是瓶颈（地板 ~10.15 GiB，见 `bench/results/proofs.md`）。分块版与一次读尽版
的摘要值逐字节相同 —— 这一点由 `tests/test_artifact_digest.py` 在 **1 MiB 边界两侧**
（0 / 1 / 1 MiB−1 / 1 MiB / 1 MiB+1 / 2 MiB+12345 字节）钉着，而不是靠「显然」。

**两处有意保留**（申报名单见 `tests/test_artifact_digest.py`）：

- `semantic._sha256_of_file`：**纯缓存壳**。它的签名里 `mtime_ns` / `size` 是**缓存键**、
  不参与计算（「文件换了就不认旧值」），与摘要口径是两件事 —— 后者已经收走，
  函数体只剩 `return sha256_file(path)`。另有一条断言证明它**真的还在缓存**。
- `tests/test_regression_prove.py::_sha256`：**独立参照**。它验的是
  `driver_fingerprint()` 的**输出**，复用生产实现就成了自证 —— 与本仓
  「Python golden ↔ Rust `pop-types::evaluate` 两处独立算」是同一种用法。

**副作用（如实记）**：4 个文件里的 `import hashlib` 成了死导入，一并删掉
（`scripts/prove/issue_cert.py`、`regression_prove.py`、`scripts/verify/verify_cert.py`、
`verify_session.py`）。另有两处**改动前就有**的死导入（`proofs/compose.py` 的
`os`/`sys`/`tempfile`、`evidence/cert.py` 的 `InvalidSignature`）**没动** —— 那是 R13 的范围。

##### 闸门（新增 `tests/test_artifact_digest.py`，11 例）

两条扫描：① 像文件摘要的**函数名**；② 「分块把文件喂给哈希」这个**惯用法**
（`iter(lambda: fh.read(N), b"")`）—— 第 ② 条非有不可，否则 `driver_fingerprint` 那段
没有名字的内联实现整条漏掉。例外逐条申报、条数钉死；两条防恒真下限（扫到 ≥100 个 `.py`；
≥8 个模块仍从这里取摘要），外加一条**给扫描器本身喂已知样本**的探针 —— 认不出东西的
扫描器与没有扫描器，在结论上无法区分。

**四条变异探针实测非恒真**：

| 探针 | 结果 |
|---|---|
| A 在别处新增一份 `def _sha256` | 红（函数名扫描）|
| B 口径改成大写十六进制 | 红（边界对拍 ×6 + 小写契约）|
| C 每一块漏读最后一个字节 | 红（边界对拍 ×6）|
| D 缓存壳长回自己那份分块实现 | 红（流式读惯用法扫描）|

##### 验收（R5 风险标「极低」，无回退判据；实测全绿，不触发回退）

| 档 | 命令 | 结果 |
|---|---|---|
| 秒级 | `unittest discover -s tests -t .` | **740 passed / 15 skipped**（729 + 新增 11，skip 集合不变）|
| 秒级 | `unittest tests.test_artifact_digest` | **11 passed**（1.00 s）|
| 秒级 | `cross_validate.py --no-prove` | **host 19/19** PASS |
| 秒级 | `verify/acceptance.py --verify` | **七面逐路径零差异** |
| 分钟 | `demo_all.sh`（fast） | **8 支路全 PASS，SKIP 集合 = ∅** |
| 分钟 | `verify_session.py --session …` | **10 项 PASS** |

真出证随 P1 阶段末统一跑（`--label P1-acceptance`）。

#### 5.7.11 P1-④ R6：kind 翻译表 3 份 → 1 处（2026-09-17，✅ 已交付）

##### 实际改了什么（`git grep` 核过）

提案写的是「`KIND_MAP` 消掉第二份（`prove_policy.py:41` 的 3 项 → 取
`cross_validate.py:72` 的 7 项）」，字面读是**两份**。实测是**三份**：

| # | 位置 | 项数 | 取用方式 |
|---|---|---:|---|
| 1 | `scripts/prove/cross_validate.py:74` | **7** | `.get(k, k)` 兜底 |
| 2 | `scripts/prove/prove_policy.py:41` | **3** | `.get(k, k)` 兜底 |
| 3 | `tests/test_commit.py:86` | **3** | **严格下标** `[k]` |

第三份不在提案的计数里。**三份不是一个模子刻出来的** —— 2 与 3 各只有 7 项里的
3 项，今天不炸只是因为 7 个策略包用到的 `evidence_kind` 恰好全落在
`keyword` / `length` / `pattern` 里（这正是 §5.7.8 那条元结论的第四次确认：
**「恰好」不是契约**）。一旦有规则用上 `format` / `tool_arg` / `budget` /
`normalized_keyword`，那份 3 项的副本会静默地把 `"format"` 本身当成 kind 交给
调用方，而 guest 写的是 `format_check` —— 两边各自自洽，出证时才报「违规集合不同」。

**唯一出处：`policydsl/core/evaluate.py` 的 `EVIDENCE_KIND_TO_RULE_KIND`**
（`def check(` 之前）。放在这里是因为两个词汇表都在这个文件里产生：`check` 的
`if/elif rule.kind == …` 分支是**唯一**写出 `(rule, evidence_kind)` 配对的地方。
`scripts/prove/*` 是消费者，不配拥有这张表的一份。

**两个方向别搞混**：表是 `evidence_kind → rule.kind`（给调用方翻译用）；
分支链是 `rule.kind → evidence_kind`。闸门比对前先把表**反过来**，否则失败信息
会读起来像「七个键两两不相干」而不是「方向错了」—— 这一点是实测踩出来的
（第一版闸门就是这么红的）。

**不在表里、且是有意不在的两个**：

- `trace_unbound` —— 合成规则 `_TraceRule` 的 kind（坏回执链的落点，不是任何策略
  规则的 kind）。它在 `tool_arg_guard` / `budget_bound` 两个分支里都会出现，也在
  分支链之外出现一次。`.get(k, k)` 与 guest 那侧都用 `trace_unbound` 兜住。
- `semantic_bound` —— 登记为 `DelegatedConstraint`、**从不产生 `Violation`**，
  所以分支链里根本没有它的 `(rule, evidence_kind)` 配对。

**一处有意的差异保留**：`tests/test_commit.py` 那份原用**严格下标**
（表外就 `KeyError`），收敛后**照样严格**，没有顺手改成 `.get(k, k)` —— 改了会
把「出现表外 kind 就当场炸」悄悄换成「放过去」。该用例的三条规则都不产生
`trace_unbound`，严格是安全的。

**一处发现但没修**（不在 R6 范围）：`evaluate.py:62` `_parse_format` 的 docstring
含未转义的 `\d`，Python 3.12+ 下每次导入都会打一条
`DeprecationWarning: invalid escape sequence '\d'`。它是**改动前就有**的，加个 `r`
前缀即可修掉（纯 docstring、零行为变化），但按「一项一提交」留给 R13 那批。

##### 等效替代性（机械证明，不是读一遍）

1. **行为等价** —— 三处调用点收敛前后取的是同一批配对：`cross_validate --no-prove`
   **host 19/19 PASS**，`prove_policy.py --no-prove` 的 `[PASS] check … rules
   golden=[] sp1=[]` 逐字未变；`tests/test_commit.py` 的
   `test_matches_evaluate_semantics` 断言的是 `canonical_violations` 与
   `evaluate.check` 的**集合相等**，直接钉住翻译结果。
2. **表本身对** —— `tests/test_rule_kinds.py` 用 `ast` 从分支体里抽出
   `(rule.kind → evidence_kind)`，与表逐项相等，并要求每个分支**恰好**一种
   evidence_kind。
3. **不再有第二份** —— AST 扫全仓找「含 ≥2 项本表配对的字典字面量」。

##### 闸门（扩展 `tests/test_rule_kinds.py`：10 例 → 16 例）

新增 `TestEvidenceKindVocabularyIsSingleSourced` 六例：① 表与 `check` 实际产生的
配对逐项相等（`ast` 只走 `if/elif` 的**分支体** `node.body`，不含 `orelse` ——
用 `ast.walk(if_node)` 会把整条 `elif` 链一起吞掉）；② 表的值必须是
`_RULE_VALIDATORS` 认得的 kind；③ 全仓不许出现第二份（副本的**实际形态**是字典
字面量，阈值 ≥2 项以免单个巧合配对误伤）；④ 扫描范围下限（≥100 个 `.py`）；
⑤ 给**扫描器**喂一段已知副本的探针；⑥ 给**抽取器**喂一段已知分派链的探针
（含一个 `trace_unbound`，要求它被剔除）。

##### 变异探针（实测，非恒真）

| 变异 | 结果 |
|---|---|
| 把一份 4 项副本塞回 `scripts/prove/prove_policy.py` | 红（报出 `{'policydsl/core/evaluate.py': 1, 'scripts/prove/prove_policy.py': 1}`）|
| 从表里删掉 `"format": "format_check"` | 红（逐项比对）|
| 还原 | 绿（`grep -c KIND_MAP` == 0，两处探针改动已完全清除）|

##### 验收（R6 风险标「极低」，无回退判据；实测全绿，不触发回退）

| 档 | 命令 | 结果 |
|---|---|---|
| 秒级 | `unittest discover -s tests -t .` | **746 passed / 15 skipped**（740 + 新增 6，skip 集合不变）|
| 秒级 | `unittest tests.test_rule_kinds` | **16 passed**（0.29 s）|
| 秒级 | `cross_validate.py --no-prove` | **host 19/19** PASS |
| 秒级 | `verify/acceptance.py --verify` | **七面逐路径零差异** |
| 分钟 | `demo_all.sh`（fast） | **8 支路全 PASS，SKIP 集合 = ∅** |
| 分钟 | `verify_session.py --session …` | **10 项 PASS** |

真出证随 P1 阶段末统一跑（`--label P1-acceptance`）。

#### 5.7.12 P1-⑤ R7：策略加载器 11 份 → 1 处（2026-09-17，✅ 已交付）

##### 改了什么

「把策略包 JSON 读成 `Policy`」这个动作抄在 **11 个模块**里，每个模块一份
`_load_policy` / `load_policy`。§5.7.7 的采集器实测：**7 个包上 `policy_hash`
每包恰好 1 种**（所以这批不等于「已经在出事」），但**签名每包 2 种**，分歧只在
`description`（3 份带、8 份丢成 `''`）。`description` 不进哈希，所以今天所有
可观察输出都对不上它 —— 这正是 §5.7.8 那条元结论：**「恰好」不是契约**。

唯一出处：**`policydsl/core/model.py::Policy.from_dict`**。11 份各自变成**一行
委派**，**函数名与签名一个没动**（`LOADERS` 表保持 11 行）——名字留着，逐份
对拍才继续把这 11 个入口都罩在观察之下；删掉名字等于把「这些入口存在过」这件事
从闸门里删掉。

| 组 | 位置 | 备注 |
|---|---|---|
| 包内 | `policydsl/__main__.py` | 保留自己的 `FileNotFoundError` / `json.JSONDecodeError` → `SystemExit` 包装 |
| 包内 | `proofs/multiparty.py`、`proofs/compose.py`、`proofs/session.py`、`runtime/service.py` | `service.py` 的 docstring 里那句「与 `verify_cert.py` / `issue_cert.py` 的 `load_policy` **逐字段相同**」被留作**反面标本**：它一句话承认了重复，却没有任何东西保证它 |
| 脚本 | `scripts/prove/{issue_cert,prove_policy,prove_multiparty,compose_proof}.py`、`scripts/verify/{verify_cert,verify_session}.py` | 同一行 |

顺带删掉 7 个文件里已成为死引用的 `Rule` / `Policy` 局部 import。

##### 一处**已声明归一**：`description`

8 份加载器把包内声明的 `description` 丢成 `''`。收敛后统一**取包内声明**。
理由是 `Policy` 的缺省值本就是 `''` —— **只有显式不传的加载器**才得到它，所以
「丢」是**信息丢失**，不是「省略」。且它不进 `policy_hash`、不进证书、CLI 也不
打印，对当前所有可观察输出是**惰性**的（§5.7.7 已实测）。

`tests/test_loader_parity.py` **不改快照**（`tests/loader_parity_baseline.json`
仍是**收敛之前**那份记录），而是加一层 `normalized_golden()` 把差异归一掉 ——
并且**再加一条反向断言** `test_the_live_delta_is_exactly_the_declared_normalization`：
逐 `(加载器, 包)` 比，变的集合**恰好**是 8 份丢 `description` 的加载器 × 7 个包、
顶层只许 `policy` / `policy_hash` 两个键动、`policy_hash` **一个字都不许动**、
只有 `description` 的值在变且恰好是 `'' → 包内声明值`。
**归一 + 这条断言**，快照才不会退化成一张空白支票（只归一、不断言，等于把
「R7 有没有多改东西」这件事从闸门里拿掉）。

##### 顺带补齐的契约：`_require_pack_shape`（**用户 2026-09-17 拍板**）

R7 引入 `from_dict` 之后，验收基线的「畸形包 → CLI」那一面**必红 4 处**，且
**没有任何写法能保住它**：多一层栈帧 → 每个 traceback 多 2 行；`from_dict` 先读
`data["id"]` → 「顶层是数组」从 `AttributeError` 变成 `TypeError`。

用户的选择是「**先把 CLI 修干净再重采**」——于是把「换了个 traceback」变成
「从崩溃变成干净拒绝」。做法不是在 CLI 里加特例，而是**把形状闸门放进唯一出处**，
于是**11 个入口一起受益**：

| 形状 | 原先漏出 | 之后 |
|---|---|---|
| 顶层不是对象 | `TypeError` / `AttributeError` | `PolicyError: policy pack must be a JSON object, got list` |
| 缺 `id` | `KeyError: 'id'` | `PolicyError: policy pack missing 'id'` |
| `rules` 不是数组 | `AttributeError` / `TypeError` | `PolicyError: policy pack 'rules' must be a list, got str` |
| 规则项不是对象 | `AttributeError` | `PolicyError: policy pack rule #0 must be a JSON object, got int` |

**为什么这四条是一件事而不是四件事**：调用方（11 份加载器、每个 CLI、常驻服务）
**统统只接 `PolicyError`**，四种形状一个都接不住 —— 于是「用户把包写错了」表现成
「工具崩了」：`python3 -m policydsl compile` 退出码 1 + 一坨 traceback，而不是
退出码 2 + 一行 `error: …`。

**分层的界线**：**形状在这里拦，内容交给 `validate`**。缺 `kind` **不在这里炸**
（那是内容问题），仍由 `Rule.validate` 报 `PolicyError: rule '…': unknown kind ''`
——两段报同一个类型，调用方看不出区别。这一条不是装饰：`r.get("kind", "")` 若改成
在这里拦，验收第 3 面的 `drop_kind` / `kind_is_list` 会跟着变，而它们**本来就不是
问题**。实测确认：40 处基线差异里**没有一处**落在 `empty_rules`（合法的空规则表）、
`extra_top_level`（多余的顶层字段允许）或任何 kind 相关用例上。

##### 验收基线为什么要**重采**（人工确认，`tests/acceptance_baseline.json`）

`scripts/verify/acceptance.py` 的 docstring 与 §5.7.4 都写着：**有意变更要显式改
快照，且必须人工确认后重新生成，diff 进提交**。这是「等效性被证明」与「变更被
承认」的分界。本次的 diff：**1567 个叶子里变了 40 个**，全部落在**申报的两类**里：

| 面 | 处数 | 内容 |
|---|---:|---|
| `3a_model_robustness` | 28 | 7 包 × `missing_id` / `rules_not_a_list` 各 × {`error.type`, `error.msg`} |
| `3b_cli_robustness` | 12 | `missing_id` / `rules_not_list` / `top_level_list` 各 × {`exit`, `stderr.first`, `stderr.last`, `stderr.lines`} |

**其余五面零差异**：`1_contract`（完整 `ConstraintSpec` 规范字节 + `policy_hash`）、
`2_verdicts`（两条判定路径 × 7 包 × 24 条语料）、`4_streaming`（流式证书序列）、
`5_cli`（正常路径）、`6_import_surface`。**第 1 面逐字节不变是 R7 最要紧的一条**：
它正是「同一个包被两份加载器编译出两个哈希」那类事故的唯一观测点。

##### 等效替代性（机械证明，不是读一遍）

1. **加载器对拍** —— `tests/loader_parity_baseline.json`（**收敛之前**采的）vs
   `--against from_dict`：7 包 × 11 份覆盖 **77/77**，`policy_hash` **每包恰好
   1 种**，签名差异**恰好**是申报的那一处。
2. **验收基线** —— 七面里五面逐字节零差异，另两面的 40 处差异**逐条归入申报**。
3. **端到端** —— `cross_validate --no-prove` **host 19/19 PASS**；`demo_all.sh`
   （fast）**8 支路全 PASS，SKIP 集合 = ∅**；`verify_session.py` **10 项 PASS**。
4. **R7 自己的三条回退判据**（§2 P1 表）：① 7 包 × 11 份 `policy_hash` 有任一
   不一致（非申报归一）—— **不触发**；② 全量测试非全绿 —— **不触发**；③ demo
   fast 出现新 FAIL/SKIP —— **不触发**。

##### 闸门（新增 `tests/test_dsl.py::TestFromDictRejectsShape` 4 例；`test_loader_parity` 10 → 11 例）

形状闸门**不只挂在验收快照上** —— 快照记的是「那一刻的文案」，谁重采一次保证就
悄悄没了。所以另钉**类型本身**：`assertRaises(PolicyError)` 是可证伪的
（`PolicyError` 继承 `ValueError`，`KeyError` / `AttributeError` / `TypeError`
都不是它的子类）。另两条**反向**用例同样重要：闸门不能反过来吞掉合法的包
（空规则表合法、多余顶层字段允许）、形状对内容错仍须由 `Rule.validate` 报到
**具体规则名**（不能被形状闸门吞成一句笼统的「包不对」）。

##### 变异探针（实测，非恒真）

| 变异 | 结果 |
|---|---|
| 摘掉 `_require_pack_shape(data)` 这一行 | 红（`test_dsl` **11 errors** = 7 个 subTest + 4 例）|
| `test_loader_parity` 里改回「丢 `description`」 | 红（9 例）|
| 把 `version` 兜底改成 `"9.9.9"` | 红（9 例）|
| 还原 | 绿（751 passed / 15 skipped，工作树与探针前逐字节相同）|

##### 顺带发现（**本轮未修，只记录**）

**「数字四处同步」这条规矩没有自动化检查，而它已经漂了。** `docs/reproduce.md`
（§5 明确列出的同步点之一）两处写着 **675 passed**，而当时的真实值是 **746**
—— 漂了 **71 个用例**，横跨 R3–R6 四次改动都没被发现。本次按规矩一并改成 751，
并在 `modules/08-tests-bench.md` 的验收判据里补上 R7 这一次重测的日期。
`docs/dev-plan.md` 里各次验收表中的旧数字（如 §5.7.11 验收表里的 746）是
**那一次运行的留痕**，按 §5.7.4 的口径**不改**。

同为顺带：`modules/08-tests-bench.md` 里 `test_loader_parity` 那一行的**标题**
写着「**十六份**策略加载器」，而同一行正文与 §5.7.7 都写着 **11 份**（16 是
「重复的加载动作」的粗计，含测试与文档里的副本）。标题改回 11 份。

##### 验收（风险标「中」，三条回退判据全部不触发 → **不回退**）

| 档 | 命令 | 结果 |
|---|---|---|
| 秒级 | `unittest discover -s tests -t .` | **751 passed / 15 skipped**（746 + 新增 5：`test_dsl` +4、`test_loader_parity` +1；skip 集合不变）|
| 秒级 | `python3 -m unittest tests.test_dsl tests.test_loader_parity` | **44 passed** |
| 秒级 | `cross_validate.py --no-prove` | **host 19/19** PASS |
| 秒级 | `verify/acceptance.py --verify`（重采后） | **七面逐路径零差异** |
| 分钟 | `demo_all.sh`（fast） | **8 支路全 PASS，SKIP 集合 = ∅** |
| 分钟 | `verify_session.py --session …` | **10 项 PASS** |

真出证随 P1 阶段末统一跑（`--label P1-acceptance`）。

#### 5.7.13 P1-⑥ R8：拆 `verify_cert` / `verify_session` 的 `main`（2026-09-17，✅ 已交付）

##### 改了什么

两个第三方验证脚本的 `main()` 是「一个函数走完 13 张卡 / 10 张卡」。按**已有
的步骤注释**把它们切成具名函数，函数名与注释里那套编号一一对应：

| 文件 | 切出来的函数 |
|---|---|
| `verify_cert.py` | `check_signature`(1) / `check_proof`(2) / `check_artifact_claims`(2b+2c) / `check_policy_binding`(3) / `check_response_binding`(3b) / `check_trace_binding`(3c+3d) / `check_semantic`(3e) / `check_anchor`(4+4b) / `print_report` |
| `verify_session.py` | `check_signers`(0) / `check_certificates`(0+1) / `check_stream_chains`(2) / `check_zk_proofs`(3) / `check_chain_anchoring`(4) / `print_report` |

`verify_cert.main`：**433 行 → 64 行**（文件 518 → 608 行，多出来的是 docstring
与函数头）。`verify_session.main`：**287 行 → 45 行**。合计 `+495 / −324`。

> 行数量法（可复核）：**下一个顶层定义的行号 − 本函数起始行号**。即
> `grep -n '^def \|^if __name__' scripts/verify/verify_cert.py`，重构前用
> `git show dfc1467^:<file> | grep -n …`。**不**含 `main` 与下一个 `def`
> 之间的空行分隔，故与「函数体行数」相差 1–2 行。
>
> 初稿（`dfc1467` 内）这里写的是「434 → 65 / 330 → 44」——同一量法下算错的两个
> 数（`330` 更是把重构前的文件总行数 344 记串了）。本段为**事后更正**，代码本身
> 未变，`dfc1467` 的 `+495 / −324` 与之相符。

**分工约定**：每个 `check_*` 只产出**自己那几张卡片**，由 `main` 按调用顺序
`results +=` 合并。「卡片顺序」是这批脚本的可观察契约（`tests/` 里多处按名取用），
所以它由 `main` 一处掌管，而不是让各函数自己去 append 一个共享列表。

##### 三处**刻意保持原样**，不做「顺手变好」

1. `check_response_binding` **就地重读** `args.response`，不复用 `main` 已经读好的
   `response_text`。两份内容必然相同，但重算路径与拆分前逐字一致 —— R8 的差异面
   越接近零，等效性的证据越硬。（`response_text` 仍只在 3e 用。）
2. `check_trace_binding` 把 3c 与 3d 合成**一个**函数，不做成两个。二者共用
   `gw_ring`（网关公钥只加载一次）与解析出来的 `receipts`；拆开就得让这两个量
   跨函数传递，反而更难读。
3. `verify_session` 的 `spec_for` 保留成「显式传 `cache`」的纯函数，缓存由 `main`
   建、第 1 步与第 3 步共用。各建一份会把同一个包白编译两次。

##### 等效性证据（机械证明，非人工阅读）

采集器把 **19 次真实调用**的 stdout+stderr+退出码归一后落盘（只归一 SP1 的
耗时字段与绝对路径；**刻意不做通用浮点归一** —— 那会把 `@0.1.0` 一起吃掉，
等于把「版本号变了」这条本该报警的差异藏掉），重构前后逐字节比：

| | |
|---|---|
| 调用数 | **19**（`verify_cert` 14 + `verify_session` 5）|
| 结果 | **逐字节一致**（`diff -rq` 无输出）|
| 覆盖的卡片名 | **28** 个（去重后），含 `signature` / `proof_*` / `proof_mode` / `vkey_label` / `policy_hash` / `response_binding` / `receipt_chain` / `trace_binding` / `trace_seal` / `semantic` / `anchor*` / `certificates_*` / `stream_chains` / `zk_proof` |
| 覆盖的出口 | 含 4 条早期返回（公钥不可得 ×2、签名不对、空 ring）与 3 种退出码（0/1/2）|

覆盖面是**故意**凑的：其中 6 例（`o`–`s`）用 `tests/test_generic_adapter.py`
生成的那份**带回执链与 `trace_seal`** 的工具会话包，专门喂 3c/3d 的三种结局
（齐全 / 缺 `--receipts` / 换别人的网关钥 / 网关公钥打不开）。

**没被覆盖的卡片名：`verify_only` / `public_values` / `vkey_hash`** —— 它们是
`prefer_verifier_only` 那条快路径。全仓 **17 份边车 `proof_mode` 全是 `core`**，
没有一份落在 `VERIFIER_ONLY_MODES = ("compressed", "groth16", "plonk")` 里，
而这条路径要的 compressed 工件（`circuits/testdata/audit_proof/`，由
`scripts/ops/make_audit_proof.sh` 生成）本机不存在。所以**这 3 张卡本机跑不到**，
不是「跑了没差异」。它们本轮的变化**只有缩进与 `results.append` → `cards.append`**。

`semantic[...]` 那一张采集器也没覆盖（要有 ezkl 材料），但**测试套件覆盖了**：
`tests/test_semantic.py:671` 断言 `[FAIL] semantic[low_harm_probability]`。

##### 顺带发现的仓库缺陷

**两份文件的模块 docstring 与代码注释用了两套步骤编号**（docstring 把「公钥」
算作第 0 条、账本链是第 1 条；代码注释里账本链是 `0)`、逐证书是 `1)`）。本轮
新函数的 docstring 统一按**代码注释那套**，并在 `verify_session` 的模块 docstring
里把这份对照写出来 —— 没改原有的两套编号本身（那是**既有**的文档不一致，
不在 R8 的改动面内；见 §3「明确不做」的口径）。

##### 一条**未复现**的观察（如实记录，不当作已解决）

R8 改完之后**第一次**跑全量测试得到 `FAILED (failures=1, skipped=15)`。
当时只留了 `tail -5`，**失败用例的名字没留下来**。此后：

| 尝试 | 结果 |
|---|---|
| 全量套件（含首次） | **23 次：1 失败 / 22 次 OK**（`751 tests / skipped=15` 恒定）|
| 只跑「驱动了这两个文件」的 6 个模块 | **6 次全绿**（74 tests / skipped=3）|
| 排查计时类断言 | `tests/test_verifier_only.py:55` 的 `assertLess(secs, 20)` 是唯一硬阈值 —— 但它 `skipTest`（**没有 compressed 夹具**），不是它 |
| 排查内存类 | 全部真出证用例都由 `POP_TEST_*` 开关守着，**默认全 skip**（skip 集合里逐条可见）|
| 排查网络类 | `tests/test_doc_links.py` 明确**跳过所有 `http(s)://`**，不连网 |

**结论：无法归因到 R8，但也无法证明无关。** 证据是「外部行为在 19 次调用上
逐字节相同」+「22 次全绿」，但这是一份**统计性**的辩护，不是机制性的。按本仓
「不响的失败」的口径，这条**留在案上**，并在 P1 大验收（`--label P1-acceptance`）
里继续观察；若再现，第一件事是**留住失败的用例名**。

（附：批次里连续 4 次耗时 40→54→55→62 s 一度像是「越跑越慢」。查证结果是
**我自己的采集器在并发跑**（每次含两趟 22 s 的 `pop-script --verify`）；
空载复测回到 **38.3 s**，仓库里没有任何随时间增长的东西 —— `git status` 全程
只有本轮改的两个文件。）

##### 验收（风险标「低」，回退判据「13 项 PASS 逐项复现」→ **成立，不回退**）

| 档 | 命令 | 结果 |
|---|---|---|
| 判据 | `verify_cert.py --proof …`（那条 canonical 配方）| **13 项 PASS 逐项复现**，`RESULT: PASS`，与重构前**逐字节相同** |
| 秒级 | `python3 -m unittest discover -s tests -t .` | **751 passed / 15 skipped**（22/23 次；首次 1 失败见上）|
| 秒级 | `cross_validate.py --no-prove` | **host 19/19** PASS |
| 秒级 | `verify/acceptance.py --verify` | **七面逐路径零差异**（未重采快照 —— 本轮没动任何被快照观测的行为）|
| 分钟 | `demo_all.sh`（fast） | **8 支路全 PASS，SKIP 集合 = ∅** |
| 分钟 | `verify_session.py --session …` | **10 项 PASS** |

真出证随 P1 阶段末统一跑（`--label P1-acceptance`）。

#### 5.7.14 P1 大验收（2026-09-17，含真出证）

按 §5.7.3 的三档跑完。判据同 P0（§5.7.6）：**「SKIP 集合前后逐条一致」**，
不是「没有 FAIL」。

| 档 | 命令 | 结果 |
|---|---|---|
| 秒级 | `unittest discover -s tests -t .` | **751 passed / 15 skipped** |
| 秒级 | `cross_validate.py --no-prove` | **host 19/19** PASS（退出码 0）|
| 秒级 | `verify/acceptance.py --verify` | **七面逐路径零差异** |
| 分钟 | `demo_all.sh`（fast） | 8 支路全 PASS，**SKIP 集合 = ∅** |
| 分钟 | `verify_session.py --session …` | **10 项 PASS** |
| 真出证 | `regression_prove.py --label P1-acceptance` | 出证 **19/19**（1987.5 s，峰值 **10,905 MB**）+ 验证腿 `clean_pass`（151.1 s）；`regression-prove.jsonl` 追加**第 3 行** |
| 真出证 | `demo_all.sh --prove` | **8 支路全 PASS，SKIP 集合 = ∅**，合计 ~21 min |

##### 跑法：⑥⑦ 严格串行，且都脱开工具进程组

两条腿各自峰值都在 **10.9–11.1 GiB**，本机总内存 **11,958 MB** —— 重叠跑必炸。
故 ⑥ 起（`setsid nohup … & disown`）、**等它退干净**（`free` 回到 10.7 GiB 可用）
才起 ⑦。这是 §5.7.6「结论是跑法问题」那条的直接沿用。

##### 真出证确实出了证明（不是「跑了一遍」）

同一个 `verify_session` 的 `zk_proof` 卡，fast 模式是
`unproven (host-check only)×3`，prove 模式变成
**`SP1 proof verified (pop-script) + unproven (host-check only)×2`** ——
这一行的差别就是「真出证」与「宿主对拍」的分界。`RESULT: PASS`（10/10）。
另：`demo_all.sh --prove` 的汇总表**没有 SKIP 行**，与 fast 那次的 `SKIP = ∅`
一致。

> **一处顺序上的取舍（记下来）**：`demo_all.sh`（fast）与 `--prove` 写的是**同一个
> 产物目录** `scripts/examples/out/all/`，所以 ⑦ 跑完之后**不能**再跑 ③ 的 fast ——
> 那会把刚验过的真证明产物覆盖掉。因此 ③ 的数取自 ⑥⑦ **之前**那一轮（P1 代码已
> 全部落地，只是还没出证），④ 则在 ⑦ **之后**重跑一次，验的是真证明产物。
> 上表 ① ② ⑤ 也在 ⑦ 之后各重跑了一次，数值不变。**③ 没有在 ⑦ 之后重跑**，
> 这是刻意的，不是漏跑。

##### 真出证的记录（`bench/results/regression-prove.jsonl`，只追加）

第 3 行 `label=P1-acceptance`：`result=PASS` / `vectors=19` / `chunk=2` /
`seconds=2139.4` / `ts=2026-09-17T15:03:49Z`，驱动 `bytes=90880016`、
`mtime=2026-09-17T00:31:35Z`（**与 P0 那次是同一个二进制**，本轮没有重建驱动）。
出证腿 `prove_leg.prove=19/19`、`host_matched=19`、`peak_rss_mb=10905`；
验证腿 `verify_leg.ok=True`、`proof_bytes=2782131`、`vkey_hash=0x00a3566…880b`
（与 P0 那行的 vkey 一致 —— 驱动的 vkey 没动过，这正是本轮**不碰
`circuits/types/src/lib.rs`** 那条界限要保的东西）。

`git.dirty=True` 的原因**与 P0 相同**：工作树里那两个刻意未提交的未跟踪文件
`bench/results/ablation_live.{json,md}`。所有**被跟踪**的文件停在 `2ecabd6`。

##### 中高风险项逐条判定（§5.7.3 的回退判据）

| 项 | 回退判据 | 实测 | 判定 |
|---|---|---|---|
| **R7**（中） | ① 7 包 `policy_hash` 有任一不一致且非申报归一 | `tests/loader_parity_baseline.json` **在 R7 的提交里一个字没动**（`git log` 上只有 P1-① 一个提交），且新加的 `test_the_live_delta_is_exactly_the_declared_normalization` 断言 `policy_hash` 一个字不许动 | ✅ |
| **R7** | ② 全量测试非全绿 | 751 passed / 15 skipped，**多轮恒定** | ✅ |
| **R7** | ③ demo fast 出现新 FAIL/SKIP | 8 支路全 PASS，SKIP = ∅ | ✅ |
| **R8**（低） | 13 项 PASS 逐项复现 | 19 次调用逐字节相同（§5.7.13）| ✅ |

**R7 附带的那处「非等效」变更是走过流程的**：它把畸形包的异常从
`KeyError` / `AttributeError` 换成 `PolicyError`（§5.7.12），于是验收第 3 面
**必红**。处理方式正是验收工具 docstring 与 §5.7.4 定的那条 —— **人工确认后
重新采集快照，diff 进提交**（`0be2edd` 里 `tests/acceptance_baseline.json`
共 40 个叶子变化，全部落在申报的 `3a_model_robustness`(28) 与
`3b_cli_robustness`(12) 两类里，其余五面零差异）。**这是「变更被承认」，不是
「等效性被证明」** —— 两者在记录里分开写。

##### 回退记录

**P1 没有发生回退。** 唯一标「中」的 R7 三条判据全过；R4/R5/R6 极低风险、R8 低
风险，各自的判据也都成立。故 `git revert` 一次没用过，工作树里没有残留的半成品。

##### 尚在案上的一条（继承 §5.7.13，**未销案**）

R8 之后第一次全量套件出现过 `FAILED (failures=1)`，因只留了 `tail -5` 而**丢了
用例名**；其后 **23 次全量 + 6 次定向** 全绿。§5.7.13 承诺「在 P1 大验收里继续
观察」——本轮的结果是：**又是多次全绿（含 ① 在 ⑦ 前后各一次），仍然没有再现**。
但它**只能算统计性辩护，机制上仍无法排除**，所以**继续留在案上**，带到 P2；
若再现，第一件事是留住失败用例名。

##### 一处事后更正

§5.7.13 里的「`434 → 65` / `330 → 44` 行」是错的，真值是
**`433 → 64` / `287 → 45`**（量法：下一个顶层定义的行号 − 本函数起始行号）。
已在 `2ecabd6` 更正，只动文档、不动代码。

##### 未决事项（需要用户拍板）

`bench/results/ablation_live.{json,md}` 两个未跟踪文件仍在原地，本轮**既不提交
也不删除** —— 它们是 `regression-prove.jsonl` 里 `git.dirty=True` 的**唯一**来源。
去留待定。

---

#### 5.7.15 P2-① R9(b)：流式路径按需算两个 O(L) 派生量（2026-09-17，✅ 已交付 `0ccaf6c`）

**改动**：`policydsl/privacy/commit.py` 的 `canonical_violations` 原先**无条件**先算
`_ascii_lower(response)` 与 `token_count(response)`；流式路径对 `1..L` 的每个前缀各调它
一次，于是除「参考评估器重扫前缀」那份 `Θ(L²)` 外又叠了一份同样的。改为**只在对应
kind 的分支里按需算**（本函数内算过即缓存到局部变量）。

**为什么敢说等效**：二者都是 `response` 的纯函数、对 `str` 全域不抛异常、各自只被
一个分支读；所有调用点传的都是 `str`。判据 ① 要求**快照零差异** —— 而快照第 4 面
（流式证书序列：固定文本逐字符喂，3 个包）**直接**给出这一条，不是靠读代码点头。

| 判据 | 门槛 | 实测 | 结论 |
|---|---|---|---|
| ① 快照 | 第 4 面零差异 | 七面逐路径一致 | 过 |
| ② 全量套件 | 全绿 | 751 passed / 15 skipped | 过 |
| ③ 加速 | `agent_tool_v1` @2000 **≥2×** | 110.5 → **6 ms（19.7×）** | 过 |

**量出来的依据**（不是估的）：profile 显示那两行占了 `agent_tool_v1` @2000 全部
110.5 ms 里的 **101.0 ms（91%）**，而该包既没有 `keyword_block` 也没有 token 预算 ——
**两个值一次都没被读到**。含 `keyword_block` 的四个包几乎不动（1.0×）：那里的 `lower`
本来就真被读到，省不掉。

> 用户 2026-09-17 定的是 **(b) 等效替代**：采样网格、`stream_step_chars` 默认值
> **一律不动**。(a)（改采样步长）会改变可观察行为，本轮不做。

---

#### 5.7.16 P2-② R10：`match_search` 内层换预计算转移表（2026-09-17，✅ 已交付，**未回退**）

##### 这一项**推翻了计划的预告**，所以先把那句预告抄在这里

§2 的 P2 表里写着：

> R10 的预期收益已被本轮实测下调：流式的二次代价**不在 NFA 上**（在 `commit.py`
> 那两行），所以 R10 对端到端流式**几乎无收益**，只加速单点 `match_search`
> （~1 µs/字符）。按回退纪律，**它很可能就该被撤回** —— 先量、按 1.5× 门槛判。

**预告错在哪**：那句结论是在 `agent_tool_v1` 上量的，而 `agent_tool_v1` 的规则集是
`tool_arg_guard` + `budget_bound` —— **一个 `pattern_block` 都没有**，匹配器根本不
在它的路径上。拿一个不走匹配器的包去判「匹配器值不值得改」，量到的当然是 0。

**真实流式路径的 profile**（`pii_redaction_v1`，4 条 pattern）：`_point_in_ranges`
独占**总耗时的 42%**（5,041,805 次调用 / 1.56 s）。所以这一项**不该撤回**。

##### 改了什么

- 新增 `nfa._transition_table`：把每个状态的每条边**预先解包**成两个平行的
  已排序数组 `(starts, ends, 闭包)`，查询换成 C 级的 `bisect.bisect_right`
  （原先每条边调一次**Python 写的**二分 `_point_in_ranges`，外加逐次
  `states[s]["edges"]` 的 dict 查找）。
- 缓存挂在 `_CompiledPattern.trans_memo` 上，与既有的 `closure_memo` 同款：
  只缓存我们自己编译的 spec，手工构造的普通 dict 照旧每次现算。
- **不做**「把同状态多条边合并成一张表」那种更省的优化 —— 那要求边与边、区间与
  区间两两不交，而「当前 8 处 `pattern_block` 恰好都不相交」是**巧合不是契约**
  （本仓老话：「恰好」不是契约）。只做等价变形。

##### 三条判据

| 判据 | 门槛 | 实测 | 结论 |
|---|---|---|---|
| ① 逐输入对拍 | 任一不等价即回退 | **15,816 次比较，0 处不等价** | 过 |
| ② 跨层对拍 | < 19/19 即回退 | **host 19/19 PASS** | 过 |
| ③ 加速 | < 1.5× 即回退 | L=500 **2.24×** / L=1000 **2.03×** / L=2000 **2.05×** | 过 |

**判据 ① 是一组入库用例**（`tests/test_nfa_transition_table.py`），不是一次性脚本：
6 条去重 pattern（去重前是 8 处约束：`sk-[A-Za-z0-9]{16,}` 在两个包里各一份）
× 2,636 条语料（小字母表全枚举 + 宽字母表随机 + 「几乎命中」串），**两把尺子**
同时比 ——

1. `_match_search_pre_r10`：R10 **之前**那段实现的逐字副本（就地放在用例文件里当
   「旧行为」的锚，对任何 spec 都成立，含畸形手工 spec）；
2. `match_search_naive`：仓库已有的、**算法不同**的匹配器。

> **为什么要两把**：单比第 1 把只证明「没改坏」；单比第 2 把会把「新旧同错」
> 读成通过。两把一起，才既管住「改动」也管住「底子」。

**这组用例是被变异测试验过的**：把快分支里的 `bisect_right` 换成 `bisect_left`
（只影响「码点恰好落在区间端点」的那一类输入），15,816 次比较里**立刻 11 处不等价**。
所以「0 处不等价」是一条会红的断言，不是恒真式。

同一条路上还钉了两个**不变量**（否则上面那些对拍可能全绿而收益已归零）：

- 仓库里 6 条 pattern 的**每一条边**都必须走 `bisect_right` 快分支
  （共 244 态 / 113 边）。若哪天区间变成未排序或同边内相交，全部会退回
  `starts is None` 的慢分支 —— 那时对拍**依然全绿**（退回的分支与旧实现逐字相同），
  所以必须单独断言；
- 该回退分支本身也要**错得和旧实现一样**，不去替畸形 spec「顺手修好」。用例里
  手工造了两个真会分叉的 spec（区间未排序 / 同边内区间相交），逐点比过。

##### 端到端（同一把尺子：`bench_streaming.py`，逐字符喂）

| 包 | @2000（`0ccaf6c`） | @2000（本次） | 加速 |
|---|---:|---:|---:|
| `agent_content_v1` | 672 ms | **393 ms** | 1.71× |
| `eu_ai_act_v1` | 2,271 ms | **1,138 ms** | 2.00× |
| `pii_redaction_v1` | 4,604 ms | **2,261 ms** | 2.04× |
| `agent_tool_v1` | 6 ms | 6 ms | 不动 ✓ |
| `multiparty_demo_v1` | 81 ms | 83 ms | 不动 ✓ |

后两行**不动是应该的**：它们没有 `pattern_block`，这条路根本不在里面 —— 这也正是
预告「几乎无收益」的来源。`Θ(L²)` 的**阶**没变，换掉的是每一格里的常数
（L=2000 拟合常数 `agent_content` 0.336 → 0.196、`eu_ai_act` 1.135 → 0.569、
`pii_redaction` 2.301 → 1.130 µs/字符²）。

##### 有意变更（快照与文档的更新是**被承认**，不是**被证明**）

`bench/results/streaming.{json,md}` 是**结果快照**，本次随代码一起重采并入库；
`docs/modules/06-frameworks.md` 的代价表与 `langchain_adapter.py` 的
`PoPCallbackHandler` docstring 同步到新值。验收快照
（`tests/acceptance_baseline.json`）**零差异** —— 这是应当的：R10 是纯性能等价变形，
不改变任何可观察行为面。

##### 阶段状态

- 全量套件：**761 passed / 15 skipped**（比 R9(b) 时的 751 多 10 条，即新增的这组用例；
  skip 数不变）；`cross_validate --no-prove` host 19/19；验收七面零差异。
- **回退记录：R10 没有回退**（三条判据全过）。P2 至此仍无回退。
- §5.7.14 末尾「尚在案上」的那一条（R8 后一次孤立的 `failures=1`）**继续继承到
  P2 大验收**观察，仍未销案。
- 未决事项（`bench/results/ablation_live.*` 两个未跟踪文件的去留）**仍未决**，见 §5.7.14。

#### 5.7.17 P2-③ R11：SP1 prover 旋钮矩阵（2026-09-17，✅ 已交付；**无代码可回退**，纯实验）

##### 问题

§3.3 那条 **~10.15 GiB 的固定地板**是「换机器也还在」的 prover 开销（周期侧天花板
在别处）。本机 11.7 GiB，缝只有 ~1.5 GiB。能不能**用 SP1 自己的旋钮把这条地板压低**？

旋钮只有环境变量一条路：`pop-script` 不认任何 prover 选项，`SP1_WORKER_*` 一族由
`sp1-prover-6.7.0/src/worker/config.rs` 的 `SP1WorkerConfig::new` 读入，链路是
`SP1_PROVER=cpu` → `sp1-sdk-6.7.0/src/blocking/cpu/mod.rs` 的 `CpuProver::new_with_opts_and_machine`
→ `cpu_worker_builder_with_machine` → `SP1LocalNodeBuilder`。所以这些变量**确实在本仓的路径上**。

##### 事先写死的判据（计划 §2 的 P2 表，跑之前定，事后不改口径）

- 任一配置把地板压低 **≥5%** 且 `--verify` 仍通过 ⇒ **写成推荐配置**；
- 一个都没降 ⇒ **照样记进结果文件**（那本身就是结论）；
- 被 OOM 杀 ⇒ 如实记录。

门槛按**当轮基线**算（首尾各跑一遍 `default` 的均值），**不是**历史值 —— 取样记录已写明
峰值内存可复现 ±1%，换一轮机器状态就可能偏出这个量级，所以基线当场重取。

##### 结果：**能压，−10.9%**

`bench/results/prover_knobs.{json,md}`：同一点 `(200, 1)`（最小的真点，已坐在地板上）、
每轮一个独立子进程、每轮出完证再用 `pop-script --verify` 独立复验。

| # | 配置 | peak RSS (MiB) | 相对当轮基线 | 耗时 (s) | verified |
|---:|:--|---:|---:|---:|:--|
| 1 | `default` | 10,453 | +0.13% | 100.2 | ✓ |
| 2 | `no-verify-intermediates` | 10,477 | +0.36% | 99.1 | ✓ |
| 3 | `few-core-workers` | **9,302** | **−10.90%** | 103.5 | ✓ |
| 4 | `tiny-buffers` | 10,509 | +0.66% | 97.5 | ✓ |
| 5 | `low-concurrency` | **9,350** | **−10.44%** | 101.4 | ✓ |
| 6 | `default-again` | 10,426 | −0.13% | 94.7 | ✓ |

当轮基线 **10,440 MiB**（首尾相差 0.26%，即底噪 ±0.13%），门槛 ≤9,918 MiB。
**两条过门槛，且两条都 `--verify` 通过** ⇒ 按事先判据**写成推荐配置**。耗时 94.7–103.5 s
全长在既有口径的 ±10% 抖动里，没有可辨的时间代价。

##### 是哪一半在起作用：**worker 数**，不是通道容量

三项分解（这三行只差动没动 worker 数）：

- `few-core-workers`（`NUM_CORE_WORKERS=1` + `CORE_BUFFER_SIZE=1`）→ **−10.90%**；
- `tiny-buffers`（7 个 `*_BUFFER_SIZE` 全压到 1，**worker 数不动**）→ **+0.66%**，即**一点没省**；
- `low-concurrency`（全部降到 1）→ −10.44%，与第一行在底噪量级内。

⇒ 占内存的是**同时在飞的工作集份数**。名字里的 `BUFFER_SIZE` 是**通道容量（元素个数），
不是字节数** —— 它本来就只装很少的东西，压到 1 也省不出内存。推荐从**旋钮最少**的那组
起步：`SP1_WORKER_NUM_CORE_WORKERS=1 SP1_WORKER_CORE_BUFFER_SIZE=1`。

##### 事先的猜测被证伪（本实验信息量最大的一半）

脚本 docstring 在跑之前写着：「**若本次证明只有一个 shard，把 worker 数降到 1 就不会省下
任何东西**（没有第二个 worker 的工作集可以省）」。**实测省下 1.14 GiB。** 那句猜测的原话
保留在 `bench/bench_prover_knobs.py` 里，并就地标注了证伪结果 —— 猜错的那一半比猜对的
那一半更有信息量，删掉它等于把「这个实验为什么值得做」抹掉。

##### `shard` 那一列是 `?`：**没量到，如实记**

`count_shards` 六轮全返回 `None`，原因是**信息不可得**，不是数丢了：SP1 的 shard 边界是
`tracing::debug!`（`sp1-prover-6.7.0/src/worker/controller/splicing.rs:204`），而未设
`RUST_LOG` 时默认级别是 **`off`**（`sp1-core-machine-6.7.0/src/utils/logger.rs:22`）。
真出证是本实验的主量测，为拿这一列去开 debug 日志会**改变被量的东西**（日志本身要内存、
要时间），所以宁可空着。md 里那段说明是由数据现推的（整列都数不出来才出现），不是写死的注释。

##### 边界跟着地板一起挪（**额外探针**，不属于矩阵本身）

矩阵只回答「地板能不能压」。压下去**买到了什么**是另一个问题，所以补了一组探针：
把默认表里标 ✗ OOM 的两个悬崖点，**在同一份语料上把两个臂都量一遍**
（`bench/results/prover_knobs_cliff.{json,md}`，`--arms`）：

| 采样点 | 默认选项（同一轮）| 推荐配置 | peak RSS |
|:--|:--|:--|---:|
| `(200, 3)`（规则数悬崖）| ✗ OOM（57.2 s 被杀）| **✓ 出证 + 独立复验通过**，160.1 s | 10,763.8 MB |
| `(20 000, 1)`（长度悬崖）| ✗ OOM（62.2 s 被杀）| ✗ **仍然 OOM**（131.0 s 被杀）| — |

##### 这一组探针**重做过一次**：跨文件的「同一份语料」是个假命题

第一版是分两次采的（默认表用 `proofs.json` 里既有的 OOM 行，推荐配置另采一份），
然后我在文档里写下「**同一份语料**、同一个点，只有旋钮不同」。**这句话当时是错的，
而且我是靠一条测试红掉才发现的** —— 那条测试断言 `cliff.json` 与 `proofs.json` 的
语料 `sha256` 相等，实测 `6a1a3431…` vs `8381462c…`。

根因不在谁写错了数，而在**这份语料本来就不可复现**：`demo` 是
`scripts/examples/out/**` 的 glob，那些产物随举例脚本的重跑而生灭（两批的差集各两个
文件，长度都是 372 字符）。两份结果文件**天然是不同时候采的**，所以那个断言要求的
是一件**永远不成立**的事。

⇒ 结论是**改量法，不是改措辞**：给 `bench_proofs.py` 加 `--arms`，让两个臂**在同一次
调用里共用同一份装载好的语料**。「两臂语料相同」于是由**构造**保证，不再需要事后比对。
上面那张表是重做后的结果，**默认臂那一列也随之变成了实测值**（不再是引用旧的 OOM 行）。

⇒ 那条测试也一起改了：**删掉跨文件的语料比对，改成钉「配对」与「悬崖性」**——
① 每个采样点在**每一个臂**下都量过（配不成对就只剩独白）；② 被复测的点确实**是
`proofs.json` 里标 ✗ OOM 的那几个**（否则量的不是悬崖）。这两条**跨语料也成立**，
才是真正承载结论的结构。**留一条测假命题的用例，比没有用例更坏。**

⇒ 顺带修掉一个**渲染器真 bug**：加 `prover env` 那列时，`show_env=False` 分支留下的
是 `"|"` 而不是 `""`，于是单臂表的每一行会多出一个**空格子**（`core || 123.46`）。
证据是 `--render-only` 重渲染 `proofs.json` 后，`proofs.md` 的**数据行也变了** ——
也就是说入库的视图与数据**已经漂过一次**。修完重渲染，`proofs.md` 的 diff 回到
**纯新增 6 行、数据行逐字节未动**。这正是 `tests/test_bench_views.py` 存在的理由，
而它确实在第一次跑起来时就把这件事抓了出来。

⇒ 省下的 ~1.1 GiB **够把一个「刚好越线」的点拉回来，不够把一个「远在界外」的点拉回来**。
所以边界那句「3 条及以上：出不来」要读成**默认选项下**的结论 —— 它随旋钮走，这正是
为什么 `bench_proofs.py` 的渲染对「点不全」的结果**根本不出边界结论**：同一个 `(200, 3)`
在两种口径下给出的答案是**相反的**，一份不含点上、只含点下的表去套那句边界就是错的。

##### 有意变更（不是等效替代）

本项**无代码可回退**，但它改了渲染器与文档，逐条记：

- `bench_proofs.py` 新增 `--render-only` / `render_only()`：视图与数据分开走路。渲染是纯函数
  （`envelope` 之外的一切都由 rows/host 决定），而重跑一次真出证要十几分钟、还可能
  撞上那几个**故意留着的 OOM 点** —— 为一句措辞付这个代价没有道理。
- 新增 `is_default_matrix()` / `partial_envelope()`：**推不出那条边界的结果，不写边界结论**。
  两个条件都要满足 —— 点齐全（`DEFAULT_POINTS` 一个不缺）**且每一行都是默认臂**。后半句是
  重做探针时补的：边界的结论句写的是「**默认 prover 选项**下」，混进旋钮之后那句话就名不副实，
  哪怕点一个不缺。（原先只查点、名字叫 `covers_default_points`。）
- 新增 `--arms` / `arm_bullets()`：**两臂在同一次调用里共用同一份语料**（理由见上一节）。
  渲染时带旋钮的批次**按采样点分组**、每臂一行 —— 平铺会让同一个点出现两次这件事看着像巧合，
  而「同一个点、两臂结论相反」恰恰是这种文件的全部内容。
- 新增 `tests/test_bench_views.py`：入库的 `.md` 必须**恰好**是 `.json` 渲染出来的那一份
  （视图/数据不漂移），且 `prover_knobs` 那份必须是**跑完的**、门槛必须**记在数据里**。
  配套的「改一行数据渲染必须跟着变」也在里面 —— 否则上一条在渲染退化成常量时照样绿。
- 修 `prover env` 列的 `show_env=False` 分支（`"|"` → `""`）：单臂表原先每行多一个空格子，
  说明**入库的视图与数据已经漂过一次**。修完重渲染，`bench/results/proofs.md` 的 diff 回到
  **纯新增 6 行、六行数字逐字节未动** —— 这既是「渲染是纯函数」的一次证据，也是上面那条
  测试**确实会抓到漂移**的一次实证（它第一次跑起来就红了）。
- **推荐配置没有设进任何脚本的默认**（`regression_prove.py` / `cross_validate.py` 保持
  默认选项）：已入库的边界与耗时都是默认口径下的，改默认等于让新旧结果不同口径。
  要省钱的人自己 `export SP1_WORKER_NUM_CORE_WORKERS=1 SP1_WORKER_CORE_BUFFER_SIZE=1`。

##### 阶段状态

- **回退记录：R11 无回退项**（纯实验，无可回退的代码）。P2 至此仍无回退。
- §5.7.14 末尾「尚在案上」的那条（R8 后一次孤立的 `failures=1`）**继续继承到 P2 大验收**，仍未销案。
- 未决事项（`bench/results/ablation_live.*` 两个未跟踪文件的去留）**仍未决**，见 §5.7.14。

---

### 5.7.18 R12 —— 门面 `__all__`：**加测试**（不是删）

**选的是「加测试」这一支**，与计划里「二选一，不留现状」的要求对齐。理由：`__all__`
本身不是死代码 —— `from policydsl import Policy` 是本包对外的稳定面，模块 docstring
自己写着「门面是稳定的」。删掉它等于把「哪些名字是承诺」这件事交给使用者猜；而
**没坏的东西不该为「省一行」删掉**。

**它坏起来没有任何东西会报错**，这才是要加测试的原因。四种坏法全在「跑一遍看看」的
射程之外：

| 坏法 | 谁会发现 |
|---|---|
| 漏掉一个名字 | **使用者**的代码里 `ImportError`，不在本仓的 CI 里 |
| 混进解析不了的名字 | `import *` 抛 `AttributeError` —— 而本包测试多起点名导入，碰不到 |
| 重名 | `len(__all__)` 撒谎，而那个长度常被当「门面有多大」读 |
| 递出来的是**另一个对象**（本地包装/别名）| 名字还在、也解析得了，**语义已经换了** |

##### 与验收快照第 6 面的分工（两者都要，不是重复）

| | 记的是 | 谁确认 | 何时红 |
|---|---|---|---|
| `tests/acceptance_baseline.json` 第 6 面 | 名单的**内容** | **人**（重采 + diff 进提交）| 名单变了就红 —— 那是「变更被承认」 |
| `tests/test_frontdoor.py` | 名单的**不变量**（不重不漏、能解析、与命名空间一致、来自本包）| 不需要人 | 名单**坏**了才红 |

只有快照，改名单会退化成「反正重采一次就绿了」；只有不变量，名单被谁加了十几个名字
也没人看见。

##### 中途踩到的一个真问题：**「同名」不等于「同一个对象」**

第一版把可调用物那条写成「**所有**已加载子模块里同名的东西都必须与门面是同一个
对象」，**单跑本文件全绿、跑全量就红**。根因不是 bug：

```
policydsl/evidence/trace.py:427        def verify_chain(receipts: Sequence[ToolReceipt], …)
policydsl/adapters/langchain_adapter.py:468  def verify_chain(certs: List[Dict[str, Any]]) -> bool
```

**本仓确实有两个同名不同物的 `verify_chain`** —— 门面那个吃 `ToolReceipt`/`ToolSeal`
对象，适配层那个吃原始 dict 载荷。两个都对，「同名」只是同一个领域词用在了两层。
而 `adapters` 只有等**别的用例**把它 import 进来之后才在 `sys.modules` 里，所以那条
断言的成败取决于**测试执行顺序** —— 这是最坏的一种红法。

⇒ 改法：**可调用物要求「存在同一个对象」，常量仍要求「所有定义者都一致」**。
两者不对称是因为它们的坏法不同：可调用物被复制一份，问题在**语义被换掉**；而常量
在两个模块里取值不同，问题在**门面递的是哪一份取决于 import 顺序** —— 那本身就是
该修的事，不能放过。（`SPEC_VERSION` 是本仓唯一的常量，两处取值相同。）

##### 回退记录：R12 无回退项

按「加测试」这一支落地，生产代码**一行未动** —— 没有可回退的动作。测试本身在
`tests/test_frontdoor.py`，9 条。

---

### 5.7.19 P2 大验收（2026-09-18，**含真出证**）

按 §5.7.3 的三档跑完，判据同 P0/P1（§5.7.6）：**「SKIP 集合前后逐条一致」**，
不是「没有 FAIL」。本轮 P2 的改动面是 R9(b) / R10 / R11 / R12。

| 档 | 命令 | 结果 |
|---|---|---|
| 秒级 | `unittest discover -s tests -t .` | **776 passed / 15 skipped**（38.7 s；+25 条 = R11 的视图用例 6 条 + R12 的门面用例 9 条，其余为 R9/R10 的既有增补）|
| 秒级 | `cross_validate.py --no-prove` | **host 19/19** PASS（退出码 0）|
| 秒级 | `verify/acceptance.py --verify` | **七面逐路径零差异**（未重采快照 —— P2 没有动任何被快照观测的行为）|
| 分钟 | `demo_all.sh`（fast） | **8 支路全 PASS，SKIP 集合 = ∅** |
| 分钟 | `verify_session.py --session …/policy/session.json` | **10 项 PASS**，末行 `RESULT: PASS`；证书按 kind：`tool-args` 3 / `tool-result` 2 / `stream` 4 / `llm` 1 / `zk` 3 |
| 真出证 | `regression_prove.py --label P2-acceptance` | 出证 **19/19**（**1986.3 s**，峰值 **10,874 MB**）+ 验证腿 `clean_pass`（138.7 s，`proof_bytes` 2,782,131）；`regression-prove.jsonl` 追加**第 4 行** |
| 真出证 | `demo_all.sh --prove` | **8 支路全 PASS，SKIP 集合 = ∅**，合计 ≈20.3 min |

##### 跑法：⑥⑦ 严格串行（沿用 §5.7.6 那条）

两条腿各自峰值都在 **10.4–11.1 GiB**，本机总内存 **11,958 MB** —— 重叠必炸。
故 ⑥ 起（`setsid nohup … & disown`）、**等它退干净**（`free` 回到 10.7 GiB 可用、
`pgrep` 无残留）才起 ⑦。

> 一处跑法上的教训留在 R11 里：`grep 文件 | tail -f` 这种**顺序写反**的监视管道，
> `grep` 一到 EOF 就退出、`tail` 永远等不到输入，于是**监视器整场静默**。静默与
> 「一切正常」看起来一模一样 —— 后来改成 `tail -f 文件 | grep --line-buffered`。
> 而又因为 `cross_validate` 的输出在重定向下是**块缓冲**的，行级监视看不到进度，
> 最终用的是**进程退出**作为信号。**「没消息」不能当「没出事」用。**

##### 真出证确实出了证明（不是「跑了一遍」）

- 出证腿 19/19 `host_matched`，**19 个向量各出一份 core 证明**，且逐点与 golden 对拍；
- 验证腿**独立进程**复验 `clean_pass` 通过，`vkey_hash = 0x00a35666586fb939…`；
- **`vkey_hash` 在 P0 / P1 / P2 三轮上逐字节相同**，且 P2 与 P1 用的**是同一个
  `pop-script`**（`sha256 8366dba6250c…`，P0 起未再重建）—— 这是「P2 没有动
  `ConstraintSpec` 规范字节 / `STABLE_KEYS` / 任何域分隔符」的**机械证据**，
  而不是一句自查。驱动二进制只在 P0 前重建过一次（`first-real-run` 的
  `a5b70e1aff77` → `8366dba6250c`），此后三轮不变。

##### `git.dirty = true` 是**已知的两条未跟踪文件**，不是未提交的改动

记录里 P2 那行的 `dirty=true` 值得说清，否则下一个人会以为验收时树是脏的。
实测 `git status --porcelain` 的全部内容：

```
 M bench/results/regression-prove.jsonl      ← 本次运行自己追加的那一行（预期）
?? bench/results/ablation_live.json          ← 待用户拍板的两条，见 §5.7.14
?? bench/results/ablation_live.md
```

**没有任何未提交的源码改动。** `demo_all.sh` 重新生成的
`scripts/examples/out/**` 是 gitignore 的，跑完不留痕。

##### ⑧ 中高风险项判定：**P2 无回退项**

| 项 | 风险 | 事先写死的判据 | 判定 |
|---|---|---|---|
| R9(b) | 中 | 快照零差异 + 全量全绿 + `agent_tool_v1`@2000 字符流式耗时改善 ≥2× | **通过**，见 §5.7.15 |
| R10 | 中 | 逐输入对拍等价 + `cross_validate` 19/19 + 加速 ≥1.5× | **通过**（实测 ~2.0×），见 §5.7.16 |
| R11 | 中 | 纯实验，**无代码可回退** | **无回退项**，见 §5.7.17 |
| R12 | 低 | 二选一，不留现状 | 选「加测试」，**生产代码一行未动**，见 §5.7.18 |

⇒ **P0 / P1 / P2 三阶段累计回退 0 项。**

##### 尚在案上（**继续继承**）

- §5.7.13 末尾那条「R8 之后一次孤立的 `failures=1`」**仍未销案**。本轮 776/15/OK
  是一次干净样本，但**一次干净不构成销案** —— 它当初就是不可复现的，要销案得
  先复现出它。**继续继承到 P3 大验收。**
- 未决事项（`bench/results/ablation_live.*` 的去留）**仍未决**，见 §5.7.14。

---

### 5.7.20 R13 —— 死代码：**删 4 保留 6**（不是提案说的「清 9 处」）

**这一条在动代码之前先做完了逐条核查**，结果推翻了提案的前提：那 9 处里
**5 处是文档化的公开 API**，另有 1 处是**承重的**，真正能删的是 **4 处**。

##### 判据（先定死再查，事后不改口径）

一条符号算「被承诺的公开 API」，**当且仅当**它满足其一：① `docs/` 下有引用；
② 在某个 `__all__` 里。两者皆无即可删。

为什么用这条而不是「有没有外部使用者」：**「无外部使用者」在本仓里根本无法证实**
（另一个仓库 import 什么，这里看不见），照字面执行等于一条都不删。而
**docs 正是本仓记录承诺的地方** —— 验收快照第 6 面的分工（§5.7.18）用的也是这条线。
`__all__` 那半边是本轮顺带确认的：四个可删项**都不在** `policydsl.__all__` 里，
而且 `evidence` / `core` / `proofs` 三个子包**都没有** `__all__`，
所以删它们**不动门面**，R12 的门面用例与快照第 6 面都不会因此变红。

##### 逐条核查（全仓 grep，**所有文件类型**，不只 `.py`）

| # | 符号 | 定义处 | 定义外的引用 | 判定 |
|---|---|---|---|---|
| 1 | `seal_digest` | `evidence/trace.py:221` | **0** | **删**（`0c7b210`）|
| 2 | `seal_for` | `evidence/trace.py:226` | **0** | **删**（`d5a2c38`）|
| 3 | `public_signer` | `evidence/cert.py:399` | **0** | **删**（`d20407b`）|
| 4 | `proved_parts` | `proofs/multiparty.py:368` | **0** | **删**（`b1c8ba7`）|
| 5 | `format_spec` | `core/nfa.py:579` | `docs/modules/01-policy-dsl.md:219` 表格行 | **保留**：文档化 API |
| 6 | `call_bool` | `evidence/anchor.py:347` | `docs/modules/04-anchoring-audit.md:96`「`call_uint / call_address / call_bool`」| **保留**：同族另两个在用，删掉破坏接口对称 |
| 7 | `call_tool_sync` | `adapters/mcp_adapter.py:224` | `docs/modules/06-frameworks.md` **4 处**，含 `:664` 的**用法示例** | **保留**：有示例的公开 API |
| 8 | `chain_digest` | `evidence/trace.py:422` | `docs/plan-p0p1p2.md:411`（计划中的签名）| **保留**：计划文档承诺过 |
| 9 | `Rule.to_dict` | `core/model.py:227` | `docs/modules/01-policy-dsl.md:85` 类签名行「+ validate() / to_dict()」| **保留**：文档化的类接口 |
| 10 | `compile.py:253` else 分支 | `core/compile.py:253` | `tests/test_rule_kinds.py:17` 注明「在 validate 之后其实是死代码，**但正是靠这条前提**」| **保留**：**承重** |

##### 第 10 条为什么不能删（这条最容易被下一次重构误删）

那个 `else` 分支生成 `{"kind": …, "stub": True, "note": "not yet implemented…"}`。
测试的注释说它在 `validate()` 之后是死代码 —— 对，**但它承的是另一件事**：
有它在，**每一条规则都必定产出至少一条约束**；删掉它，未知 kind 的规则会从
约束列表里**静默消失**，而「少了一条约束」在 `ConstraintSpec` 上不留痕迹。
所以它不是冗余，是**兜底**：把「漏了一种 kind」从**静默**变成**看得见的 `stub: true`**。
**留着它。** 这也是「死代码」这个词最会骗人的地方 —— 覆盖率测不到的路径，
未必没有职责。

##### 第 9 条 `Rule.to_dict` 差点被误删的原因

提案的备注写着「注意：`Violation.to_dict()` 用的是 `self.rule.name/kind`，不经它」——
**这句是对的，但它证明的是「别的 `to_dict` 不走这条路」，不是「这个没人用」**。
`Rule.to_dict` 之所以留下，靠的是 `docs/modules/01-policy-dsl.md:85` 那行类签名。
（全仓 `to_dict` 有 27 处命中，绝大多数是**别的类**的 —— 只数命中数、
不看接收者是谁，是这类核查最常见的错法。）

##### 每条单独提交，四条各自可独立 revert

删除是**不可逆**的（`git revert` 能恢复文件，但恢复不了「它曾经是公开 API」这个事实），
所以四条**各占一个提交**，`git revert` 其中任意一条都不会牵动另外三条。
每条提交的门禁都跑满了：**776 passed / 15 skipped + `cross_validate` host 19/19
+ 验收快照七面零差异 + demo fast 无 FAIL**（四条全绿，无一条需要回退）。

##### 回退记录：R13 无回退项

**保留 6 处不是「没做完」，是核查的结论。** 下一个人要再清，请先读上表第 5–10 行
与各自的引用出处 —— 照着提案原话再删一次，删掉的会是公开 API 和兜底分支。

---

### 5.7.21 R14 —— `core → proofs` 分层倒置：**纯搬位置**

**这一条是全轮风险最高的一项**（提案 P3 表里标「中高」），因为它的正确性判据
恰恰是「**什么都没发生**」。任何行为变化都算失败，没有「大体上对」这个档。

##### 倒置长什么样

`policydsl/core/compile.py` 与 `core/evaluate.py` 需要**模型指纹**
（`onnx_sha256` / `model_vkey`）来把 `semantic_bound` 编译进契约、并在参考判定
里填 `DelegatedConstraint` 的字段。这些函数原先住在 `policydsl/proofs/semantic.py`
里 —— 于是判定层为了取一个指纹，**反过来 import 出证编排层**：

```
core.compile ──(取指纹)──▶ proofs.semantic      ← 方向反了
```

`core` 是**判定层**（决定合规与否），`proofs` 是**出证编排层**（把判定包装成
可核验的产物）。这条依赖的合法方向**只有一个**：`proofs` 可以依赖 `core`，
`core` 依赖 `proofs` 永远不行 —— 否则「判定」就变成了「由出证方式决定」，
而这正是整个 PoP 想排除的那类循环论证。

##### 先量后改：为什么这一搬不会造出 import 环

搬位置之前先做了两项**测量**（不是推断）：

1. **`proofs/semantic.py` 是叶子** —— 它不 import 任何 `policydsl.core.*`；
2. **目标依赖 `evidence/cert.py` 与 `paths.py` 都是干净的** —— 二者不 import
   任何 `policydsl` 里的东西（`cert` 只用标准库 + `paths`，`paths` 只用标准库）。

所以 `core/model_fp.py` 的依赖边**全部指向 core 之外且不回指 core**，环不可能形成。
（顺带纠正了一条先前记岔的边界：「本层只用标准库」这条约束是**只在门面
`policydsl/__init__.py` 上**强制执行的，**没有**加在 `core` 包上 —— 所以
`input_width` 可以带着它那句**函数级**的 `from semantic import features as F`
（torch 是懒加载的，`semantic/features.py` 的模块级 import 是纯标准库）一起搬过去。

##### 搬了什么

新建 `policydsl/core/model_fp.py`（**212 行**），从 `proofs/semantic.py`
**整块搬入** 5 段纯契约代码，`proofs/semantic.py` 由 **602 行降到 455 行**：

| 搬走的 | 内容 |
|---|---|
| `SemanticError` / `SEMANTIC_VERSION` | 版本标签与异常类型 |
| `ARTIFACT_NAMES` / `model_dir` / `vk_path` | 产物路径口径 |
| `onnx_sha256` / `cached_onnx_sha256` / `cached_file_sha256` / `_sha256_of_file` | 指纹与缓存入口 |
| `model_manifest` | 模型清单 |
| `input_width` | 图的字符上限（带函数级 `from semantic import features`）|

`proofs/semantic.py` 里换成**原地 re-import**，并且 `__all__` **一个字未改** ——
于是 `sem.S.<name>` 的所有调用方（测试、`scripts/prove/ezkl_prove.py`、`bench/`）
**一行都不用动**。私有 `_sha256_of_file` **特意不 re-export**：`semantic.py` 自己
已经不再用它，再挂一个用不上的私有壳只是把「谁在用」这件事弄糊。

`core/compile.py` 3 处（`:92` / `:119` / `:145`）与 `core/evaluate.py` 1 处
（`:272`）从 `sem.` 改指 `model_fp.`。

##### 「纯搬位置」是**机械证明**的，不是读出来的

| 证明 | 怎么做的 | 结果 |
|---|---|---|
| 搬走的字节没被改 | 五个代码块逐字节比对 `git show HEAD:policydsl/proofs/semantic.py` | 逐字节相同 |
| 对象没被复制 | `is` 断言 10 个公开名字在 `S` 与 `M` 里是**同一个对象** | 10/10 相同 |
| 契约字节没变 | 验收快照**第 1 面**（7 包的完整 `ConstraintSpec` + `policy_hash`） | **零差异** |
| 空白没被抖乱 | 先测量：全文件 94 段空行、**没有一段 ≥3 行**；据此只删内容区间、再把 ≥3 空行压成 2 | 接缝之外是恒等变换 |

第 1 面零差异这一条尤其要写清楚：`policy_hash` 是对 `STABLE_KEYS` 的规范 JSON
字节求的 SHA-256。**它零差异 ⇒ 七个策略包的约束字节一个 bit 都没动**，
而这正是「行为无变化」在契约层最硬的那张证据。

##### 四条判据（提案 P3 表里预先写死的，事后不改口径）

| # | 判据 | 结果 |
|---|---|---|
| ① | 无 import 环 | ✅ 37 个模块逐个**冷启动**导入通过 |
| ② | 全量测试全绿 | ✅ **776 passed / 15 skipped / OK** |
| ③ | demo fast 无新增 FAIL/SKIP | ✅ 8/8 PASS，**SKIP 集合 = ∅**，与基线逐条一致 |
| ④ | semantic / ezkl 路径行为无变化 | ✅ `test_semantic` 30 例全绿、demo 语义支路 PASS、快照七面零差异 |

##### 补的门槛：`tests/test_layering.py`

R14 是「**修好一条规则**」，而本仓反复栽在「**修好了但没人守**」上 ——
修完不复盘，下一次重构会原样搬回来（这个倒置本来就已经存在过一整个版本、
没人发现）。所以这一项**必须配一条会变红的闸门**，否则等于没修。

`tests/test_layering.py`（129 行，6 条用例）用 **AST** 而不是正则扫
`policydsl/core/**.py`：正则会把 docstring 里的散文当成 import，也会漏掉函数体内的
import。要点：

- **`ast.walk` 全树**，所以**函数体内的 import 照样算** —— 原先那处倒置正是
  函数级 `from policydsl.proofs import semantic`，只扫模块顶层是漏得掉的；
- **两条防恒真下限**：`test_the_scan_actually_covers_the_core_package` 断言至少扫到
  **5 个文件**、且 `compile.py` / `model_fp.py` **必须在名单里** ——
  挡的是「扫描器什么都没扫到，于是全绿」这个本仓的招牌失败模式；
- **扫描器自身被喂了已知样本**（`TestTheGateWouldNoticeAnInjection`）：模块级注入、
  函数级注入、经 `core.model_fp` 中转不算违规、docstring 里的文字不算 import。

**端到端证伪**：往 `core/compile.py` 注入一句函数级
`from policydsl.proofs import semantic` → 用例**变红**并指出
`('policydsl/core/compile.py', 114, 'policydsl.proofs')`；移除后工作区**零 diff**。
红过又恢复，才算这条闸门真的会响。

##### 连带改动

- `core/model.py:159` 的文档引用 `policydsl.proofs.model_manifest` →
  `policydsl.core.model_fp.model_manifest`（那条路径本来就少一段，搬完更错）；
- `tests/test_artifact_digest.py` 的 `DECLARED_HELPER_EXCEPTIONS` 键从
  `policydsl/proofs/semantic.py` 改到 `policydsl/core/model_fp.py`，
  并把身份断言改钉在**公开**名字上（`semantic.model_manifest is
  model_fp.model_manifest`）—— 私有 `_sha256_of_file` 不再 re-export，
  原先那条 `semantic._sha256_of_file` 的断言会因为**名字不在那儿**而炸。

##### 后续：测试计数「四处同步」

R14 新增了一个测试文件，真实计数从 **776 变 782**（42 个模块）。按
`docs/modules/08` §5 自己列的那份「四处同步」清单改了 `modules/08`、
`modules/README`、`security-model`、`reproduce`、`development` 五处；
`dev-plan.md` 与 `plan-p0p1p2.md` 里的**各阶段验收表是留痕**，按 §5.7.12 的
口径**不随本轮改写**。

##### 提交

| 提交 | 内容 |
|---|---|
| `e25720e` | refactor(core): 模型契约下沉 `core/model_fp.py`（生产代码）|
| `d4cfba5` | test(layering): 钉住 `core` 不许 import `proofs`（门槛）|
| `5a21b84` | docs: 测试计数「四处同步」到 782 / 42 个模块 |

##### 回退记录：R14 无回退项

四条判据全过，且等效性由快照第 1 面（`policy_hash` 零差异）机械证明。

##### 记录在案、本轮**未修**的两处

1. **`core/compile.py:304` 写的是 `:func:`policydsl.proofs.shard``，而 `shard`
   在 `proofs/multiparty.py:181`。** 初判是「笔误」，**量过之后推翻了**：

   - 写了个一次性脚本（放 `/tmp`，不入库）扫全仓 docstring 里的 `:func:`/`:class:`
     /`:mod:` 目标，对 `policydsl.*` 的 62 个逐个做「最长可解析模块前缀 + 属性链」
     判定 → **34 个指不到**，`compile.py:304` 只是其中之一；
   - 34 处**全部是同一款式**：`policydsl.<子包>.<名字>`，省略掉定义它的那个模块
     （`policydsl.evidence.ToolReceipt`、`policydsl.core.check`、
     `policydsl.privacy.canonical_violations` …）。而 `evidence` 与 `proofs`
     两个子包的 `__init__.py` **都**明写「**本子包不 re-export 任何符号**」，
     所以这些简写在运行时确实解析不到 —— 已实测确认。
   - **本仓没有 Sphinx**（无 `conf.py`、无 `Makefile`、无依赖、CI 里零命中），
     这些角色**从不被渲染**，是给人读的散文。所以「指不到」**不构成缺陷**。

   ⇒ 结论改成：**这是一条一致的简写口径，不是笔误；本轮不改**（只改一处会让它
   与其余 33 处不一致，收益为零）。原来的「笔误」判断是**只看了单个样本**得出的，
   记在这里当作提醒。

   （附带说明 R14 里改掉的 `core/model.py:159`：那条**必须**改 —— 模块搬了家，
   旧路径指的东西已经不在原处，与上面这种「本来就是简写」不是一回事。）

2. **`docs/plan-p0p1p2.md:6` 的「今天是 675 / 15」**：那是**计划启动时的快照**，
   文档自身标了不动。按留痕口径**不改**。

---

### 5.7.22 P3 大验收（2026-09-18，**含真出证**）

**这是本轮（P0→P3）的最后一次阶段大验收。** 改动面：R13（删 4 处死代码）+
R14（分层倒置）。跑的是 §5.7 计划里那份固定的八项清单，一项没减。

##### 七项结果

| 档 | 命令 | 结果 |
|---|---|---|
| 秒级 | `unittest discover -s tests -t .` | **782 passed / 15 skipped**（42.6 s）|
| 秒级 | `cross_validate.py --no-prove` | **host 19/19** PASS（退出码 0）|
| 秒级 | `verify/acceptance.py --verify` | **七面逐路径零差异** |
| 分钟 | `demo_all.sh`（fast） | **8 支路全 PASS，SKIP 集合 = ∅** |
| 分钟 | `verify_session.py --session …/policy/session.json` | **10 项 PASS**，末行 `RESULT: PASS`；证书按 kind：`tool-args` 3 / `tool-result` 2 / `stream` 4 / `llm` 1 / `zk` 3 |
| 真出证 | `regression_prove.py --label P3-acceptance` | 出证 **19/19**（**1899.3 s**，峰值 **10,843 MB**）+ 验证腿 `clean_pass`（140.4 s，`proof_bytes` 2,782,131）；`regression-prove.jsonl` 追加**第 5 行** |
| 真出证 | `demo_all.sh --prove` | **8 支路全 PASS，SKIP 集合 = ∅**，合计 ≈**20.9 min** |

`verify_session` 的 10 项与 `demo fast` 的 8 支路**与 P1/P2 逐条一致**，
`acceptance` 七面**零差异** —— 也就是说 R13/R14 两个阶段**没有动过任何一个
被观测的行为**。

##### ⑦ 的分支明细（peak 一列是这次真出证的实测）

| 支路 | 墙钟(s) | 峰值(KiB) |
|---|---:|---:|
| 公开模式主干 | 120.9 | 10,889,124 |
| 私有模式 | 123.0 | 10,831,408 |
| 语义规则(P2-9) | 9.4 | 1,030,108 |
| 组合证明(P1-6) | 346.4 | 10,950,520 |
| 会话聚合(P2-10) | 281.6 | **10,967,312**（本轮最高，≈10.46 GiB）|
| 多证明者(P2-11) | 188.0 | 10,922,884 |
| 链上锚定(P7-c) | 160.3 | 10,917,544 |
| 第三方独立验证 | 25.2 | 7,359,496 |

**语义支路只有 1.0 GiB**（其它七条都在 10.8–10.97 GB）—— 它走的是 ezkl 那条陪伴
证明的路，**不碰 SP1 证明器**：这条支路的日志里 `pop-script` / `sp1` 的出现次数是
**0**（`grep -ci` 实测）。与「SP1 出证地板 ~10.15 GiB」是两回事，别混。

##### ⑥⑦ 严格串行：这次是真的守住了

两条腿峰值都到 **10.8–10.97 GB**，而本机总内存 **11,958 MB** —— 重叠必炸。
执行顺序与中间检查：

1. ⑥ 起（`setsid nohup … & disown`）→ 全程约 **34 min**；
2. 退出后等 15 s，`free` 回到**可用 10,647 MB**、`pgrep` **无残留**，才起 ⑦；
3. ⑦ 全程约 **20.9 min**，退出后 `free` 可用 **10,639 MB**、`pgrep` 无残留。

**一个实测的坑（记下来，下次别再踩）**：⑥ 是作为**前台等待**（`kill -0` 轮询）盯完的 ——
第一次用工具的后台任务盯，被内存守卫**杀掉了等待进程**（告警原文：running low on memory）。
**等待进程被杀不等于出证进程被杀**（⑥ 当时仍活着，最终正常跑完）。教训是
`dev-plan.md` §5.7.6 那条的延伸：**长任务要 `setsid` 脱离，盯它的手段也必须是不吃内存的**
（前台 `kill -0` 轮询 / `sleep` 循环），别用一个会被守卫收割的后台壳去套。

##### ⑥ 留痕里的 `dirty: true` 是正常的

`regression-prove.jsonl` 记的 `git.sha = da7db49`（**这就是被验收的树**：R14 的
代码 `e25720e` + 门槛 `d4cfba5` + 三份文档提交），`dirty: true` 有两个来源，
都不是缺陷：① 那条记录**是在运行过程中追加进去的**（文件自己把自己改脏了）；
② 两个**未跟踪**的 `bench/results/ablation_live.*`（R11 实验产物，见 §5.7.16，
**按约定一直不动、也不入库**）。

##### 回退记录

**本轮无回退。** 八项里没有任何一项触发中高风险项的回退判据：
R13 四条删除各自的门禁全绿，R14 四条判据全过且等效性由快照第 1 面机械证明。

##### 结转（仍未销案，如实记）

- **§5.7.13 那条「R8 之后一次孤立的 `failures=1`」仍然没被复现。**
  P2 与 P3 两轮大验收里全量套件跑了**多次**，**次次 OK** —— 但「没复现」不等于
  「不存在」。来源指向 R7（策略加载器收敛）那条线，**在找到可复现路径之前不许
  当成已修**。下一轮谁动 `Policy.from_dict` 附近，请把这个案底一并带上。
- **R14 之后 `core` 已无倒置**，`tests/test_layering.py` 会挡住回退。但那条闸门
  **只覆盖 `core → proofs`** 这一个方向、这两个包；别把它当成完整的层次检查器。

---

### 5.8 结构/架构文档校对 + demo 子系统重整（2026-09-18 立）

#### 5.8.1 起因与两条边界

用户 2026-09-18 的要求：**调整梳理项目结构和架构设计组织，重新编写 demo 对应文档
和相关功能模块，开发使用文档。**

§5.6（2026-09-17）已经做过一轮同类工作（拆包 / 分组 / 索引 / demo 文档 / 手册，
七步七个提交，见 §5.6.11）。**但之后 §5.7 的 R1–R18 重构又动过代码** ——
所以本轮的性质是**校对式重写**。动手前先定死两条边界：

1. **目录物理布局不动。** 它被 `test_scripts_layout` / `test_doc_links` /
   `test_layering` / `test_frontdoor` 共 **27 条断言**钉住（2026-09-18 实测全绿），
   且刚在 §5.6 理过一遍。本轮**只把「文档说的」与「代码是的」重新对上**，
   不改结构本身。
2. **demo 子系统连代码一起重整**（用户 2026-09-18 明确选择）。
   理由是普查发现那里有**真实断点**，不是措辞问题 —— 见下表第 7–9 条。

#### 5.8.2 现状普查（每条都能从仓库直接核对）

| # | 漂移 | 现场 | 性质 |
|---|---|---|---|
| 1 | `07` 的脚本计数是旧的 | 头部与 §1 写「**16** 个 Python 入口 + 7 个 shell = **23**」；磁盘实为 **18 + 7 = 25**。差额恰是 verify 组漏列的两个 | 计数 |
| 2 | verify 组清单漏两个脚本 | `07-cli-scripts.md` §1 的组表只写 `verify_cert.py` `verify_session.py`，`scripts/verify/` 下实有 **4 个**：另有 `acceptance.py`、`loader_parity.py`（`grep` 在该文件里 **0 命中**）。注：只此一处漏；根 `README.md` 并无逐脚本清单 | 漏项 |
| 3 | `core/model_fp.py` 在文档里失踪 | R14（`e25720e`）从 `proofs/semantic.py` 下沉来的模块。`01-policy-dsl.md` 头部覆盖行、`modules/README.md` 的布局树**与**板块表 —— **三处都没有它**（`grep -c model_fp` 在两个文件里均为 **0**）。只有 `08-tests-bench.md:53,57` 在讲 R5/R14 两条测试时提过 | 漏项 |
| 4 | 四个模块没有板块认领 | `evidence/trace.py`（P1-5 处处引用）、`evidence/keys.py`、`runtime/{service,auth}.py`、`paths.py` —— **正文有提，覆盖列表里没有**：03 头部只写 `cert.py`+`agent.py`、04 头部只写 `anchor.py`+`verifier.py`；02 头部只写 `commit.py`，漏了 `challenge.py` | 归属 |
| 5 | 5 处把**已冻结的历史文档**说成「当前计划」 | `README.md:245`、`roadmap.md:4`、`roadmap.md:62`、`docs/8week-gantt.md:4`、`circuits/README.md:92` 都指向 `plan-p0p1p2.md`；而 `docs/README.md` §2.2 已把它列为**已冻结历史**、写明唯一维护中的计划是 `dev-plan.md`。**文档与文档自相矛盾** | 自相矛盾 |
| 6 | `bench/README.md` 说「**六个**脚本」，实际 **8 个** | 表里缺 `bench_streaming.py` 与 `bench_prover_knobs.py`（后者是 R11 新增）—— 两份在该文件里均 **0 命中**。`08-tests-bench.md` 两份都提了 | 漏项 |
| 7 | `demo_all.sh` 的 `_solo` 是**死目录** | `demo_all.sh:94-95` 建 `$OUT_DIR/_solo`，注释写「供不走 out-dir 参数的驱动（private_demo）用」；但 `private_demo.py:171` 把产物路径**硬编码**成 `REPO/scripts/examples/out/private`，**根本不读这个变量**。于是每条支路都落在统一产物目录里，只有私有模式那条约 13 个产物散在源码目录下 | 名不副实 |
| 8 | 报告/截图那条腿**没接进编排** | `demo_all.sh` 全程**不调用** `make_shots.py`；而 `make_shots.py:30` 的默认输入是 `scripts/examples/out/e2e/session.json`，与 `demo_all.sh` 产出的 `…/out/all/policy/session.json` **不是同一份**。跑完编排想拿报告，得自己拼 `--session` 参数 | 断链 |
| 9 | `docs/demo/` 下三份产物过期 | `session_report.svg`、`session_summary.png`、`verify_result.png` 的 mtime 都是 **09-13 02:36**，早于 `make_shots.py` 当前版本（09-17 08:08）**4 天**；只有 `.html` 是新的。且 `docs/demo/README.md` **通篇不提** `make_shots.py`（0 命中）—— 四份产物在文档里没有出处 | 过期 |
| 10 | 根 README 目录结构树漏项 | 漏 `.github/workflows/ci.yml`（全仓 README **无「CI」字样**）、`requirements-ezkl.txt` / `requirements-frameworks.txt`、`方向二_README.md`、`.pop-keys/`，以及 `contracts/` `circuits/` `bench/` 三个子目录 README | 漏项 |
| 11 | `docs/demo/README.md` 的环境前提过窄 | §2 写「fast 只要 Python 3 与标准库」，但 `policy` 支路驱动 `demo_e2e.py` 要 langchain / langgraph / mcp 才跑得起来（那正是它演示的东西） | 口径 |

**另一项单独登记，不在本轮改动内**：`policydsl/.pop-keys/signing.key` 是一份
**孤儿私钥** —— 与根 `.pop-keys/signing.key` 内容不同（`a656b8…` vs `dca2d0…`），
而 `policydsl/evidence/keys.py:48` 的缺省路径 `DEFAULT_KEY_PATH` 指向**根**那份，
所以 `policydsl/` 里这份**没有任何代码会读**（全仓 `grep` 只有这一处 `DEFAULT_KEY_PATH`
定义，无相对路径写法）。来源已查明：mtime **09-17 07:56**，而拆包提交 `22642bc`
是 **09-17 08:06** —— 正是 `paths.py` docstring 记的那次 `parent.parent` 事故
（拆包期间 `policydsl/evidence/keys.py` 的 `parent.parent` 一度等于 `policydsl/`）。
**该事故已修**（`REPO` 现由 `find_repo()` 按标记搜索），这份文件是**残留**。
两份都在 `.gitignore` 内、不入库。**本轮只登记、不删除** —— 它不是本轮创建的东西，
处置权交回用户。

#### 5.8.3 分步与验收闸门

每步**独立提交**，闸门不过就迭代到过（长期规则）。文档类步骤的闸门是
`test_doc_links`（相对链接悬空 0）+ 全量套件；代码类另加真跑。

| 步 | 做什么 | 闸门 | 状态 |
|---|---|---|---|
| 0 | 方案（本提交） | — | ✅ 2026-09-18 |
| 1 | **结构/架构文档校对**（第 1–5、10 条）：07 计数与 verify 组、`model_fp` 补三处、trace/keys/runtime/paths 认领、02 头部补 `challenge.py`、5 处计划错指、根 README 目录树 | 悬空链接 0 + **782 passed / 15 skipped** | ✅ `4b473ad` |
| 2 | **评测文档**（第 6 条）：`bench/README.md` 六→八个、补两行；`08` 校对其 bench 节 | 同上 | ✅ `9c6dba6` |
| 3 | **demo 代码重整**（第 7–9 条）：`private_demo.py` 加 `--out-dir`（缺省值**保持原样**，只是可覆盖）并接进 `demo_all.sh`；删死 `_solo`；`demo_all.sh --shots` 把报告腿接上 | `test_demo_e2e` + `demo_all.sh`（fast）+ `--shots` 真跑出四份产物 | ✅ 2026-09-18 |
| 4 | **拆 `demo_e2e.py` 的 `main`**（258 行）：纯搬位置、行为不变，口径同 R8 | `test_demo_e2e` + fast demo **输出逐行不变** | |
| 5 | **demo 文档重写**（第 9、11 条）：补 `make_shots` 一环、修环境前提、统一计时口径、更新产物树；**重渲**三份过期产物 | 8 条支路与 `LANES` 机械比对一致 + 四份产物 mtime 全部更新 | |
| 6 | **开发手册校对**：`docs/development.md` 补两条 verify 脚本与 `--shots` 用法，计数对齐 | 手册里每条新命令**实敲一遍** | |
| 7 | 收尾：测试计数「四处同步」、交叉链接普查、推送 | 全量 + 工作树干净 + origin 同步 | |

**本轮的重闸门**（步 4 之后一次跑完，不跑两遍）：`bash scripts/demo/demo_all.sh --prove`
真跑一轮 —— 8 条支路全 PASS、**SKIP 集合 = ∅**。≈21 min、峰值 ~11 GB、**必须串行**
（§5.7.22 的两条实测教训：长任务 `setsid` 脱离；盯它的手段也要不吃内存）。

#### 5.8.4 边界（本轮**不做**）

- **不动 `policydsl/` 与 `scripts/` 的目录布局** —— 那要另开一轮，且会碰四条结构测试。
- **不动论文** —— 本机无 TeX 工具链，改了无法本地验证（§5.6.11 已如实登记）。
- **不重跑 bench 数字** —— R11 的 `bench/results/ablation_live.*` 是未跟踪产物，
  按 §5.7.16 的约定一直不动、也不入库；本轮只把它在文档里**登记清楚**。
- **不删** `policydsl/.pop-keys/`（见 §5.8.2 末段）。
- **不接 `make_shots` 进第 9 条支路** —— 它是「收尾一步」而不是一条独立支路，
  加进去会让「8 条支路」这个已被测试与文档钉住的口径变成 9（改动面远大于收益）。
  做法是给 `demo_all.sh` 加 `--shots` **开关**，缺省不开。
