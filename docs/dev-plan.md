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
- [x] 证书规范：`policydsl/cert.py` —— payload `{cert_version, policy(id,version), policy_hash, mode, outcome, binding{vkey_hash, proof_sha256, proof_mode}, ai_act, ts}` + **DSSE 信封**（Ed25519 签名，P0-3；按 `keyid` 前缀分发）+ 稳定 `cert_digest`（`proof_mode` 为 P0-4 的证据档位诚实标注）
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
- [x] **一键端到端 demo（P5I）**：`scripts/demo_e2e.py` —— 真实会话（LLM 流式链+早停、真实 MCP 参数/响应侧、含预检拦截）→ 13 张证书 → 锚定账本 →（可选）**真实 SP1 证明**；`scripts/verify_session.py` 第三方独立验证
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
- [x] **P7-b format/budget/tool 规则入电路**：请求扩展「响应+工具轨迹」；`FormatCheck`（json/int/float 规范子集）/`ToolArgGuard`（含 tools 限定）/`BudgetBound`（calls/tokens）在 `pop-types::evaluate` 判定；跨层证据串逐字一致；`AgentMonitor` 工具路径 `zk:true`；`tests/test_rules_incircuit.py`(13) + cross_validate **14 向量（host 14/14 + 真实证明 14/14 PASS）**（P7-b 当时的向量集；2026-09-12 已随 P1-5/P2-9b 扩到 **19 向量**，见 `docs/reproduce.md` §验收判据）
- [x] **P7-c 链上锚定 RPC 后端**（2026-09-10 完成，foundry 1.8.1 装好、真跑本地 Anvil 端到端 PASS）
  - 合约：`contracts/Anchor.sol`（`anchor(bytes32)` 首次即最终 + `anchoredAt/anchoredBy/isAnchored/count` + `Anchored` 事件，链上只存 32 字节摘要）；`contracts/Anchor.json`（abi+bytecode）**入库** → 运行期部署**不需要 solc/forge**
  - 后端抽象：`AnchorBackend` / `FileLedgerBackend`（默认，离线可验）/ `RpcAnchorBackend`（幂等；链上成功后回写 `meta.on_chain={tx_hash,block,chain_ts}` 到本地哈希链账本）；`backend_from_env()`；`CastRpc`（foundry `cast`，**不引入 web3.py 依赖**，可注入以便离线单测）
  - 工具：`scripts/deploy_anchor.py`、`scripts/anchor_e2e.sh`（起 anvil → 部署 → 13 张证书全部上链 → 第三方 `verify_session --rpc` → 反例对照）；`issue_cert.py`/`demo_e2e.py`/`verify_cert.py` 均支持 `--rpc/--contract`
  - 真跑修复：`pop-script --proof-out` 对 **core 也会写边车**，导致「verifier-only 快路径」误判 core（`pop-verify` exit 3）→ 抽出 `policydsl/verifier.py::prefer_verifier_only`（二进制+边车+模式∈{compressed,groth16,plonk}）并补单测
  - 验证：`scripts/anchor_e2e.sh` **ALL PASS**（`chain_anchored 14/14` + 反例 0）；`--prove` 变体真实 Core 证明上链且第三方验证 PASS（**2026-09-12 复跑确认**：3:10 / 峰值 10.18 GiB）；`tests/test_anchor_chain.py` 22 例全绿（无 anvil 自动 skip）
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
- [x] **发布材料**：README 一键 demo + `docs/reproduce.md` 复现指南 + `scripts/make_shots.py` 截图；
  测试 **630 全绿 / 15 skip**（2026-09-13 复跑；skip 均为设计内，见 `docs/security-model.md` §6）
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

> **前置**：Phase 0–6 与 P7 全部收尾，测试 **630 全绿 / 15 skip**，
> `scripts/demo_all.sh` 8 条支路全通。本节是**交付之后**的两步 ——
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
   **已做（#98）**：新增 `policydsl/llm.py`（规格解析 + 构造，**刻意不认**
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
| 库：策略注册表 + 作业队列 + 两段出证 | `policydsl/service.py` |
| HTTP 驱动（纯标准库） | `scripts/proof_service.py` |
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

- `policydsl/auth.py`（新模块）：token 解析/匹配/令牌桶。**单独成模块而不是塞进
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

- **`ledger_tail()` + `(st_size, st_mtime_ns)` 戳的缓存**（`policydsl/anchor.py`）：
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

- `policydsl/cert.py`：新增 `VKEY_HASH_UNPROVEN`（**故意**等于 `PROOF_MODE_UNPROVEN`
  同一个字符串 —— 二者说的是同一件事），把「vkey 没有真值可指」这件事从一条
  注释升级为一个**具名常量**；
- `scripts/demo_e2e.py`：`vkey = "demo"` → `cert.VKEY_HASH_UNPROVEN`；
- `scripts/verify_cert.py`：新增 `vkey_label` 卡（2c），与 `proof_mode` 卡（2b）同构；
- `scripts/verify_session.py`：新增 `certificates_vkey_label` 卡，两个方向都拦；
- `tests/test_policy_binding.py`：`TestVkeyLabelHonestyRejected`（4 例，**反例就是
  `"demo"` 本身**）+ `TestSessionVkeyLabelHonesty`（2 例）。

> **这道校验当场抓出了两处既有问题**，说明它不是恒真的：
> ① `tests/test_policy_binding.py::TestVerifierEndToEnd` 的 fixture 里，
> 那条名为 `test_honest_certificate_passes` 的**诚实对照组**所用的证书
> `vkey_hash` 恰恰是随手编的 `"deadbeef"` —— 与 `demo_e2e.py` 是同一个毛病；
> ② `issue_cert.py`、三个适配器的缺省值、`zk_path --no-prove` 分支都已经是对的
> （`unproven`），唯独演示脚本例外。现已一并订正。
