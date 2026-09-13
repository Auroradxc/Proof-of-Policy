# 08 · 测试与评测

> 覆盖 `tests/`（27 个模块，581 个用例）与 `bench/`（5 个脚本，结果入库在 `bench/results/`）。
> 这一板块回答：**哪些性质被自动化守住了，论文里的数字是怎么测出来的。**

---

## 1. 测试套件总览

```bash
python3 -m unittest discover -s tests -t . -v   # 期望 581 passed, 15 skipped
```

| 模块 | 用例数 | 守护的性质 |
|---|---:|---|
| `test_trace` | 41 | **P1-5**：四条验收（①完整链通过 ②删/换/重排失败 ③伪造「参数干净」的回执验签失败 ④旧 `tool_calls` 向量被拒）；`trace_root` 与 Python **逐字节一致**（实测 `--check`）；编码层的长度前缀/键序/keyid 覆盖；链尾篡改**只有链下验签抓得住**的边界；**第三方核对**（`verify_cert.py --receipts [--gateway-key]` 7 例：摘要重算对齐 / 换链对不上 / 重排结构先炸 / 伪造链尾只被验签抓住 / 缺网关公钥时如实报「签名未验」/ 没有 `--receipts` 时仍单独核 seal / 截尾三路全拒）；**P1-5b 截尾对策**（`TestSeal` 9 例：确定性 / 空链 genesis / 四个字段都进签名原像 / 回执签名不能冒充 seal（域分隔）/ 三类失败形态 / 早期 seal 被后续调用作废 / 无公钥时如实报「签名未验」/ **seal 只进载荷顶层不进 outcome** / 缺 seal 的诚实口径）+ **`test_tail_truncation_is_rejected`**（原 seal+截断链 / 冒充 keyid 的伪造 seal / 索性不带 seal 三路全拒 + 「没截尾时全 PASS」的正对照；原「缺口」用例已翻转，见安全模型 §5.3 与待办 T4） |
| `test_dsl` | 29 | 领域模型、七类规则的通过/违规矩阵（含 P2-9b 的 `normalized_keyword_block`）、`PolicyError` 路径；**P1-5**：链坏 fail-closed、tokens 电路内自算（不可自填） |
| `test_nfa` | 7 | 正则子集解析、NFA 构造、`match_search` 与 `re` 的行为对照、fail-fast |
| `test_pii` | 8 | 四个 PII 模式的命中/漏报、IBAN MOD-97 校验位 |
| `test_serialize` | 10 | serde 外部标签枚举形状、未知 kind 抛 `NotImplementedError`、`spec_canonical` 字节稳定 |
| `test_commit` | 12 | 承诺、私有输出、掩码覆盖、脱敏、证据开示 |
| `test_policy_binding` | 28 | **P0-1**：策略绑定三方比对；「空策略证明 + 真策略哈希」攻击回归；未入电路的 kind **fail-closed**；**P0-4**：夸大/低报证明模式的证书被判 FAIL（单证书层与会话层各一）、缺字段的旧证书如实跳过 |
| `test_binding` | 19 | **P0-2**：挑战-响应绑定（①正确对通过 ②换 T 拒 ③换 nonce 拒 ④空 nonce 独立域）、`NonceStore` 重放、Python↔Rust 逐字节对齐、带挑战证书端到端 |
| `test_cert` | 19 | 证书载荷、`cert_digest` 稳定性、签名与篡改拒绝；**P0-3**：按 keyid 方案前缀分发、旧 `demo-hmac-sha256` 结构性被拒、`load_keyring` 的三种公钥来源（路径拼错要报**真因**）；**P0-4**：`binding.proof_mode` 诚实标注与 `proof_hiding` 映射 |
| `test_cross_validate` | 6 | 真实证明分块（`--chunk`）：切开后拼回去逐一相等、顺序不变、`--chunk 0` 等价单进程、默认值刻意保守 |
| `test_agent` | 5 | `AgentMonitor` 两条路径、`mock_agent` 确定性、LangGraph 适配 |
| `test_frameworks` | 53 | LangChain 回调（流式链/篡改/早停/**真掐断**）、`guard_node`、`astream_events`；**P0-4**：`proof_mode` 贯通到回调与 `guard_node` 出的证书；错误回调（#96）与统一网关（#99，含**非恒真对照**：不共用网关时 seal 报截尾） |
| `test_mcp` | 15 | 参数侧飞行前拦截、结果侧判定、文本提取、**工具清单动态发现**（#98：未声明的工具在执行前被拦，附「声明过的照常放行」对照）；**P0-4**：`proof_mode` 同时落到参数侧与结果侧证书 |
| `test_real_llm` | 13 | **`--model` 真模型客户端**（#98）。三层：① 规格解析与报错（未知 provider / 空模型名 / 缺 key 都当场说清是哪一个，**刻意不认** Claude Code 自己的 `ANTHROPIC_AUTH_TOKEN`）② 真实 `langchain_openai` 客户端 + 本地 SSE 桩（`tests/openai_sse_stub.py`，**默认跑**，不需要网络与真 key）—— 由**服务器侧**数它写出去了几片，证明早停是在**传输层**真的断了连接，而非「我们这边不再 append」；对照组是关掉 `hard_stop` 后每一片都写出去 ③ 真 provider（`POP_TEST_LLM=1`）只断言结构，**不**赌模型一定会违规 |
| `test_anchor` | 4 | 账本读写、`verify_ledger`、篡改检出 |
| `test_anchor_chain` | 22 | 合约 artifact、摘要编码、后端选择、RPC 后端离线（幂等/竞态）、cast 命令行、anvil 端到端 |
| `test_normalize` | 28 | **P2-9b**：同形异义折叠（`pop-fold-v1`）。折叠表构造与 13 种非法声明（未知版本/未知键/超长表/非 ASCII或多字符替换值/自映射/重复 `from`/`map∩drop` …）全部 fail-closed；算法单遍**不链式**、`ascii_lower` 只碰 ASCII；**验收判据**是「折叠前 `passed=True`、折叠后 `passed=False`」这一对（并另断言 ASCII 那条被两条规则同时拦住，免得用例退化成恒真）；折叠表**进契约** → 改表即改 `policy_hash`。 |
| `test_rules_incircuit` | 13 | 七类规则在 `--check` 下与 Python golden 逐点对齐（**P1-5**：轨迹类规则判回执链，链坏两端都 fail-closed；**P2-9b**：`normalized_keyword_block` 7 组逐点对拍 + 私有模式下证据承诺与 Python 一致） |
| `test_ablation` | 5 | pike ≡ naive（Python 与 Rust 两侧） |
| `test_verifier_only` | 8 | `prefer_verifier_only` 三条件、core 不走近路；**P0-4**：`artifact_proof_modes` 收齐多来源、缺失不编默认值、来源不一致如实暴露 |
| `test_demo_e2e` | 4 | 端到端会话产物结构；**`--model` 与离线桩同构**（#98：真客户端跑出的会话与 fake 路径**逐条同形** —— 比的是两份会话的形状，不是一个写死的数字，因为写死的数字在假路径改动之后不会报错、只会静默地变成另一件事），外加「规格写错必须报错、绝不静默退回桩」 |
| `test_ezkl_evm` | 10 | **T2**：`ezkl_evm.run` 对同步/异步/Future 三种可调用对象都成立（5 例，**不依赖 ezkl**）；真实 ezkl 下裸调用必抛 `no running event loop`（把上游坏行为钉死）、包一层即产出 `Halo2Verifier` 源码与 `verifyProof` ABI、连调互不影响、`reusable` 变体 + VK artifact（`vka.json` 实为 bincode，不是 JSON）、**剥空 `PATH` 也不调用 solc** |
| `test_semantic` | 30 | **P2-9**：语义规则（学习型规则）的委托与绑定，**含 6 条反例**（换 ONNX、换 vk、改阈值、翻转 `direction`、换证明文件/换响应、图外自算特征）与 fail-closed 四路（缺材料目录/缺陪伴证明/缺 `--response`/多带证明）；**分层**见下 —— 30 例中只有 1 例（`test_real_proof_verifies_and_binds`）需 ezkl 与 32 MiB `srs`，其余 29 例在本机实际执行 |
| `test_compose` | 48 | **P1-6**：组合证明 `Compose = (推理完整性 ∧ 策略合规)`。三层 —— ① 参考实现逐位一致（`pop-script --check --job infer` ↔ `policydsl/infer.py`：模型哈希/响应绑定/输入绑定/输出）② 组合绑定的 **5 组反例**（换证明文件·缺失、同 vkey·非期望 vkey、换模型·换输入、两半绑不同 T·送达 T′ 不符、形状·模式·域·policy_hash 重编译）③ **四条驱动接线回归**（`--job` 旗标 ≠ part 的 kind；`part_from_proof` 得把旗标而不是 kind 传下去；验证结果的 `mode` 不能被当展示元信息剥掉；`pop-script --verify` 必须显式给 `--out`，否则在仓库根落一个 `results.json`）——这几条对应 2026-09-12 真端到端跑出来的真 bug，单测当时全绿。真·端到端 5 例由 `POP_TEST_COMPOSE=1` 打开 |
| `test_session` | 38 | **P2-10**：跨证书一致性（`session` 域 = guest③）。三层 —— ① **Merkle 纯算术层**（单叶子即叶子本身；内部节点带 `pop-session-node-v1` 前缀；**奇数末位提升、绝不复制** ← 这条是「挖尾」防线的前提；n=1…9 的包含证明往返；篡改叶子与形状非法 fail-closed）② **两层对拍**（`pop-script --check --job session` ↔ `policydsl/session.py::run_session` 在链长 1/2/3/5/8 上**逐字段相等** —— 奇数链才会走到末位提升；Merkle 根跨层逐字节一致；nonce 改则 `session_binding` 改）③ **义务与反例**（混异策略 / 挖中间 / 换序 / 缺 `chain` / 缺 `seal` / 两条网关的 seal / 空集；验证侧的 happy path、**挖尾**、**整张换尾**、伪造根 / 伪造链尾承诺 / 伪造策略哈希、错域、现场重编译策略包、seal 签名与真回执）。**真·端到端 1 例**（`POP_TEST_SESSION=1`）对着真证明跑计划的两条验收判据（混异策略 + 挖尾），并核 `--nonce` 换一个即拒 |
| `test_multiparty` | 44 | **P2-11**：多证明者（模型方 / 工具网关 / 部署方各证一段策略切片）。三层 —— ① **切分层**（8 个 kind 的归属普查：每条规则恰属一个角色、切片两两不交且并集为全策略、三个角色**恒存在**（空切片也要签名）、未知 kind 在两处被拒、同名规则拒绝、`require_covering_length_bound` 只在整条策略上查一次、切片与整策同一份编译器、内容寻址确定性）② **绑定层**（happy path；缺 keyring 时如实标注「未验签名」；语义切片真实但需陪伴证明；JSON 往返；`plan_digest` 绑进**每一份**签名；**验收 ①** 缺任一角色签名 / 空签名表 / 缺 part / 重复 part；**角色密钥分离**；**验收 ②** 单角色切片被换（含该角色拿自己键重签、把切片谎报为空、单独改 plan、改 `plan_digest`）与**三方合谋改 plan**（不带策略包时而通过、带上 `policy_pack` 即被拒 —— 如实记下这条边界）；证明文件被换 / 张冠李戴 / 空切片带证明 / 非空切片不带证明 / 非 public 模式 / vkey 混用 / 非期望 vkey；换 T / 两半绑不同 T / 不同 `trace_root`；违规切片是**真证书但未满足**）③ **构造层**（缺角色键、一把键当两个角色、空策略无法出证、构建期缺证明、构建期 part 与策略不符）。真·端到端 1 例由 `POP_TEST_MULTIPARTY=1` 打开 |
| `test_proof_service` | 62 | **第二步（服务化）**：策略注册表（同名不同内容拒收、坏包**报告**而不吞掉）、**两段同形**（`host_outcome` 的键集与电路公开值逐字段相同；`violations` 镜像 `pop-types::evaluate`；两套推导打架就**停证** `VerdictMismatch`）、队列（第二个请求**排队**而非被拒、满了 429 且被拒的不吃队列位、作业炸了不带走工作线程、`stop()` drain）、`/v1/check` 的证书**真的验得过**（`verify_cert.py` → `RESULT: PASS` 含 `[PASS] trace_binding`，且账本里每条锚定摘要磁盘上都还在）、OOM 杀进程要被翻成一句「内存不足」（含 10.15 GiB 地板与 `dmesg` 核实法）、HTTP 层分得清 400/404/413（**413 不读正文**）、**鉴权层**（27 例：token 解析与三条拒收理由「短/含空白/重复标签或 secret」、**五处来源合并而非覆盖**、401 带 `WWW-Authenticate` 且**区分「格式错」与「token 错」**、报错**不回显**收到的值、`/v1/health` 快照**不含 secret**、令牌桶突发→429→回填、**按 token 分桶**（一个人打满不饿死另一个）、管理员豁免、**别人的作业返 404 且与「不存在」措辞逐字相同**、未鉴权不许提交）。**真 vkey 出证 1 例由 `POP_TEST_PROOF=1` 打开** |
| **合计** | **581** | |

### 15 个 skip（都是设计内的）

| skip | 原因 | 怎么启用 |
|---|---|---|
| `test_verifier_only` 中 2 例 | `circuits/testdata/audit_proof/` 没有 compressed fixture | 在 ≥16 GB 机器上跑 `SP1_PROVER=cpu bash scripts/make_audit_proof.sh` |
| `test_frameworks`（或 `test_mcp`）中 1 例 | 依赖已安装而用例本身是「缺依赖时的行为」 | 设计如此，装了框架就会 skip |
| `test_policy_binding` 中 2 例 | 「证明层」用例默认关闭（要 `scripts/examples/out/cert_public/` 下的工件与当前 guest ELF 匹配；改过 ELF 就得重新出证） | `POP_TEST_PROOF=1 python3 -m unittest tests.test_policy_binding`（**已实测通过**：Ran 22 … OK，67.1 s） |
| `test_multiparty` 中 1 例 | 「真·端到端」要给**两段**切片各出一份 SP1 证明（每段 ~2 分钟、峰值 ~10 GiB） | `POP_TEST_MULTIPARTY=1 python3 -m unittest tests.test_multiparty.TestMultipartyEndToEnd -v` |
| `test_semantic` 中 1 例 | 「真·端到端」要出一份 ezkl 证明（~61 s、峰值 ~9 GiB） | `POP_TEST_EZKL=1 python3 -m unittest tests.test_semantic`（已实测通过） |
| `test_compose` 中 5 例 | 「真·端到端」要出**两份** SP1 证明（各 ~2 分钟、峰值 ~10.5 GiB） | `POP_TEST_COMPOSE=1 python3 -m unittest tests.test_compose`（**已实测通过**：47 例全跑、无一 skip，563.5 s；加四条接线回归后共 48 例） |
| `test_session` 中 1 例 | 「真·端到端」要出一份 SP1 **会话聚合证明**（3 张证书，~2.5 分钟、峰值 ~10 GiB） | `POP_TEST_SESSION=1 python3 -m unittest tests.test_session.TestSessionEndToEnd -v`（**已实测通过**：Ran 1 … OK，152.5 s —— 含一次出证、一次独立验证与**四条**拒绝路径：换组证书 / 尾截断 / 混入异策略证书 / 错 nonce） |
| `test_proof_service` 中 1 例 | 「真 vkey 出证」要跑一次 SP1 core 证明（~2.5 分钟、峰值 ~10.2 GiB 的**固定地板**）。本机 11.7 GiB **装得下但没有余量**：2026-09-13 第一次与别的进程并跑时被 OOM killer 杀在 9.7 GiB 常驻（`dmesg` 有记录），**腾空后重跑通过**（171.1 s，`MemAvailable` 一度只剩 0.15 GiB 并靠 swap 撑住）。服务把这种失败翻成一句人话，见下 | `POP_TEST_PROOF=1 python3 -m unittest tests.test_proof_service.TestRealProofAttest -v`。**跑之前先让别的进程腾出内存**（本机实测：腾空即过、并跑即 OOM）；换 ≥16 GB 的机器则不必讲究 |
| `test_real_llm` 中 1 例 | 「真 provider」要一个真 API key + 网络 —— CI 不该依赖它 | `POP_TEST_LLM=1 POP_TEST_MODEL=openai:<model> python3 -m unittest tests.test_real_llm`。**注意**：同模块里那 4 例真客户端的用例（本地 SSE 桩）**默认就跑** —— 桩实现的是 OpenAI 的协议，所以「真实客户端接进回调层后早停还能不能掐断」不需要网络与真 key |

#### `test_semantic` 为什么敢把 ezkl 关在门外

六条反例在 `verify_companion` 的**第 1–5 步**就被挡住（指纹比对、证明文件哈希、
本地 `vk` 哈希、`encode(T′)` 逐位比对），而这几步不跑 ezkl 验证器 ——
所以 29 例在**没有 ezkl、没有 32 MiB `kzg.srs`** 的机器上也能全绿。
第 3 步之后才是"跑 ezkl 验证器"（`verify_proof=True`），它由那条默认关闭的端到端
用例覆盖。**把最后一颗钉子与整面墙分开**，是为了让反例能在 CI 上天天跑。

> `test_binding` 的 19 例**全部实际执行**：它靠 `pop-script --check`（秒级、不出证明）做
> Python↔Rust 逐字节比对，不需要真证明，因此不受 `POP_TEST_PROOF` 门控。

> 这是当前环境下的计数（`langchain`/`langgraph`/`mcp`、`pop-script`/`pop-verify`、
> 以及 `ezkl`/`torch` 均已安装，因此真实框架用例、Rust 路径用例与 ezkl 用例**实际执行**了，
> 而不是跳过）。**CI 上的 skip 数会更多（12 → 17）**：CI 不装 `ezkl`/`torch`，
> `test_ezkl_evm` 里需要真实 ezkl 的 5 例（`TestEzklEvmVerifier`）整组跳过，只有不依赖 ezkl 的
> `TestRunHelper` 5 例照跑 —— 这是设计内的，P2-9 的可选依赖不进 CI。

### 分层设计：为什么没装框架也能跑

所有框架适配器都遵循「**导入回退 + 离线 fake**」：

| 层次 | 手段 | 例子 |
|---|---|---|
| 真依赖存在 | 跑真实端到端 | `test_mcp.py` 起真 `stdio_client` 子进程；`test_frameworks.py` 用真 LangChain/LangGraph |
| 真依赖缺失 | 鸭子类型 fake | `test_mcp.py::FakeSession`（记录 `calls` 以证明「拦截发生在执行前」） |
| Rust 二进制缺失 | 用 `skipUnless` 跳过 | `test_rules_incircuit.py`、`test_ablation.py::TestRustNaivePath` |
| foundry 缺失 | 跳过 anvil e2e | `test_anchor_chain.py::TestAnvilEndToEnd` |

CI（`.github/workflows/ci.yml`）跑的是**最轻的一档**：Python 套件 + 锚定测试（离线 fake-RPC）
+ 一条文档卫生检查（禁止出现陈旧的绝对路径 `/home/*/方向二`）。**不跑证明、不依赖网络。**

---

## 2. 测试 ↔ 性质对照（安全模型）

把 `../security-model.md` 的定义映射到具体用例：

| 定义 | 对应用例/脚本 |
|---|---|
| Completeness | `scripts/prove_policy.py`（eu pass）、`cross_validate.py` **host 19/19 · prove 19/19**（2026-09-12 整批重跑） |
| Soundness（入电路规则） | `cross_validate` 的 violate 向量、`private_demo` 的违规用例 |
| Content privacy | `test_commit.py::TestPrivateOutput`（无明文泄露）、`private_demo` 的 `leak` 实验 |
| Redaction soundness | `test_commit.py::TestMaskCoverage`（伪造 span → `mask_covered=false`） |
| Evidence unforgeability | `test_commit.py::TestEvidenceOpening`（篡改开示 → 失败） |
| Provenance | `scripts/verify_cert.py` 的 `policy_hash`/`vkey`/`proof_sha256` 卡；`test_cert.py`；`test_policy_binding.py`（P0-1 攻击回归） |
| Response binding (A6) | `scripts/verify_cert.py --response` 卡；`test_binding.py`（换 T′/换 nonce/域分离）；`demo_e2e` 的 challenge 实验 |
| 证据档位诚实标注 (P0-4) | `scripts/verify_cert.py` 的 `proof_mode` 卡（与工件自报模式比对）；`verify_session.py` 的 `certificates_proof_mode`；`test_cert.py::TestProofModeLabeling`、`test_policy_binding.py::TestProofModeOverclaimRejected`（自称某档却无工件 ⇒ FAIL）、`test_verifier_only.py::TestArtifactProofModes` |
| vkey 诚实标注（同构的第二条） | `scripts/verify_cert.py` 的 `vkey_label` 卡；`verify_session.py` 的 `certificates_vkey_label`；`test_policy_binding.py::TestVkeyLabelHonestyRejected`（**用 `demo_e2e.py` 写过的魔法值 `"demo"` 本身作反例**）+ `::TestSessionVkeyLabelHonesty`。此前 `vkey_hash` **一条不变量都没有**，那个字段可以被写成任意字符串而全绿通过 |
| Ledger integrity | `test_anchor.py`（链篡改检出）、`verify_session.py::ledger_chain` |
| Stream chain | `test_frameworks.py`（链路验证/篡改/早停） |
| 链上锚定 | `test_anchor_chain.py`（离线 fake + anvil e2e）、`anchor_e2e.sh` 的 `chain_anchored` 与反例 |
| End-to-end | `scripts/verify_session.py` 全 PASS（含真实 SP1 证明） |

**关键的一类测试是「负例/反例」**：伪造 span、篡改开示、篡改账本条目、未登记摘要读回 0、
core 边车不得走快路径 —— 这些保证正向检查**不是恒真**的。

---

## 3. 评测（`bench/`）

**六个脚本**，覆盖六种成本：

| 脚本 | 测什么 | 用时不出证？ | 输出 |
|---|---|---|---|
| `bench_cycles.py` | **zkVM 周期数**（`pop-script --execute`） | 每点数秒 | `bench/results/cycles.{json,md}` |
| `bench_ablation.py` | **匹配器消融**：pike(NFA) vs 朴素回溯在病理输入下的退化 | 每点数秒 | `bench/results/ablation.{json,md}` |
| `bench_proofs.py` | **证明墙钟时间 + 工件大小 + 峰值内存** | 本机实测每点 **119–173 s** | `bench/results/proofs.{json,md}` |
| `bench_verify.py` | **验证成本**（冷启动 CLI / vkey setup / 纯验证） | 每次 ~20 s | `bench/results/verify.{json,md}` |
| `bench_semantic.py` | **ezkl 陪伴证明的成本**（setup / prove / verify） | 真出 ezkl 证明 | `bench/results/semantic.{json,md}` |
| `bench_compose.py` | **组合证明的成本**（两半各自 prove/verify + 组合层开销） | 真出两份 SP1 证明 | `bench/results/compose.{json,md}` |

```bash
python3 bench/bench_cycles.py
python3 bench/bench_ablation.py
SP1_PROVER=cpu python3 bench/bench_proofs.py
SP1_PROVER=cpu python3 bench/bench_verify.py --proof <proof.bin>
SP1_PROVER=cpu python3 bench/bench_compose.py
```

> `bench_proofs.py` 另有 `--proof-mode {core,compressed,groth16,plonk}`（默认 core）与
> `--points` 口径，写法见 [`bench/README.md`](../../bench/README.md)。量测机器与模式
> 会被一并写进 `proofs.json` 的 `host` / `proof_mode` 字段 —— **这张表只在它自己的机器上成立**。

**设计要点**（都写在 `bench/README.md`，改评测前先读）：

- **语料（P2-12）**：默认 `--corpus demo` —— 把仓库里**真跑出来的**工件的 `response`
  字段（`scripts/examples/out/**`）与示例回复汇总**去重**后当扫描对象，替掉以前那串纯
  合成的 `the quick brown fox jumps`。命中规则的段落**剔除并逐条记录**
  （真实轨迹里本来就有违规的：示例里那个 `sk-…` 凭据、含 `doxxing` 的回复都会命中），
  因为本基准量的是**扫到底**的最坏情况成本，命中即短路会让数字偏低。
  语料比采样点短（372 字符）时按**平铺重复**补齐，重复倍数如实写进结果 ——
  「一段 100k 的真实文本」和「372 字符铺 269 次」是两回事，不能含糊。
- 规则数 `1/2/3/4/6`（**刻意不是 `1/3/6`**）：那三个点对应的 `(n_kw, n_pat)` 是
  `(0,0)/(1,1)/(3,2)`，两个解释变量近似成比例，拟合出的单价一正一负 —— 这是**采样设计**
  问题，加长度救不了。走 `(0,0)/(1,0)/(1,1)/(2,1)/(3,2)` 才能把两类规则解耦。
- **消融**：`match_mode="naive"`（每个起点重跑 NFA，O(n²)）对照默认 `pike`。
  naive 只在 `length ≤ 2000` 上跑（>2000 在 zkVM 内过慢）。
- `bench_cycles` 走**子进程**调 `pop-script`（而不是 import），以测真实 CLI 路径的开销。
- **两条探针**（默认开，`--no-order-probe` 关）：**顺序探针**把同一批规则换个顺序再量；
  **边际探针**补上矩阵缺的「只有正则、没有关键词」那一格。它们不是补充材料 ——
  「成本不可按规则条数相加」这条结论的直接证据就是它们（见 §3.1 末）。
- `bench_proofs` 用 `/usr/bin/time` 抓峰值 RSS；每个点跑完顺手 `--verify` 确认证明有效。
  **每个点一个独立子进程**，且**量到一个点就落一次盘**：20k 的点随时可能被 OOM 杀掉，
  不能让前面几十分钟的数据跟着消失。

### 3.1 周期数矩阵（`bench/results/cycles.md`）

完整矩阵有 40 行（6 个长度 × 5 个规则数，naive 只到 2k），这里摘长度轴上的关键点：

| length | rules | pike | naive |
|---:|---:|---:|---:|
| 200 | 1 | 65,370 | 65,370 |
| 200 | 6 | 2,070,670 | 3,038,413 |
| 2,000 | 1 | 197,825 | 197,825 |
| 2,000 | 6 | 11,805,864 | 22,008,409 |
| 10,000 | 6 | 55,028,165 | — |
| 20,000 | 6 | 109,055,864 | — |
| 50,000 | 6 | 271,177,443 | — |
| 100,000 | 6 | 541,342,069 | — |

**读法一：固定策略时，cycles 对长度是精确线性的。** 每个规则集各自拿 6 个长度点拟合，
R² 全部 ≈ **1.0000**：

| 规则数 | keyword | pattern | 斜率 (cycles/字符) | 截距 |
|---:|---:|---:|---:|---:|
| 1 | 0 | 0 | 73.9 | 50,137 |
| 2 | 1 | 0 | 105.3 | 65,942 |
| 3 | 1 | 1 | 4,289.8 | 387,501 |
| 4 | 2 | 1 | 4,048.8 | 405,785 |
| 6 | 3 | 2 | 5,403.5 | 993,257 |

⇒ 扫描成本由 **NFA 正则主导**：一条 email 正则把每字符成本从 74 抬到 4,290
（**~58×**），而一条 keyword 规则只有 **~31 cycles/字符**。规则**条数**不是主因。

**读法二（重要）：成本不能按「单价 × 规则条数」相加。** 计划里那条
`cycles ≈ a·|T|·rules + b` 被数据否掉（R² = 0.872，截距为负）；更细的按类拆开也
拟合出**负的** keyword 单价（−477 cycles/字符）。这不是测量噪声，两条探针给出机制：

- **顺序探针**（同一批规则、同一段文本，L=100k）：声明顺序 541,342,069 vs 逆序
  570,736,989 ⇒ **+5.43%**，而两次的 `passed` 完全一致 ——
  **判定语义与顺序无关，成本不是**。
- **边际探针**（补上矩阵缺的「只有正则、没有关键词」那格，L=100k）：keyword
  单独加 **+31.6 cycles/字符**；在已有正则的策略里、加在正则**之前** **+585.6**、
  加在正则**之后** **−153.7**（反而更快）。同一个「加一条 keyword 规则」，
  单价随位置在 **−154 ~ +586** 之间**变号**。

⇒ 单价是「**规则 + 上下文**」的属性，不是规则的属性。原因是 zkVM 内 `ascii_lower`
与 Pike VM 都要分配内存，而**分配器状态依赖先前的分配**。所以本仓库引用的一律是
**按规则集的斜率**（上表），不引用任何加式单价。`bench_cycles.py` 的拟合也据此改成
**两段式**（先按规则集量斜率、再解释斜率），并把残差与两条探针一起写进结果 ——
**残差是结论，不是瑕疵。**

`naive` 在非对抗输入下约 1.9× pike（2k×6：22.0M vs 11.8M）；对抗输入下见 §3.2。

### 3.2 消融：病理输入下的二次退化（`bench/results/ablation.md`）

构造：模式 `a+b`，输入 `a`×n（整段没有 `b` ⇒ 必然不匹配 ⇒ 扫到底）。
`naive` 对**每个起点**重新锚定跑一遍。用 `bench/bench_ablation.py` 复跑：

| n | pike (cycles) | naive (cycles) | 比值 | naive 每字符涨幅 |
|---:|---:|---:|---:|---:|
| 100 | 643,894 | 12,382,720 | 19.2× | — |
| 200 | 1,145,209 | 48,638,946 | 42.5× | +96.4% |
| 400 | 2,143,617 | 193,207,130 | 90.1× | +98.6% |

看**每字符成本**：n 翻倍时 pike 基本不变（−11.1%、−6.4%），naive 近乎翻倍
⇒ naive 的绝对代价是 **O(n²)**，pike 保持线性。到 n=400 时 naive 已是 pike 的 **90 倍**。
这是「策略合规匹配」这一场景下的首个消融证据（论文 §7.2）。

**这是个攻击面**：输入长度由外部决定（agent 回复、拼接会话），对手只要把回复写长，
朴素实现的成本就二次增长。
两个匹配器的**语义等价**由 `tests/test_ablation.py` 保证 —— 否则这个对比没有意义。

> 口径变更（2026-09-12）：本表上一版（24.5× / 49.4× / 99.1×）是在**旧的电路构建**上量的；
> 周期数矩阵重跑时（§3.1）发现旧构建与当前 ELF 不可比，故用固定的
> `bench/bench_ablation.py` 重新量了一次。趋势一致，绝对值不同。

### 3.3 真实证明成本与**证明侧天花板**（`bench/results/proofs.md`）

P2-12 把这一节从「三个点」扩成「一条边界」：不只量**能证的多大**，也量**从哪儿开始证不出来**。
采样点与 §3.1 的周期表共用同一份语料（`demo`，372 字符），每点**独立子进程**，OOM 如实记进表里。

| length | rules | time (s) | proof (KiB) | peak RSS (MiB) | verified | 结论 |
|---:|---:|---:|---:|---:|:--|:--|
| 200 | 1 | 123.46 | 2716.4 | 10389.4 | yes | ✓ |
| 200 | 2 | 118.89 | 2716.9 | 10438.4 | yes | ✓ |
| 2,000 | 1 | 138.11 | 2718.6 | 10448.7 | yes | ✓ |
| 10,000 | 1 | 172.50 | 2726.6 | 10506.4 | yes | ✓ |
| 200 | 3 | 87.2 | — | — | — | ✗ OOM |
| 20,000 | 1 | 87.69 | — | — | — | ✗ OOM |

**这一节最该读出来的一句：证明侧与周期侧的天花板不在同一个地方。**

- **固定地板 ~10.15 GiB**：200 字符 × 1 条规则这种最小配置就已经 10,389 MB。
  这层开销与 trace 几乎无关，是 prover 本身（`core` 证明的 trace/permutation 结构）。
  成功的四个点全落在 10,389–10,506 MB 这条带里 —— **加长度、加规则数在内存上的
  边际都很小，但缝太窄**。
- **两级台阶**（不是斜线）：1 条规则 ≤10k 字符可证；2 条规则约 200 字符可证；
  **3 条及以上出不来**。第 3 条规则恰好是 `pattern_block` —— 正则匹配激活另一族
  AIR chip，trace area 一次性抬高一截，所以规则数在 **2→3 之间断崖**；长度则在
  **10k→20k 之间断崖**。
- **卡的是内存不是 CPU**：周期表能扫到 100k 字符 × 6 条规则，因为那只跑执行不出证；
  100k 字符时周期数也才千万级，CPU 完全跑得动。

时间仍由**证明器固定开销主导**（~120–170 s 量级），证明工件稳定在 ~2.7 MiB，
与长度/规则数几乎无关（2716.4 → 2726.6 KiB）。这就是「复现需要 ≥12 GB 内存」的来源，
也是 `cross_validate.py` 必须 `--chunk` 分进程的原因（§5）。

> **可复现性口径**：墙的位置可复现（`(200,3)` 与 `(20000,1)` 各失败两次），
> **墙上的耗时不可复现**（同一组点单跑复核，时间有 ±10% 抖动，内存只有 ±1%）。
> 引用时间时给量级，不要给到小数位。

> **口径绑定（2026-09-12 起）**：上表是 **12 GB / 24 核本机 + SP1 `core`** 的表，
> 两条轴都随机器走 —— 耗时随 CPU 核数与型号，可行域随内存。所以 `bench_proofs.py`
> 现在把**核数 / CPU 型号 / 内存 / hostname** 与 `proof_mode` 一并写进 `proofs.json`、
> 并在 `proofs.md` 顶部打印；换机器（如待办 T1 的云机）重跑时**另存
> `proofs-cloud*.json` 并列呈现，不要覆盖本机这张表**。本机够不着的那半张矩阵
> （20k/50k/100k × 1/2/3/6）就是挂在 T1 租机窗口里做的 —— 它不是 T1 的阻塞项，
> 命令与跨机口径见 [`../reproduce.md`](../reproduce.md) §4½、排期见
> [`../plan-p0p1p2.md`](../plan-p0p1p2.md) §9 待办 T1。

### 3.4 验证成本（`bench/results/verify.md`）

| proof | cold CLI (s) | vkey setup (s) | pure verify (ms) |
|---|---:|---:|---:|
| `bench/work/proof.bin` | 22.799 | 1.616 | 89.84 |

- **cold CLI** 包含构造 SP1 证明器客户端（重）—— 这是实现细节造成的，不是密码学成本；
- **pure verify** 是「vkey setup 一次 + N 次验证」，即 ~90 ms。

`pop-verify`（`05` §5）正是为了消掉 cold CLI 里的证明器构造而存在的：它只依赖 `sp1-verifier`。
`bench/results/verify.md` 里那句 “A verifier-only path … is future work” 是**写入时的状态**，
现已实现（`circuits/verifier`、`policydsl/verifier.py`）；重跑该 benchmark 可更新这一行。

### 3.5 语义规则（ezkl）的出证代价（`bench/results/semantic.md`）

P2-9 的语义规则走**另一套证明系统**（ezkl / halo2），代价必须单独测
（`bench/bench_semantic.py`，每个阶段**分进程**跑 —— 见下）：

| 阶段 | 耗时 | 峰值常驻 | 频次 |
|---|---:|---|---|
| setup | 48.2 s | 4.76 GiB | 每策略一次 |
| prove | 76.6 s（3 次中位） | 8.72 GiB，proof 40 KiB | **每条响应** |
| verify | 1.0 s | — | 每条响应 |

三个结论（也写进了 [`../design-semantic-rules.md`](../design-semantic-rules.md) §8）：

1. **`prove` 的成本落在在线路径上**：每条响应 77 s。这把语义规则定位成**离线审计/
   批量核查**的能力，不是实时护栏 —— 实时护栏仍需轻量的确定性规则。
2. **峰值 ~9 GiB**：`setup` 与 `prove` 必须**分进程**跑，否则两段峰值叠加会在
   12 GB 机器上 OOM。`bench_semantic.py` 的 `_run_phase` 就是为此存在的。
3. **入不入库**：`vk.ezkl`（802 KiB）**必须入库** —— 它是验证方唯一的凭据；
   `pk.ezkl`（2.92 GiB）与 `kzg.srs`（32 MiB）不入库（可重算）；`proof.json`（40 KiB）
   **也不入库** —— 它是**每条响应一份**的产物，随证书归档，入库的只是它的 sha256
   （写在证书的 `semantic.companions[].proof_sha256` 里）。

### 3.6 组合证明（P1-6）的成本（`bench/results/compose.md`）

组合义务 `Compose = (推理完整性 ∧ 策略合规)` 要**两份**证明，来自**两个 guest**
（不同 vkey ⇒ 键分离）。`bench/bench_compose.py` 把两半分开测（各起独立进程），
再测一次合成 + 联合验证：

| 子证明 | 程序 | zkVM 周期数 | prove | 峰值常驻 | 证明体积 | verify |
|---|---|---:|---:|---:|---:|---:|
| 策略合规 | `pop-program` | 643,610 | 127.3 s | 10.2 GiB | 2.72 MiB | 29.6 s |
| 推理完整性（代理 MLP） | `pop-infer` | 83,492 | 110.8 s | 10.0 GiB | 2.72 MiB | 34.2 s |

组合层本身是**毫秒级**（合成 5.0 ms，纯哈希/绑定比对），联合验证 53.8 s ——
主导项是两次 vkey setup，不是比对。出证顺序跑合计 238.1 s。

**两半都必须分进程**：峰值内存**不相加**（取 max ≈ 10.2 GiB）；同一进程里连出两份
会叠加到 ≈ 20 GiB 被 OOM-kill。这是组合在资源上唯一不需要加法的部分。

**计划里那句假设要如实分开看**（`compose.md` 里逐条报）：

1. **「组合成本 ≈ 两者之和」——成立**。合成与联合验证不引入额外证明。
2. **「由推理证明主导」——本机不成立**。代理模型是 16→32→4 的定点 MLP，
   周期数（8.3 万）**低于**策略那一半（64.4 万），两半都被 zkVM 的固定开销
   （setup 与证明器启动）主导。比值 0.87×，看不出成本结构。

> **所以这份实验验证的是组合机制，不是成本结构。** 代理推理证明与真实 zkAgent
> 推理证明的规模差若干个数量级（§3.6 的下一节）；换上真 prover 后「推理主导」才
> 可能成立，而那时的组合层代价仍由**同一个** `policydsl/compose.py` 承担 ——
> 毫秒级，不随子证明规模变化。

⚠️ 表里两半的 `verify` 都含**从 ELF 重推 vkey** 的 setup；验证方缓存了 vkey 就只付
一次验证器启动。改措辞想重出这份 `.md` 时用 `--render-only`（从已有 JSON 重渲染，
不再花几分钟出证）。

### 3.7 对标 zkAgent

详见 [`bench/comparison_zkagent.md`](../../bench/comparison_zkagent.md) 与论文 §7.4。
一句结论：二者**证明义务不同**（推理完整性 vs 策略合规），**不可宣称「PoP 更快」**；
正确表述是「在不涉模型的前提下，以同量级证明时间、低一个数量级的硬件、与 LogUp 相当的证明规模
完成，并补上没有的内容隐私」。

---

## 4. 不变量与边界

1. **结果文件入库**：`bench/results/*.{json,md}` 是**提交进仓库**的（供论文/文档引用），
   中间产物 `bench/work/` 被 gitignore。
2. **重跑要声明环境**：内存、CPU 核数、`SP1_PROVER` 取值都会显著影响数字；
   对比时务必确认是同一档配置（本机：24 核 / 12 GB）。
3. **naive 只在小长度上测**：这不是遗漏，是刻意的（zkVM 内 O(n²) 会失控）。
4. **测试不得依赖网络**：所有网络相关行为都要有离线回退，否则 CI 会红。
5. **测试不得依赖 SP1 证明**（除非显式声明）：默认路径是 `--check`；真实证明用例要
   `skipUnless` 二进制存在。
6. **`tests/mcp_echo_server.py` 的 `@tool` docstring 不翻译**：它会被发给模型，属于功能字符串。

---

## 5. 扩展指引

- **加测试**：优先补「负例」——正向检查容易写成恒真，反例才有价值（参考 `TestMaskCoverage`、
  `TestAnvilEndToEnd` 的反例对照）。
- **加评测点**：改 `bench_cycles.py` 的 `lengths` / `rule_counts`；`bench_proofs.py` 的采样点
  要克制（每点 ~2 分钟 + 10 GB 内存）。
- **更新论文数字**：跑完 `bench_*.py` 后，`README.md`、`paper/proof-of-policy.md` §7、
  `docs/reproduce.md` 的验收判据里都有硬编码的数字，需要一并核对。
  当前验收判据是 **581 passed / 15 skip**（2026-09-13 复跑；CI 上更多 skip，见 §1）、
  `cross_validate` **`RESULT: host 19/19  prove 19/19  PASS`**（2026-09-12 整批重跑，见下）。
- **`cross_validate` 的 prove 侧怎么跑**：19 条向量各出一份真 core 证明，**必须**按
  `--chunk`（默认 4，实测 `--chunk 2` 更稳）切到**独立子进程**里跑 —— SP1 证明器的内存在同一进程内
  **逐份累积**，一口气跑完 19 条会被 OOM 杀掉（本机 12 GB，单份峰值 ~10.3 GB；
  第一次整批重跑就是这么死的：`died with <Signals.SIGKILL: 9>`）。按 2 条/进程切分后
  峰值回到单份水平，全程约 **45 分钟**（≈2.1 分钟/证明）。**别把 `--no-prove` 的末行当出证结论** ——
  它现在会显式打印 `prove SKIPPED (--no-prove)`。另：**证明期间不要并行跑任何重活**
  （整轮测试、另一个出证任务），内存余量只够一件事。

---

**相关**：各板块覆盖了什么 → [`01`](01-policy-dsl.md)～[`07`](07-cli-scripts.md) 各文档的「测试对应」小节；
跑起来 → [`../reproduce.md`](../reproduce.md)。
