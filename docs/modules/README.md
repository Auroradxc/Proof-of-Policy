# 模块文档总览

> 本目录按**功能板块**拆解 zk-policy 的实现：每个板块一份文档，包含
> 「职责 / 文件清单 / 关键数据结构 / 函数级 API / 不变量与边界 / 测试对应 / 扩展指引」。
> 与既有文档的分工：`docs/architecture.md` 讲**分层与契约**（一页纸），
> 本目录讲**代码怎么落地**；`docs/security-model.md` 讲**安全论证**；
> `docs/reproduce.md` 讲**怎么跑起来**。

---

## 1. 一句话理解这个项目

zk-policy（Proof-of-Policy，PoP）证明的是：
**「某条 agent 响应 `T` 满足某个公开策略 `π`」**，且不需要 TEE/硬件信任。
为此它把「策略」编译成**可序列化的约束契约**，让 **Python 参考层**与 **SP1 zkVM 内的 Rust 程序**
消费同一份契约、得出同一个判定，再把这个判定包成**可签名、可锚定、可第三方核验的证书**。

三个关键设计决定了全仓库的形状：

1. **唯一跨层契约 `ConstraintSpec`** —— 编译产物是 JSON，两侧都解释它（见 `02`）。
2. **参考实现 (golden) 与电路实现成对存在** —— 每个规则类型都有 Python 版与 Rust 版，
   并由 `scripts/cross_validate.py` 交叉验证逐向量一致（见 `01`/`05`）。
3. **证书只绑定「哈希」** —— 策略哈希、vkey 哈希、证明哈希、证书摘要；验证方全部**重算**（见 `03`/`04`）。

---

## 2. 仓库布局

```
zk-policy/
├── policydsl/                # Python 参考层（仅标准库；框架适配除外）
│   ├── model.py              #   领域模型：Rule / Policy / Violation / CheckResult / Transcript
│   ├── compile.py            #   Policy → ConstraintSpec（含 sha256 绑定哈希）
│   ├── evaluate.py           #   「golden」参考判定器（对应电路内 pop-types::evaluate）
│   ├── serialize.py          #   ConstraintSpec → serde 外部标签枚举 JSON
│   ├── nfa.py                #   正则子集 → 可序列化 NFA + Pike VM（唯一的正则编译器）
│   ├── pii.py                #   规范 PII 模式 + IBAN MOD-97 校验位
│   ├── commit.py             #   私有模式原语（承诺 / 选择性披露 / 可证明脱敏 / 证据开示 / 挑战-响应绑定）
│   ├── challenge.py          #   一次性挑战 nonce 的生成、编解码与重放记录
│   ├── cert.py               #   合规证书（DSSE 风格信封 + Ed25519 签名，按 keyid 前缀分发）
│   ├── keys.py               #   签名密钥：定位/读写 PKCS#8、公钥导出与 keyring 装配（P0-3）
│   ├── anchor.py             #   锚定后端：文件哈希链账本 / 链上 Anchor 合约
│   ├── trace.py              #   工具回执链：结构/验签/会话末端 seal（P1-5 / P1-5b）
│   ├── semantic.py           #   语义规则的委托与 ezkl 陪伴证明核验（P2-9 / 引理 L7）
│   ├── ezkl_evm.py           #   ezkl 的 EVM 验证器接口（事件循环包装，T2）
│   ├── infer.py              #   代理推理模型（定点 MLP）的 Python 参考实现（P1-6）
│   ├── compose.py            #   组合证明：键分离 + 8 步联合验证（P1-6 / 引理 L6）
│   ├── agent.py              #   框架无关钩子 AgentMonitor（生成路径 + 工具路径）
│   ├── verifier.py           #   verifier-only 快路径判定（core 不能走快路径）
│   ├── langchain_adapter.py  #   LangChain/LangGraph 回调（含流式证书与早停）
│   ├── langgraph_adapter.py  #   LangGraph 节点包装 / astream_events 事件认证
│   ├── mcp_adapter.py        #   MCP 工具守护（参数侧 + 结果侧 + 工具清单发现，可飞行前拦截）
│   ├── llm.py                #   --model 规格解析与真实模型构造（缺依赖/缺 key 当场说清）
│   └── __main__.py           #   CLI：compile / check
├── circuits/                 # Rust + SP1 证明层（workspace）
│   ├── types/                #   共享判定逻辑（no_std）：evaluate / evaluate_private / NFA
│   ├── program/              #   zkVM guest①（pop-program）：只收策略任务 → run_job → commit
│   ├── infer-program/        #   zkVM guest②（pop-infer）：只收推理任务（P1-6 组合证明）
│   ├── session-program/      #   zkVM guest③（pop-session）：只收会话任务（P2-10 跨证书一致性）
│   ├── script/               #   宿主驱动 pop-script：--check / --execute / 出证 / --verify
│   ├── verifier/             #   pop-verify：仅验证器二进制（无证明器状态）
│   └── patches/              #   tempfile 补丁（sp1-prover 6.7.0 依赖 TempDir::keep）
├── semantic/                 # P2-9：语义规则的模型与特征（确定性 ONNX 导出 + ezkl 产物）
├── contracts/                # Anchor.sol + 已编译 artifact（Anchor.json，免 solc 部署）
├── scripts/                  # 端到端脚本（demo / 交叉验证 / 出证 / 验证 / 安装）
├── bench/                    # 评测（周期数矩阵 / 证明成本 / 验证成本 / ezkl / 组合 / 对标）
├── tests/                    # 单测与集成测试（515 passed / 14 skip）
├── policy_packs/             # 示例策略包（EU AI Act / PII / 金融 / agent 内容与工具）
└── docs/                     # 文档（本目录为分板块模块文档）
```

---

## 3. 端到端数据流（带函数名）

```
⓪ 出题            challenge.new_nonce()
                       │  一次性挑战值；P0-2 把「被证明的 T」拴到「送达的 T′」
                       ▼
① 策略编写        policy_packs/*.json
                       │  model.Policy / model.Rule.validate
                       ▼
② 编译            compile.compile_policy(policy)
                       │    ├─ nfa.compile_pattern()      正则→NFA
                       │    └─ _canonical_hash(stable)    policy_hash
                       ▼
③ 契约            ConstraintSpec(JSON)  ←──── 唯一跨层契约
                       │
       ┌───────────────┴────────────────────────────┐
       ▼（链下 golden）                              ▼（链上证明）
④a  evaluate.check()                          ④b serialize.spec_canonical_text()
       │                                             │  → vectors.json（原始字节）
       │                                             ▼
       │                                       circuits/script (pop-script)
       │                                             │  → pop-types::run_job
       │                                             ▼
       │                                       guest: commit(Outcome) + proof
       │                                             │
       └────────── cross_validate.py 交叉验证 ────────┘
                       │
                       ▼
⑤ 证书            cert.build_payload(...) → cert.sign_payload(payload, signer)
                       │  policy_hash / vkey_hash / proof_sha256 / proof_mode / outcome
                       │  challenge{nonce, response_binding}
                       ▼
⑥ 锚定            anchor.backend_from_env(ledger, rpc, contract)
                       │    ├─ FileLedgerBackend   哈希链账本（离线可验）
                       │    └─ RpcAnchorBackend    contracts/Anchor.sol（公共时间戳）
                       ▼
⑦ 第三方核验      verify_cert.py / verify_session.py   ← 只持公开产物
```

---

## 4. 板块索引

| # | 文档 | 覆盖文件 | 一句话 |
|---|---|---|---|
| 01 | [策略 DSL 与编译](01-policy-dsl.md) | `model.py` `compile.py` `evaluate.py` `serialize.py` `pii.py` `nfa.py` `__init__.py` `__main__.py` | 把 JSON 策略变成可跨层消费的约束契约，并给出参考判定 |
| 02 | [隐私与承诺](02-privacy-commitment.md) | `commit.py` `challenge.py`（+ `nfa.py` 的区间计算） | 私有模式：承诺、选择性披露、可证明脱敏、证据开示、挑战-响应绑定 |
| 03 | [合规证书](03-certificate.md) | `cert.py` `agent.py` | 把一次判定包成可签名、可重算哈希的 DSSE 信封 |
| 04 | [锚定与审计](04-anchoring-audit.md) | `anchor.py` `contracts/` `verifier.py` | 防篡改记录：本地哈希链账本 + 链上存在性证明 |
| 05 | [ZK 电路层](05-zk-circuits.md) | `circuits/types` `program` `infer-program` `session-program` `script` `verifier` | zkVM 内重放判定并承诺结果；证明的生成与验证；**三个 guest 的键分离**（P1-6 / P2-10）（**注意四种证明模式的安全性差异**，见 [`../sp1-zk-audit.md`](../sp1-zk-audit.md)） |
| 06 | [框架集成](06-frameworks.md) | `langchain_adapter.py` `langgraph_adapter.py` `mcp_adapter.py` `llm.py` | 把两个钩子接到真实 agent 框架上（含流式、真早停、飞行前拦截与工具清单发现） |
| 07 | [CLI 与脚本](07-cli-scripts.md) | `scripts/*` | 出证、交叉验证、私密 demo、端到端会话、一键锚定 |
| 08 | [测试与评测](08-tests-bench.md) | `tests/*` `bench/*` | 515 个测试覆盖什么、评测数字怎么来的 |

三条**不在本目录**但同样属于实现层的线（各自有独立文档，故未拆成板块）：

| 线 | 文档 | 代码 | 一句话 |
|---|---|---|---|
| P2-9 语义规则（引理 L7） | [`../design-semantic-rules.md`](../design-semantic-rules.md) | `semantic.py` `ezkl_evm.py` `semantic/` `scripts/ezkl_prove.py` | 学习型规则不在 SP1 内判定，而是**委托**给 ezkl/halo2 陪伴证明，验证方必须**合取**二者 |
| P1-6 组合证明（引理 L6） | [`../security-model.md`](../security-model.md) §3 L6 | `compose.py` `infer.py` `circuits/infer-program` `scripts/compose_proof.py` | 两份证明（策略合规 ∧ 推理完整性）合成一次会话结论，前提是**键分离** |
| P2-10 跨证书一致性（引理 L8） | [`../security-model.md`](../security-model.md) §3 L8 | `session.py` `circuits/session-program` `circuits/types::run_session` `scripts/prove_session.py` | 一个 run 的流式证书用 Merkle 根聚合成一次证明；证同一策略 / 无缺口 / 覆盖完整 —— **尾截断只有根比对拦得住** |

推荐阅读路径：

- **想改策略/加规则**：01 → 05（两侧都要改）→ 08（补交叉验证用例）
- **想接自己的 agent**：06 → 03 → 04
- **想接自己的链/审计流程**：04 → 07（`anchor_e2e.sh` 是最小完整例子）
- **想懂语义规则怎么不被「证明者声明」钻空子**：`../design-semantic-rules.md`（§3 的**三个信任边界条件** + §6 的诚实边界）
- **只想复现数字**：`docs/reproduce.md` 与 08

---

## 5. 全局不变量

贯穿全部模块、改代码时必须保持的七条：

| # | 不变量 | 由什么保证 |
|---|---|---|
| I1 | **跨层判定一致**：同一 `ConstraintSpec` + 同一输入，Python golden 与 `pop-types` 结果逐字段相同 | `scripts/cross_validate.py`（**host 19/19 · prove 19/19**，2026-09-12 整批重跑；分块口径见 `08` §5）、`tests/test_rules_incircuit.py` |
| I2 | **契约哈希稳定**：语义相同 ⇒ `spec["sha256"]` 相同（键排序、紧凑分隔符、字符串排序去重小写化） | `compile._canonical_hash`、`cert.canonical` |
| I3 | **ASCII 语义**：关键词大小写折叠、NFA 的 `\w\d\s` 都只在 ASCII 上定义，避免 Python `str.lower()` 与 Rust 的差异 | `commit._ascii_lower`、`types::ascii_lower`、`nfa.py` 模块注释 |
| I4 | **不出电路就无法证明**：一个规则类型要么两侧都实现，要么**根本产不出证明**，绝不静默跳过 | `compile.py` 把未知 kind 原样写进规范字节 → guest 的 serde 解析失败即 panic（fail-closed）；`tests/test_policy_binding.TestFailsClosed` 锁死 |
| I5 | **先有事实再有记录**：链上交易成功之后才写本地账本 `meta.on_chain`，哈希链因此始终自洽 | `RpcAnchorBackend.anchor` |
| I6 | **策略绑定**：证书声称的 `policy_hash` == 由策略包现场重编译的 == **证明公开值承诺的**（三方比对，缺一不可；只有两个来源时一律判失败，防空洞） | `policydsl.verifier.check_policy_binding`；`tests/test_policy_binding.py` |
| I7 | **响应绑定**：证书 `challenge` 块声明的 `response_binding` == outcome 内嵌的 == **证明公开值承诺的** == 由**送达的响应 T′** 与 nonce 现场重算的（同样 ≥2 来源才算比对）。绑定公式含 nonce 长度前缀，`(nonce, T) → 字节串`恒为单射 | `policydsl.verifier.check_response_binding`、`commit.response_binding`（↔ `pop_types::response_binding`）；`tests/test_binding.py` |

---

## 6. 命令速查

```bash
# 只跑参考层（秒级，无需 Rust）
python3 -m unittest discover tests -v            # 515 passed / 14 skip
python3 -m policydsl compile policy_packs/eu_ai_act_v1.json
python3 -m policydsl check scripts/examples/eu_agent_reply.txt --policy policy_packs/eu_ai_act_v1.json

# 交叉验证（需要先构建 circuits，见 docs/reproduce.md §2）
SP1_PROVER=cpu python3 scripts/cross_validate.py          # host 19/19 · prove 19/19（约 45 min，分块口径见 08 §5）

# 一条命令跑通端到端（含链上锚定）
bash scripts/anchor_e2e.sh                                # 秒级，--prove 加真实证明
```

完整的复现步骤、环境要求与故障排查见 [`../reproduce.md`](../reproduce.md)。
