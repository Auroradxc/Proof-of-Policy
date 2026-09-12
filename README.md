# zk-policy · Proof-of-Policy (PoP)

为 LLM agent 响应提供**策略零知识证明**：证明「响应 `T` 满足公开策略 `π`」而**不暴露违规内容**（违规只以证据承诺披露），
无 TEE、可链上验证，支持公开（透明）与私有（选择性披露）两种模式。

> **隐私口径（P0-4 核查后收紧，2026-09-11）**：本系统的「零知识」指**策略零知识** ——
> 合规性可被证明、违规内容不泄露。**响应内容隐藏有明确上界**：私有模式保证「公开值不含明文」，
> 但公开的响应承诺可被离线枚举猜测-验证（且 SP1 的 `core`/`compressed` 证明本身并非零知识）。
> 完整核查与建议见 [`docs/sp1-zk-audit.md`](docs/sp1-zk-audit.md)。

> 独立方向，与既有 SP1+ezkl 私有面部认证项目无关；SP1 仅作为通用证明基础设施。

## 为什么值得做（30 秒版）

现有方案要么靠 TEE 只证明「护栏执行过」不证明「合规」（Proof-of-Guardrail），要么只有 2 类策略且闭源（WITNESS），要么是单条正则积木（zk-regex）。**通用策略 DSL → ZK 约束编译 + 无硬件信任 + 双隐私模式 + 形式化安全模型**的组合目前无人系统化。本项目填补该空位。

## 双层架构

> **这张图画的是「证明层栈」，不是「一次 demo 能走完的路」。** 项目实际有 8 条端到端
> 支路，`demo_e2e.py` 只覆盖其中的「公开模式主干」；其余每条有自己的驱动。下图每格右侧
> 标了**对应驱动**与**是否在主 demo 里**，完整的 8 条见紧跟其后的表 —— 或者直接跑
> `bash scripts/demo_all.sh` 把 8 条一次跑完并汇总成一份报告。

```
┌───────────────────────── Python（链下，作者/编译/参考评估）─────────────────────────┐         ← 8 条支路共同的编译/参考层
│  policy_packs/*.json  ──►  policydsl.compile()  ──►  ConstraintSpec (JSON, 链上契约)   │
│                                    │                     │                            │
│  response ──►  policydsl.evaluate()──► 参考判定（golden） ◄── 用于单测与交叉验证        │
└─────────────────────────────────────┼─────────────────────────────────────────────────┘
                                      ▼
┌───────────────────────── Rust + SP1（链上/链下证明）──────────────────────────────────┐       ← 支路①「公开模式主干」 `demo_e2e.py` ✅
│  circuits/program ：在 zkVM 内读 ProofRequest，判定约束，commit(passed, evidence)       │
│  circuits/script  ：证明生成 + 宿主机/链上验证                                          │
└───────────────────────────────────────────────────────────────────────────────────────┘
                                      │
┌──────────────────── ezkl / halo2（仅 P2-9 的语义规则）──────────────────────────────────┐     ← 支路③「语义规则」 `ezkl_prove.py` ⛔ 不在主 demo
│  semantic/ ：确定性导出 ONNX → scripts/ezkl_prove.py 出证                               │
│  公开值 delegated[] 登记「哪几条没被 SP1 判」；陪伴证明补上判定，验证方合取二者           │
└───────────────────────────────────────────────────────────────────────────────────────┘
                                      │
┌──────────────────── 第二个 guest（仅 P1-6 的组合证明）─────────────────────────────────┐      ← 支路④「组合证明」 `compose_proof.py` ⛔ 不在主 demo
│  circuits/infer-program（pop-infer）：代理推理前向，vkey_infer                          │
│  与策略半（pop-program，vkey_policy）**必须不同程序**（键分离）→ 合取成一张组合证书       │
│  Compose = (推理完整性 ∧ 策略合规)；驱动 scripts/compose_proof.py                       │
└───────────────────────────────────────────────────────────────────────────────────────┘
                                      │
┌──────────────────── 第三个 guest（仅 P2-10 的跨证书一致性）─────────────────────────────┐     ← 支路⑤「会话聚合」 `prove_session.py` ⛔ 不在主 demo
│  circuits/session-program（pop-session）：把**一组**证书聚合成一次证明，vkey_session      │
│  证①policy_hash 全同 ②流式链无缝无缺口 ③覆盖完整轨迹；Merkle 根承诺整组                  │
│  驱动 scripts/prove_session.py；⚠️ 尾截断只有「根比对」拦得住，见 L8                      │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

**ConstraintSpec**（`policydsl/compile.py` 产出）是两层之间的唯一契约，结构见 `docs/architecture.md`。

### 8 条端到端支路（上图哪一格 = 哪个驱动 = 在哪跑）

| # | 支路 | 驱动 | 在 `demo_e2e` | 前置 |
|---|---|---|---|---|
| ① | **公开模式主干**：流式(含早停) + MCP 工具 + 真 SP1 证明 + 挑战绑定 + **公私对比** + 账本 | `scripts/demo_e2e.py` | ✅ 就是它 | — |
| ② | **私有模式**：响应承诺 + 逐违规证据承诺 + 脱敏证明 + 证据开示 | `scripts/private_demo.py` | 🔶 部分（① 里已含「同一条 T 两种模式」的并排对比与证据开示；②里的六个专项实验仍只在 `private_demo.py`） | — |
| ③ | **语义规则**（P2-9）：ezkl 陪伴证明，验证方与 SP1 结论**合取** | `scripts/ezkl_prove.py` | ⛔ | ezkl + `semantic/artifacts/` |
| ④ | **组合证明**（P1-6）：策略半 ∧ 推理半，两个 vkey | `scripts/compose_proof.py` | ⛔ | — |
| ⑤ | **会话聚合**（P2-10）：一组证书的 Merkle 根 + 三条义务 | `scripts/prove_session.py` | ⛔ | ① 的 `session.json` |
| ⑥ | **多证明者**（P2-11）：按规则类切三段，各角色自证自签 | `scripts/prove_multiparty.py` | ⛔ | — |
| ⑦ | **链上锚定**（P7-c）：起 anvil → 部署 `Anchor.sol` → 摘要上链 | `scripts/anchor_e2e.sh` | ⛔（可选步骤） | foundry |
| ⑧ | **第三方独立验证**：只用公开产物复算全部结论（闭环） | `scripts/verify_session.py` | ✅ 主 demo 末尾会提示这条 | ① 的产物 |

```bash
bash scripts/demo_all.sh            # 8 条依次跑一遍 + 合并报告（fast：宿主校验，约半分钟）
bash scripts/demo_all.sh --prove    # 出真证明（每条数分钟、峰值 ~10 GB，本机实测 26–27 分钟）
bash scripts/demo_all.sh --list     # 只列支路
```

> **跑完最该记住的三件事**（`demo_all.sh` 每次都会把它从产物/源码里**现推**出来打印，
> 所以它们不会随文档更新而漂移）：① 链上只锚定**证书摘要**，合约里没有 `anchorWithProof`
> —— 「链上可验证」目前是过度声明（见 `docs/plan-p0p1p2.md` §P1-7）；② 流式路径的「LLM」
> **缺省**是 LangChain 的 `GenericFakeChatModel`（终端会如实打出 `llm model : fake (offline)`）；
> `--model openai:<model>` 可换成真实模型，始终真实的是 **callback 管线**而不是模型；
> ③ 组合证明里的「推理」是 **stand-in**（确定性 MLP 前向），验收的是组合机制而非推理本身。

## 快速开始（无需 Rust）

```bash
# 1) 参考评估：响应是否满足策略？（响应在前，--policy 指定策略包）
python3 -m policydsl check scripts/examples/eu_agent_reply.txt --policy policy_packs/eu_ai_act_v1.json

# 2) 编译策略包 → ConstraintSpec（W4 之后交给 SP1 prover）
python -m policydsl compile policy_packs/eu_ai_act_v1.json

# 3) 运行单测
python -m unittest discover tests -v
```

## 端到端 demo（一键跑）

> **想一次看全 8 条支路**：`bash scripts/demo_all.sh`（把每条支路依次跑一遍并汇总成
> `REPORT.md`，标出哪条跑了 / 哪条为什么跳过 / 耗时与峰值内存）。下面这一节只讲**主干**
> 那一条（支路①）。

真实 agent 会话（LangChain 流式 + 真实 MCP 工具）→ 证书（含流式证书链/早停、工具参数与响应侧）→ 锚定账本 →（可选）真实 SP1 证明 → **第三方独立验证**。

```bash
# 1) 跑一次会话（含真实 SP1 证明；加 --no-prove 可只做 host 校验，秒级）
SP1_PROVER=cpu python3 scripts/demo_e2e.py [--no-prove]

# 2) 第三方独立验证（只用公开产物：session.json + ledger + proof）
python3 scripts/verify_session.py --session scripts/examples/out/e2e/session.json
#   → ledger_chain / certificates_signature / policy_hash / certificates_response_binding / anchored / stream_chains / zk_proof 全 PASS

# 3) 生成演示报告与截图（HTML/SVG/PNG）
python3 scripts/make_shots.py --run-demo
#   → docs/demo/session_report.html · session_report.svg · session_summary.png · verify_result.png
```

### 公私模式对比（就在上面的主 demo 里，第 4 步）

同一条响应、同一条策略、同一个 `nonce`，公开模式与私有模式**各出一张证书**，
然后把「验证方在这两张证书里分别看得见什么」**现读**出来并排打印
（`--no-contrast` 可跳过）：

```text
[PASS] 对比前提 同一 T · 同一策略：policy_hash 相同=True passed 相同=True（=False）
     验证方能看到           公开模式                                                   私有模式
     结论 passed            False                                                      False
     策略指纹 policy_hash   ffb2722e19d886c6…                                          ffb2722e19d886c6…
     命中了哪几条规则       no_bad_topics no_secret                                    no_bad_topics no_secret
     每条规则的证据         no_bad_topics「exploit」, no_secret「sk-[A-Za-z0-9]{16,}」 no_bad_topics 04da09655d48e492…, no_secret 71a60a1657d3fe25…
     响应本身的承诺         —（该模式不承诺 T）                                        28df5e47336a061b…
     脱敏见证               —                                                          mask_count=29 mask_covered=True
[PASS] 选择性开示 开示件自洽=True 与证明里的承诺逐条相符=True 篡改被拒=True
```

> **这一步默认只做宿主校验（两张证书都标 `unproven`），不是省时间而是证不了**：
> 本 demo 的 `agent_content_v1`（3 条规则、含 `pattern_block`）**公开模式能出证、
> 私有模式不能** —— 在本机 11.9 GB 上实测被内核 OOM-kill（`anon-rss` 10.391 GiB，
> 而本机可用天花板约 10.385 GiB；对照 `private_demo.py` 那条更小的策略峰值
> 10.383 GiB 能过）。私有模式的**真证明**由支路② `private_demo.py` 承担。
> ≥16 GB 的机器可以加 `--contrast-prove` 让对比也出真证明。

三件要读对的事：

- **策略指纹与结论必须相同** —— 同一个 T、同一条策略，所以两张证书的 `policy_hash`
  与 `passed` 一致；脚本自己断言这一点（上面那行 `[PASS] 对比前提`），不一致就是 FAIL。
  差别**只在验证方看得见什么**，不在判定结果。
- **公开模式把命中的那个词逐字写进证书**（`no_bad_topics「exploit」`，连密钥正则
  `sk-[A-Za-z0-9]{16,}` 也照抄）—— 这就是私有模式要解决的问题。私有模式同一位置只有
  `evidence_commitment`，外加响应承诺与脱敏见证。
- **私有模式不是「涂黑」** —— 它的出口是**证据选择性开示**：`commit.evidence_bundle`
  开示一件证据时，该件必须与证书里那条承诺**逐条相符**，篡改一件即被拒。公开模式
  没有这一步，因为证据本来就是明文。

这两张证书也写进 `session.json`（`kind` 同为 `"zk"`），所以下面第 2 步的第三方验证会
**连同它们一起验**，对比演示不额外开一条验证旁路。

> ⚠️ 对比表里 `passed=False` 是**故意**的：对比用的是会同时触发关键词规则与密钥规则的
> 违规响应 —— 有违规才看得出两种模式的差别。主 demo 那条 `zk` 证书用的仍是干净响应
> （`passed=True`）。

### 链上锚定（可选，真跑本地 Anvil，一键）

```bash
bash scripts/retry_install_foundry.sh   # 装 foundry（anvil/cast）；已装则秒退
bash scripts/anchor_e2e.sh              # 起 anvil → 部署 Anchor.sol → 13 张证书摘要上链 → 第三方 --rpc 核对
SP1_PROVER=cpu bash scripts/anchor_e2e.sh --prove   # 附真实 Core 证明（本机实测 3:10 / 峰值 10.2 GiB）
#   → [PASS] chain_anchored 14/14 digests on chain … (14 cross-checked) + 反例对照 anchoredAt=0
```

- 📚 **分板块模块文档（按功能读代码的入口）**：**`docs/modules/`** —— 总览 [`README.md`](docs/modules/README.md)，
  以及 01 策略 DSL / 02 隐私与承诺 / 03 合规证书 / 04 锚定与审计 / 05 ZK 电路 / 06 框架集成 / 07 CLI 与脚本 / 08 测试与评测
- 📄 端到端复现指南（环境 → 一次合规证明 → 验证）：**`docs/reproduce.md`**
- 🖼 演示报告（截图）：`docs/demo/session_report.html`、`docs/demo/session_summary.png`、`docs/demo/verify_result.png`
- 📘 分阶段代码计划：`docs/dev-plan.md` · P7 收尾计划：`docs/plan-p7.md` · 安全模型：`docs/security-model.md` · 信任-成本四象限：`docs/quadrant.md`
- 🔗 **轨迹绑定（P1-5）**：工具轨迹不再是 agent 自报的 `tool_calls`，而是**工具网关**签发的**回执链**（`policydsl/trace.py` + `pop-types::verify_receipt_chain`）。链**结构**由电路保证（删/换/重排 → `trace_unbound` fail-closed），**签发者身份**由链下 Ed25519 验签 + 公开值 `trace_root` 承担；`budget_bound(tokens)` 改为电路内自算。**截尾**（整条删掉链尾那条违规回执）由网关的**会话末端承诺** `trace_seal{count, trace_root, ts, keyid, sig}` 拦（P1-5b，载荷**顶层**，不在 `outcome` 里——`outcome` 是证明公开值的镜像）；验证方**须给 `--gateway-key`** 才核得了签名。验收见 `tests/test_trace.py`（39 例：四条验收 + `verify_cert.py --receipts` 的第三方核对 + seal 本身 + 截尾三路）；边界如实标注于 `docs/security-model.md` §5
- 🧠 **语义规则（P2-9）**：第七类规则 `semantic_bound`（“回复的有害概率不得高于阈值”这类**学不出来形式证明**的规则）**不在 SP1 里判定** —— 电路只把「这条被委托了」登记进公开值 `delegated[]`，出证方附一条 **ezkl/halo2 陪伴证明**（`policydsl/semantic.py` + `semantic/` + `scripts/ezkl_prove.py`）。验证方必须**合取**二者，并核 `{system, model_vkey, onnx_sha256, threshold_bp, direction}` 逐字段相等 + 公开实例的输入 == 由送达的 `T′` 现场重算的 `encode(T′)`。⚠️ 三条硬边界：**`passed=true` 而 `delegated` 非空的证明不等于策略被满足**（`verify_cert.py` 因此打印**两行**：`RESULT:` 说证书真不真，`合规:` 说策略满足没满足）；**语义规则只支持公开模式**（`encode` 在词表上单射，公开实例可反查原文，私有模式直接 panic）；**随包模型是演示用小模型**，不构成语义安全保证。见 [`docs/design-semantic-rules.md`](docs/design-semantic-rules.md)（引理 L7）
- 🔗 **组合证明（P1-6）**：`Compose = (推理完整性 ∧ 策略合规)` —— 两份证明合成一张组合证书，回答「**这条 `T` 是被那个模型算出来的吗**」这个策略合规本身不覆盖的问题（`policydsl/compose.py` + `scripts/compose_proof.py`）。**键分离**是前提：两半必须来自**不同程序**（`pop-program` 判策略、`pop-infer` 证推理，两个 guest 入口各断言一次自己的域），否则「这份证明属于哪一半」无从判断。⚠️ 推理半当前是**代理**（确定性定点 MLP，权重由编译期种子生成 ⇒ 被 vkey 承诺），**不是 zkAgent**（其源码不可得，D1）；`bench/results/compose.md` 如实报告「组合成本 ≈ 两者之和**成立**、由推理证明主导**在代理规模下不成立**」。见 `docs/security-model.md` 引理 L6
- 🧾 **跨证书一致性（P2-10）**：`session` 域（第三个 guest `pop-session`，vkey 与另两域不同）把**一个 run 的流式证书**用 Merkle 根聚合成**一次**证明，证三件事：①所有证书 `policy_hash` 全同 ②流式链无缝拼接无缺口 ③覆盖完整轨迹（链尾带网关的会话末端承诺）。驱动 `scripts/prove_session.py`（`policydsl/session.py` 是纯 Python 参考实现，两端逐字段对拍）。⚠️ 三条硬边界：**电路不验网关签名**（zkVM 里没有网关公钥，「这条链网关真的签过」由链下 `trace.verify_seal` 判，不给 keyring 时会如实注明「签名未验」）；**尾截断只有 Merkle 根拦得住** （`[0..k]` 前缀的 `index`/`prev` 依然连续，电路本身接受一个被砍了尾巴的证书集 —— 拦下它的是「承诺的根 vs 由交付证书重算的根」这一步）；`ok`（聚合是真的）与 `satisfied`（覆盖的证书都 `passed`）必须**分开读**。见 `docs/security-model.md` 引理 L8
- 🔐 **SP1 健全性与零知识性核查（P0-4）**：`docs/sp1-zk-audit.md` —— 健全性成立；**`core`/`compressed` 证明非零知识**（Succinct 官方安全模型明文 + 本机源码审计，两类独立证据）。私有模式因此只能宣称「公开值不泄露明文」，不能宣称「`T` 不可恢复」
- 🔎 审计路径（verifier-only，免构造证明器）：`circuits/verifier`（bin `pop-verify`）+ `pop-script --proof-mode compressed`；见 `docs/reproduce.md` §11
- ⛓ 链上锚定（真跑本地 Anvil）：`contracts/Anchor.sol` + `bash scripts/anchor_e2e.sh`（部署 → 每张证书摘要上链 → 第三方 `verify_session --rpc` 核对 + 反例对照）；见 `docs/reproduce.md` §12
- 📝 论文初稿：**`paper/proof-of-policy.tex`（权威源，`xelatex` 编译）**；`paper/proof-of-policy.md` 是**便于阅读的镜像**，两者不一致时以 `.tex` 为准 · 评测脚本与结果：`bench/`（`bench/results/*.md`）· EU AI Act 映射：`docs/eu-ai-act-mapping.md`

依赖（可选，安装后真实框架测试自动启用）：`pip install -r requirements-frameworks.txt`（或 `bash scripts/install_frameworks.sh`）。

## 目录结构

```
zk-policy/
├── policydsl/            # Python DSL + 参考评估 + 私密/证书/锚定 + 框架适配（langchain/langgraph/mcp）
├── policy_packs/         # 示例策略包（JSON）
├── semantic/             # P2-9：语义规则的模型与特征（确定性 ONNX 导出 + ezkl 产物）
├── circuits/             # SP1 程序与驱动（Rust，v6 workspace：types/program/infer-program/session-program/script/verifier）
├── contracts/            # Anchor.sol + 入库 artifact（Anchor.json，部署无需 solc）
├── scripts/              # 交叉验证 / demo / 证书签发与验证 / 链上锚定 / 安装脚本
├── tests/                # 单测与集成测试（unittest，stdlib + 可选框架）
├── bench/                # 评测（周期数 / 证明成本 / 验证成本；结果在 bench/results/）
├── paper/                # 论文初稿
├── docs/                 # 架构 / DSL / 复现指南 / 安全模型 / **modules/（分板块模块文档）**
└── roadmap.md            # 8 周开发映射
```

## 学习路线（0 基础研究生）

详见 **《方向2_Proof-of-Policy_8周计划_v2_零基础版.md》** —— 该文件在**仓库外的上层工作区**
`Proof-of-Policy/02_项目计划/`（不随本仓库分发），本仓库内的历史映射表见
[`roadmap.md`](roadmap.md)，当前计划见 [`docs/plan-p0p1p2.md`](docs/plan-p0p1p2.md)。

本仓库按周打标（落点按**实际交付**订正，2026-09-12）：

- **W2**：`policydsl/model.py` 的 KeywordBlock / LengthBound 规则 → `tests/`
- **W3**：PatternBlock（PII 正则）+ NFA 路径设计 → `docs/policy-dsl.md`
- **W4**：`compile.py` 产出 ConstraintSpec → 填充 `circuits/program`（PoP v0 真出证）
- **W5**：私有模式（承诺 + 违规定位）→ `policydsl/commit.py` + `pop-types::evaluate_private`
- **W6**：agent 插桩 + 合规证书 → `policydsl/agent.py` + 三个框架适配器 + `cert.py` + `scripts/demo_e2e.py`
- **W7**：评测脚本（`bench/`）+ 安全模型（`docs/security-model.md`）

## 安装 Rust + SP1（W4 前执行）

```bash
curl -L https://sp1.succinct.xyz | bash      # Windows: 见 SP1 官方文档安装脚本
cargo prove install                          # 安装 SP1 工具链与 crates
```

> 环境状态（2026-09-10）：Rust + SP1 **v6.7.0 已安装**，`circuits/` 可构建并出证；
> `policydsl/` 与 demo 可直接运行。工具链与网络对策见 `docs/dev-plan.md`。
