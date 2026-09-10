# zk-policy · Proof-of-Policy (PoP)

为 LLM agent 响应提供**零知识合规证明**：证明「响应 `T` 满足公开策略 `π`」，无 TEE、可链上验证，支持公开（透明）与私有（选择性披露）两种模式。

> 独立方向，与既有 SP1+ezkl 私有面部认证项目无关；SP1 仅作为通用证明基础设施。

## 为什么值得做（30 秒版）

现有方案要么靠 TEE 只证明「护栏执行过」不证明「合规」（Proof-of-Guardrail），要么只有 2 类策略且闭源（WITNESS），要么是单条正则积木（zk-regex）。**通用策略 DSL → ZK 约束编译 + 无硬件信任 + 双隐私模式 + 形式化安全模型**的组合目前无人系统化。本项目填补该空位。

## 双层架构

```
┌───────────────────────── Python（链下，作者/编译/参考评估）─────────────────────────┐
│  policy_packs/*.json  ──►  policydsl.compile()  ──►  ConstraintSpec (JSON, 链上契约)   │
│                                    │                     │                            │
│  response ──►  policydsl.evaluate()──► 参考判定（golden） ◄── 用于单测与交叉验证        │
└─────────────────────────────────────┼─────────────────────────────────────────────────┘
                                      ▼
┌───────────────────────── Rust + SP1（链上/链下证明）──────────────────────────────────┐
│  circuits/program ：在 zkVM 内读 ProofRequest，判定约束，commit(passed, evidence)       │
│  circuits/script  ：证明生成 + 宿主机/链上验证                                          │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

**ConstraintSpec**（`policydsl/compile.py` 产出）是两层之间的唯一契约，结构见 `docs/architecture.md`。

## 快速开始（无需 Rust）

```bash
# 1) 参考评估：响应是否满足策略？
python -m policydsl check policy_packs/eu_ai_act_v1.json example_response.txt

# 2) 编译策略包 → ConstraintSpec（W4 之后交给 SP1 prover）
python -m policydsl compile policy_packs/eu_ai_act_v1.json

# 3) 运行单测
python -m unittest discover tests -v
```

## 端到端 demo（一键跑）

真实 agent 会话（LangChain 流式 + 真实 MCP 工具）→ 证书（含流式证书链/早停、工具参数与响应侧）→ 锚定账本 →（可选）真实 SP1 证明 → **第三方独立验证**。

```bash
# 1) 跑一次会话（含真实 SP1 证明；加 --no-prove 可只做 host 校验，秒级）
SP1_PROVER=cpu python3 scripts/demo_e2e.py [--no-prove]

# 2) 第三方独立验证（只用公开产物：session.json + ledger + proof）
python3 scripts/verify_session.py --session scripts/examples/out/e2e/session.json
#   → ledger_chain / certificates_signature / policy_hash / anchored / stream_chains / zk_proof 全 PASS

# 3) 生成演示报告与截图（HTML/SVG/PNG）
python3 scripts/make_shots.py --run-demo
#   → docs/demo/session_report.html · session_report.svg · session_summary.png · verify_result.png
```

- 📄 端到端复现指南（环境 → 一次合规证明 → 验证）：**`docs/reproduce.md`**
- 🖼 演示报告（截图）：`docs/demo/session_report.html`、`docs/demo/session_summary.png`、`docs/demo/verify_result.png`
- 📘 分阶段代码计划：`docs/dev-plan.md` · P7 收尾计划：`docs/plan-p7.md` · 安全模型：`docs/security-model.md` · 信任-成本四象限：`docs/quadrant.md`
- 🔎 审计路径（verifier-only，免构造证明器）：`circuits/verifier`（bin `pop-verify`）+ `pop-script --proof-mode compressed`；见 `docs/reproduce.md` §9
- 📝 论文初稿：`paper/proof-of-policy.md` · 评测脚本与结果：`bench/`（`bench/results/*.md`）· EU AI Act 映射：`docs/eu-ai-act-mapping.md`

依赖（可选，安装后真实框架测试自动启用）：`pip install -r requirements-frameworks.txt`（或 `bash scripts/install_frameworks.sh`）。

## 目录结构

```
zk-policy/
├── policydsl/            # Python DSL + 参考评估 + 私密/证书/锚定 + 框架适配（langchain/langgraph/mcp）
├── policy_packs/         # 示例策略包（JSON）
├── circuits/             # SP1 程序与驱动（Rust，v6 workspace）
├── scripts/              # 交叉验证 / demo / 证书签发与验证 / 安装脚本
├── tests/                # 单测与集成测试（unittest，stdlib + 可选框架）
├── docs/                 # 架构 / DSL / 开发计划 / EU AI Act 映射
└── roadmap.md            # 8 周开发映射
```

## 学习路线（0 基础研究生）

详见 `../方向2_Proof-of-Policy_8周计划_v2_零基础版.md`。本仓库按周打标：
- **W2**：`policydsl/model.py` 的 KeywordBlock / LengthBound 规则 → `tests/`
- **W3**：PatternBlock（PII 正则）+ NFA 路径设计 → `docs/policy-dsl.md`
- **W4**：`compile.py` 产出 ConstraintSpec → 填充 `circuits/program`（需先装 Rust+SP1）
- **W5**：私有模式（承诺 + 违规定位）
- **W6**：`demo/` agent 插桩 + 合规证书
- **W7**：评测脚本 + 安全模型

## 安装 Rust + SP1（W4 前执行）

```bash
curl -L https://sp1.succinct.xyz | bash      # Windows: 见 SP1 官方文档安装脚本
cargo prove install                          # 安装 SP1 工具链与 crates
```

> 环境状态（2026-09-10）：Rust + SP1 **v6.7.0 已安装**，`circuits/` 可构建并出证；
> `policydsl/` 与 demo 可直接运行。工具链与网络对策见 `docs/dev-plan.md`。
