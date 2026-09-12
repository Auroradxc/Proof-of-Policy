# 8 周开发映射

> ⚠️ **本文件是「8 周学习计划」阶段的历史映射表，不是当前开发计划。**
> 当前计划看 [`docs/plan-p0p1p2.md`](docs/plan-p0p1p2.md)（P0/P1/P2 补足计划 + T1–T4 待办）
> 与 [`docs/dev-plan.md`](docs/dev-plan.md)（按代码板块的 checklist）。
> 三套编号的对应关系见下面 §3。
>
> **2026-09-12 订正**：本文件与 [`docs/8week-gantt.md`](docs/8week-gantt.md) 的勾选清单
> 自 2026-08 起**从未回填**（`docs/dev-plan.md` §3 写明的「每阶段完成把基线写入
> `roadmap.md` 勾选清单」这一步没有执行），于是长期停在「Rust/SP1 未装，待装」这种
> 与实际完全相反的状态。现已按实际交付逐条核对补齐。

> 完整计划见《方向2_Proof-of-Policy_8周计划_v2_零基础版.md》（**在仓库外的上层工作区**：
> `Proof-of-Policy/02_项目计划/`，不随本仓库分发）。本文件把每周里程碑对应到仓库里的具体文件与任务。

## 1. 周 × 落点 × 验收

| 周 | 目标 | 仓库落点 | 验收 | 状态 |
|---|---|---|---|---|
| 周0 | 环境 + 概念 | Rust 1.98 / SP1 6.7.0 / Go 1.25 / foundry 1.8.1；`circuits/README.md` | `cargo prove build` 跑通官方 fibonacci | ✅ |
| W1 | 概念 + zkVM 实操 | `docs/architecture.md` | 口述 R1CS/公开-私密 | ✅（**概念笔记 `docs/w1_notes.md` 从未落盘**，如实记） |
| W2 | 首批规则 | `policydsl/model.py` 的 KeywordBlock/LengthBound + `tests/test_dsl.py` | 单测全绿；基准表 | ✅ |
| W3 | PII 正则 | `policydsl/nfa.py` + `policydsl/pii.py` + `docs/policy-dsl.md` | ≥2 类 PII 规则通过 | ✅ |
| W4 | 透明模式 MVP | `circuits/program` + `circuits/script` | PoP v0：公开响应→证明→验证 | ✅ |
| W5 | 私有模式 | `policydsl/commit.py` + `pop-types::evaluate_private` | 验证者看不到全文 | ✅ |
| W6 | Agent 集成 | `policydsl/agent.py` + 三个框架适配器 + `policydsl/cert.py` + `policydsl/anchor.py` + `scripts/demo_e2e.py`；链上见 `contracts/Anchor.sol` | 真实会话产出证书 | ✅（**原计划的 `demo/` 目录未使用** —— 功能落在上述模块，该空目录已删除） |
| W7 | 评测 + 安全模型 | `bench/`（6 个脚本）+ `docs/security-model.md` v2（L1–L9）+ `docs/quadrant.md` | 成本曲线 + 四象限表 | ✅ |
| W8 | 论文 + 发布 | `paper/proof-of-policy.tex`（权威源）+ `docs/reproduce.md` + `scripts/make_shots.py` → `docs/demo/` 截图 | 导师按 README 复现通过 | ✅（**demo 视频未产出**，改由一键 demo + 截图替代） |

> W8 之后的工作（P0 补足、P1 轨迹/组合/链上/形式化、P2 语义/会话/多证明者/规模评测）
> 不在 8 周计划内，见 `docs/plan-p0p1p2.md`。

## 2. 完成度标记（Checklist）

- [x] 周0 环境（Rust/SP1 已装并验证；`SP1_PROVER=cpu` 出证跑通）
- [x] W1 概念笔记（`docs/architecture.md`；**独立笔记文件未产出**）
- [x] W2 骨架：KeywordBlock / LengthBound / PatternBlock（Python 参考层）+ 单测
- [x] W3 NFA 路径设计（`policydsl/nfa.py`，与 `re.search` 在 264 项语料上全一致）
- [x] W4 SP1 透明模式（`circuits/program` + `script`，PoP v0 出证+验证 PASS）
- [x] W5 私有模式（承诺 + 违规定位 + 脱敏 + 证据开示）
- [x] W6 agent 集成 + 证书（含链上锚定：真跑本地 Anvil 端到端 PASS）
- [x] W7 评测 + 安全模型（`bench/` 6 脚本 + `docs/security-model.md` v2 + `docs/quadrant.md`）
- [x] W8 论文 + 发布（`paper/proof-of-policy.tex` + `docs/reproduce.md`；**demo 视频未产出**）

## 3. 三套编号的对应关系

仓库里同时存在三套阶段编号，此前**没有映射表**，同一件事有三个名字。对照如下：

| 8 周计划（本文件 / `8week-gantt.md`） | `docs/dev-plan.md` | `docs/plan-p0p1p2.md` / `plan-p7.md` |
|---|---|---|
| 周0–W3 | Phase 0–2 | （P0 之前的基线） |
| W4 透明模式 MVP | Phase 3 | 基线 |
| W5 私有模式 | Phase 4（含 P4E） | 基线（口径由 P0-4 收紧） |
| W6 Agent + 证书 | Phase 5（含 P5G/P5H/P5I/P5J） | 基线；**链上验证证明 = P1-7** |
| W7 评测 + 安全模型 | Phase 6 | **P2-12**（评测）/ 形式化 = **P1-8** |
| W8 论文 + 发布 | Phase 6 | 论文在 P0–P2 期间持续刷新 |
| —— | **P7-a** verifier-only | **P1-7** 的前置；见 `docs/plan-p7.md` §A |
| —— | **P7-b** format/budget/tool 入电路 | 基线（P0 之前的健全性修复） |
| —— | **P7-c** 链上锚定 RPC 后端 | **P1-7** 的代码侧基础；见 `docs/plan-p7.md` §C |
| —— | —— | **P0-1…P0-4 / P1-5…P1-8 / P2-9…P2-12**，待办 **T1–T4** |

> 读法：**`plan-p0p1p2.md` 是当前的权威计划**；`dev-plan.md` 是按代码板块的 checklist；
> 本文件与 `8week-gantt.md` 只保留 8 周学习阶段的历史对应，不再更新。
