# 文档索引

> 这里是 `docs/` 的入口。**先看你要做什么，再看表** —— 这个仓库的文档有
> 「**维护中的当前说明**」与「**如实保留的历史记录**」两类，混着读会得到过期结论。
> 每篇文档开头都自带状态标注，本页把它们汇成一张表（§2）。
>
> 仓库入口是 [`../README.md`](../README.md)；一次完整复现见 [`reproduce.md`](reproduce.md)。

---

## 1. 按目的挑

| 我想…… | 读这几篇，按顺序 |
|---|---|
| **30 秒知道这项目在干嘛** | [`../README.md`](../README.md) → [`architecture.md`](architecture.md) |
| **上手开发 / 把仓库跑起来** | [`development.md`](development.md)（环境 → 15 分钟跑通 → 日常循环 → 配方 → 排查） |
| **看懂代码怎么落地** | [`modules/README.md`](modules/README.md)（总览 + 01–08 板块索引） |
| **亲手跑一遍完整链路** | [`reproduce.md`](reproduce.md) → [`demo/README.md`](demo/README.md) |
| **把出证做成常驻服务** | [`runbook-proof-service.md`](runbook-proof-service.md) |
| **评估它到底安全不安全** | [`security-model.md`](security-model.md) → [`sp1-zk-audit.md`](sp1-zk-audit.md) |
| **知道它跟 TEE / 形式验证差在哪** | [`quadrant.md`](quadrant.md) |
| **接自己的 agent 框架** | [`modules/06-frameworks.md`](modules/06-frameworks.md) §8 → [`modules/03-certificate.md`](modules/03-certificate.md) |
| **对上 EU AI Act 的条款** | [`eu-ai-act-mapping.md`](eu-ai-act-mapping.md) |
| **改语义规则那条线** | [`design-semantic-rules.md`](design-semantic-rules.md) |
| **看接下来要做什么** | [`dev-plan.md`](dev-plan.md)（唯一维护中的计划） |

---

## 2. 全部文档一览

### 2.1 当前说明（维护中）

| 文档 | 定位 |
|---|---|
| [`architecture.md`](architecture.md) | **分层与契约**，一页纸。想知道「有几层、层间签的是什么合同」就读它 |
| [`modules/README.md`](modules/README.md) | **实现层总览**：仓库布局、端到端数据流（带函数名）、7 条全局不变量、8 个板块索引 |
| [`modules/01-policy-dsl.md`](modules/01-policy-dsl.md) … [`08-tests-bench.md`](modules/08-tests-bench.md) | 按**功能板块**拆解代码：职责 / 文件清单 / 数据结构 / 函数级 API / 不变量与边界 / 测试对应 / 扩展指引 |
| [`security-model.md`](security-model.md) | **安全模型 v2**：游戏式定义 + 归约 + 引理 L1–L9，每条性质给出代码落点 |
| [`sp1-zk-audit.md`](sp1-zk-audit.md) | SP1 v6.7.0 的**健全性与零知识性核查**（结论：健全性成立；`core`/`compressed` 不满足零知识性） |
| [`design-semantic-rules.md`](design-semantic-rules.md) | 语义规则（学习型规则）的**信任边界论证**（引理 L7）：为什么它必须委托给陪伴证明、三个边界条件 |
| [`quadrant.md`](quadrant.md) | **信任-成本四象限**：与 TEE / 形式验证 / hash-chain 三派对位比较 |
| [`eu-ai-act-mapping.md`](eu-ai-act-mapping.md) | 证书字段与 EU AI Act Art.12/13 透明义务的**工程映射**（非法律意见） |
| [`reproduce.md`](reproduce.md) | **复现指南**（按功能）：从零到「一次合规证明 + 第三方独立验证」，含环境要求与故障排查 |
| [`development.md`](development.md) | **开发与使用手册**（按循环与角色）：环境分层 / 15 分钟跑通 / 改一处代码跑哪几条验证 / 常见任务配方 / 环境变量 / 产物地图 / 故障排查。与 `reproduce.md` 的分工：那篇回答「每个特性怎么复现出来」，这篇回答「我平时怎么在这个仓库里干活」 |
| [`runbook-proof-service.md`](runbook-proof-service.md) | 证明服务的**运维手册**：跑起来要什么 / 怎么确认它是好的 / 满载时怎么表现 / 出事怎么办 |
| [`demo/README.md`](demo/README.md) | **全链路 demo**：`demo_all.sh` 的 8 条支路各跑什么、看到什么算对、哪条为什么没跑，以及 fast 模式下 `PASS` 的**确切含义** |
| [`dev-plan.md`](dev-plan.md) | **当前开发计划**（唯一维护中的计划）。按代码板块 × 阶段组织，勾选即验收 |
| [`refactor-proposal.md`](refactor-proposal.md) | **重构与优化建议书 + 执行计划**（2026-09-17 立，**已采纳**）。从技术框架 / 效率 / 内存 / 简洁四个角度普查后给出的 R1–R18 建议与 P0–P3 阶段。执行进度与每阶段的验收记录见 [`dev-plan.md` §5.7](dev-plan.md) |

### 2.2 历史记录（**已冻结，刻意保留原样**）

> 这几篇里的测试计数、任务编号都是**当时那一刻的快照**，不要拿来当现状。
> 计数现状**一律**以 [`modules/08-tests-bench.md`](modules/08-tests-bench.md) 为准。

| 文档 | 冻结于 | 为什么留着 |
|---|---|---|
| [`plan-p0p1p2.md`](plan-p0p1p2.md) | P0/P1/P2 收尾（2026-09-12） | P0–P2 的**逐任务工作记录**（含一个已实跑复现的健全性破坏的记录）。它解释了今天很多设计的**来由** |
| [`plan-p7.md`](plan-p7.md) | P7 收尾（2026-09-10） | P7（verifier-only / 规则入电路 / 链上锚定）的按日记录 |
| [`policy-dsl.md`](policy-dsl.md) | v0.1（已被取代） | 最早的 DSL 规范。「规则长什么样 → 编译成什么 → 谁怎么判定」的**权威说明**已移到 [`modules/01-policy-dsl.md`](modules/01-policy-dsl.md) |
| [`8week-gantt.md`](8week-gantt.md) | 8 周阶段结束 | 8 周进度看板 + SQLite 任务视图说明 |
| [`learning-calendar.md`](learning-calendar.md) | 8 周阶段结束 | W1–W8 逐日学习日历（0 基础研究生用） |
| [`kanban.html`](kanban.html) | 8 周阶段结束 | 上述看板的网页版 |

### 2.3 论文

| 文件 | 说明 |
|---|---|
| [`../paper/proof-of-policy.tex`](../paper/proof-of-policy.tex) | **权威源**（改动先落这里） |
| [`../paper/proof-of-policy.md`](../paper/proof-of-policy.md) | 可读镜像，与 `.tex` 同步 |

---

## 3. 三条「唯一权威源」约定

同一个事实只在一处维护，其余地方要么引用、要么是快照（并在文中注明）：

| 事实 | 权威源 | 别处怎么办 |
|---|---|---|
| 测试数量 / 每个测试模块覆盖什么 | [`modules/08-tests-bench.md`](modules/08-tests-bench.md) | 其他文档引用它，或标注「某次快照」 |
| 策略 DSL 的语义（规则 → 契约 → 判定） | [`modules/01-policy-dsl.md`](modules/01-policy-dsl.md) | `policy-dsl.md` 是 v0.1 历史规范 |
| 要做的事 / 做到哪一步 | [`dev-plan.md`](dev-plan.md) | `plan-*.md` 是历史记录 |
| 论文数字 | [`../paper/proof-of-policy.tex`](../paper/proof-of-policy.tex) | `.md` 是镜像；`README.md` 与 `reproduce.md` 的硬编码数字要一并核对 |
| 评测原始数据 | [`../bench/results/`](../bench/results/) | 文档里的数字应当指得回某一份结果文件 |

---

## 4. 文档写法上的两条纪律

这两条是这个仓库踩过坑之后立的，改文档时请遵守：

1. **不要写「恒真的断言」。** 「测试全绿」若把那批 `skip` 算进去，就是**静默的绿** ——
   `unittest` 的 skip 不报错。凡是「只在更强的机器 / 更大的内存上才跑」的路径，
   测试套件对它**零覆盖**，而它照样全绿。所以验收优先写「**实跑了什么**」，
   而不是「测试过了」：见 [`dev-plan.md` §5.6.7](dev-plan.md) 的两个实例。
2. **过期就标注，不要悄悄改。** 历史文档里的旧数字是**证据**，留着；但要在开头写明
   「这是某阶段快照，现状见 X」。已经这么做过的一批见 [`dev-plan.md` §5.4.1](dev-plan.md)。

---

## 5. 相关

- 仓库根：[`../README.md`](../README.md)
- 8 周学习阶段的对外说明：[`../方向二_README.md`](../方向二_README.md)
- 周次打标：[`../roadmap.md`](../roadmap.md)
