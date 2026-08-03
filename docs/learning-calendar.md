# W1-W8 逐日学习日历（0 基础研究生专用）

> 配套：《方向2_Proof-of-Policy_8周计划_v2_零基础版.md》+ 仓库 `zk-policy/`
> 节奏：周一至周六学习+开发，周日复盘补缺。每天约 5-6 小时（3h 学习 + 2-3h 开发）。
> 规则：**先跑通再懂原理**；每周末有一个「一句话口述」检查点；落后就砍 W5→W6→W7（顺序见 v2 计划）。

---

## W1 · 概念建基 + zkVM 实操

**本周目标**：理解 ZK 三性质与 R1CS 直觉；跑通 SP1 最小证明；能分清「公开输入 / 私密 witness / 承诺输出」。

**Day 1（Mon）—— 为什么 ZK 可信**
- 阅读：Petkus《零知识证明入门》**第 1 章**（同态隐藏、盲计算）；若没有中译，读英文版 *Why and How zk-SNARK Works* 第 1 章。
- 练习：纸笔做一个「多项式盲评估」小例子（自己选一个常数 r，手算多项式在某点的隐藏评估）。
- 产出（写进 `docs/w1_notes.md`）：用自己的话写 3 句——完备性 / 健全性 / 零知识。
- 检查点：给同学讲 1 分钟「为什么多项式评估是『隐藏的』」。

**Day 2（Tue）—— 多项式是地基**
- 阅读：Petkus **第 2 章**（多项式、度、根、因式定理）。
- 练习：验证「两个多项式共享多个根 ⇒ 有公共因式」的小例子；手算一个 2 次多项式在 3 个点的取值。
- 产出：笔记「因式定理为什么是 SNARK 的基石」。

**Day 3（Wed）—— 环境 + 第一个证明**
- 阅读：SP1 官方文档「What is a zkVM」+ 快速开始。
- 练习：安装 Rust + SP1（`curl -L https://sp1.succinct.xyz | bash` 后 `cargo prove install`；Windows 按官方指引）；跑通官方 `fibonacci` 例程：生成证明 → 验证通过。
- 产出：截图 `cargo prove run examples/fibonacci` 的证明生成/验证成功日志。
- **风险提示**：SP1 安装可能 30-60 分钟，若失败先记录报错，Day 4 解决。

**Day 4（Thu）—— 程序 = 约束**
- 阅读：Petkus **第 4 章**（一般计算 → 多项式约束）；SP1 `examples/is-even` 或 `examples/io` 源码。
- 练习：读懂 fibonacci 程序代码，标出「哪部分是公开输出、哪部分是私有输入」。
- 产出：笔记「为什么程序能被证明执行」（约束 vs 普通执行的区别）。

**Day 5（Fri）—— R1CS 直觉**
- 阅读：Petkus **第 5 章**前半；Vitalik《Quadratic Arithmetic Programs: from Zero to Hero》（中文翻译版）前半。
- 练习：把表达式 `x³ + x + 5` 手动写成 R1CS 约束（对照 Vitalik 的逐步例子）。
- 产出：概念笔记：公开输入 / 私密 witness / 约束系统三者关系。
- 检查点：**口述给导师**：「证明者知道 witness，验证者只看到公开输入和证明」。

**Day 6（Sat）—— zkVM 实操**
- 阅读：SP1 docs 的 IO / 内存模型。
- 练习：改 fibonacci：加一个**私密输入**，只承诺输出；重新跑证明验证。
- 产出：改后代码 + 验证结果；`git commit`。
- 检查点：能说出「改了什么让输入变私密」。

**Day 7（Sun）—— 复盘**
- 任务：补 Day1-6 缺口；写周记；向导师做「口述验收」（三性质 + R1CS）。
- 里程碑达标标志：环境跑通 + 概念笔记完成。

---

## W2 · 电路思维 + 首批规则（KeywordBlock / LengthBound）

**本周目标**：理解 lookup 直觉；读懂 `policydsl` 的模型与测试；会写新规则测试；理解「约束编译要确定性」。

**Day 1（Mon）—— lookup 直觉**
- 阅读：zk-learn 的 lookup 笔记（或 Jolt 论文动机段）；Petkus 第 5 章后半（可选）。
- 练习：在黑名单场景思考：为什么「查表命中」比「逐词比较电路」更小。
- 产出：笔记「lookup 查表命中直觉」。

**Day 2（Tue）—— 读代码 + 写测试**
- 阅读：`policydsl/model.py`、`policydsl/evaluate.py`、`tests/test_dsl.py` 全文。
- 练习：`python -m unittest discover tests -v` 跑通；新增 2 个测试（中文关键词、大小写混合关键词）。
- 产出：新测试入库。
- 检查点：能解释 `assertFalse(r.passed)` 在测什么。

**Day 3（Wed）—— 确定性编译**
- 阅读：`docs/architecture.md` 的 ConstraintSpec 结构；`policydsl/compile.py` 的 `_canonical_hash`。
- 练习：读懂 KeywordBlock 的「小写化 + 排序」规范化，写测试覆盖（两个不同顺序的关键词列表 → 相同 spec）。
- 产出：笔记「为什么约束编译要确定性」。

**Day 4（Thu）—— 长度规则 → 电路**
- 阅读：`circuits/program/src/main.rs` 骨架；SP1「写约束」的思维（zkVM 里一切可证明）。
- 练习：写一个「长度边界」的最小 Rust 伪代码（不用编译，纯注释版即可），表达 min/max 两个 range 检查。
- 产出：笔记「长度规则 → 电路映射」。

**Day 5（Fri）—— 基准与成本概念**
- 阅读：SP1 关于证明时间/内存的文档。
- 练习：`python -m policydsl compile policy_packs/eu_ai_act_v1.json` 与 `finance_redaction_v1.json`，记录各自 spec 大小与 sha256；改动关键词数量观察 spec 大小变化。
- 产出：基准表 v0（规则数 × spec 大小；证明时间基线待 W4）。

**Day 6（Sat）—— 黄金测试**
- 阅读：复习本周笔记。
- 练习：在 tests 里加「策略包黄金测试」：读 `eu_ai_act_v1.json`，对 3 个已知响应断言 passed/failed。
- 产出：黄金测试全绿；`git commit`。
- 检查点：一句话解释 lookup 优势。

**Day 7（Sun）—— 复盘**
- 口述「黑名单为什么用 lookup」；补缺；里程碑：规则库 v0 + 基准表 + 黄金测试。

---

## W3 · 正则/NFA + PII 规则（PatternBlock）

**本周目标**：理解正则→NFA→电路路径验证；实现 ≥2 类 PII 规则；能画出「正则→NFA→约束」流程。

**Day 1（Mon）—— 正则 → NFA**
- 阅读：Neso Academy「正则表达式→NFA」视频或教材；Thompson 构造概念。
- 练习：把 email 正则 `[\w.+-]+@[\w-]+\.[\w.]+` 手画 NFA（纸笔）。
- 产出：NFA 草图扫描/拍照入档 `docs/`。

**Day 2（Tue）—— 两段式路径验证**
- 阅读：zk-regex V2 README + 博客《zk-regex-v2》（离线匹配出路径 → 电路内只验路径）。
- 练习：精读 README 流程图；画出「路径验证」框图。
- 产出：笔记「为什么路径验证比全图匹配电路小」。

**Day 3（Wed）—— PII 校验位数学**
- 阅读：IBAN MOD-97、Luhn（信用卡）、身份证号（GB11643）校验算法。
- 练习：手算 1 个 IBAN 校验位。
- 产出：笔记「校验位在电路里如何表达（模运算 → 约束）」。

**Day 4（Thu）—— 实现 PII 规则**
- 阅读：`policydsl/evaluate.py` 的 `pattern_block` 分支（`re.search` 语义）。
- 练习：给 `finance_redaction_v1.json` 加 phone、IBAN 两条新 pattern 规则；用 `python -m policydsl check` 验证。
- 产出：PII 规则 ≥3 类；黄金测试扩展。
- **风险**：正则电路最可能超时。**退路**：只保留 email + phone，IBAN 留到 Day5。

**Day 5（Fri）—— NFA 电路接口设计**
- 阅读：`docs/policy-dsl.md` 的 `pattern_block` 说明。
- 练习：写「NFA 路径验证电路接口」伪代码（状态转移表 + 路径向量），追加到 `docs/policy-dsl.md`。
- 产出：接口设计文档。
- 检查点：给同学讲 5 分钟「NFA 路径验证」。

**Day 6（Sat）—— 电路伪代码**
- 阅读：SP1 字节/字符串处理示例。
- 练习：为 `circuits/program` 写 PatternBlock 判定的 Rust 伪代码（不编译，标注 W4 接入）。
- 产出：伪代码入库；`git commit`。

**Day 7（Sun）—— 复盘**
- 口述「PII 规则原理」；若正则卡壳，执行退路；里程碑：字符串规则模块 + 黄金测试。

---

## W4 · 策略编译器 + 透明模式 MVP（★ 必达）

**本周目标**：ConstraintSpec → SP1 program → 证明 → 验证打通；产出 **PoP v0**。

**Day 1（Mon）—— 契约与结构**
- 阅读：`docs/architecture.md` 精读；`sp1-contracts` 链上验证概览。
- 练习：定义 ProofRequest 的 serde 结构（Rust 注释版），写入 `circuits/program/src`。
- 产出：ProofRequest 定义入库。

**Day 2（Tue）—— program：规则判定**
- 阅读：SP1 官方 `groth16` 示例（zkVM 内 verify 模式）。
- 练习：填充 `keyword_block` + `length_bound` 的 zkVM 内判定（真实 Rust 代码）。
- 产出：program v0 可编译（装好 Rust 后）；否则保留并注释 TODO。

**Day 3（Wed）—— program：PatternBlock**
- 阅读：W3 的 NFA 路径验证设计。
- 练习：实现/接入 NFA 路径验证（若困难，先用「字符串包含」简化版并标注 TODO）。
- 产出：program 支持全部 3 类规则。

**Day 4（Thu）—— script：证明与验证**
- 阅读：SP1 SDK 证明生成 API 文档；`circuits/script/src/main.rs` 骨架。
- 练习：填充 script：加载 ProofRequest → `prove` → 宿主机 `verify`。
- 产出：端到端脚本（装好 Rust 后跑通一次证明/验证）。
- 检查点：记录一次真实证明时间。

**Day 5（Fri）—— 交叉验证**
- 阅读：交叉验证思路（SP1 判定 vs `policydsl.evaluate`）。
- 练习：写 `tools/check_cross.py`：同一响应比较两层判定。
- 产出：交叉验证脚本，3 个样例（1 pass / 2 fail）两层一致。
- 检查点：两层判定全一致。

**Day 6（Sat）—— demo**
- 阅读：EU AI Act 官方 FAQ 摘要（Art.12/13 一两句即可）。
- 练习：完善 `eu_ai_act_v1` 策略包；写透明模式一键 demo 脚本；录屏 30s。
- 产出：**PoP v0 demo**。
- 检查点：**给导师演示**。

**Day 7（Sun）—— 复盘**
- 口述「我证明的是什么——性质，不是模型计算」；把 MVP 结果写入 `roadmap.md`（勾选 W4）。

---

## W5 · 私有模式（尽力项）

**本周目标**：响应私有化（承诺）；违规理由选择性披露；（尽力）redaction-with-proof。**允许降级**。

**Day 1（Mon）—— 承诺方案**
- 阅读：Petkus 第 1 章 HH 复习；VDR（IACR 2024/813）摘要 + 位选择器结论。
- 练习：在 `policydsl` 实现 `commit_response()`：`sha256(response || nonce)`。
- 产出：commit 函数 + 测试。

**Day 2（Tue）—— 违规定位**
- 阅读：选择性披露直觉（zk-regex 的 `is_public` 标志 / VDR 位选择器）。
- 练习：实现「只揭示 `violations[].rule + evidence_kind`、不揭示响应」的私有输出。
- 产出：私有模式 v1（简化）。
- 检查点：能说清「披露了什么、没披露什么」。

**Day 3（Wed）—— redaction-with-proof（尽力）**
- 阅读：VDR 的 redaction 构造（可选）。
- 练习：PII 掩码：掩码版 + 证明「只在掩码位置不同」。
- 产出：redaction-with-proof（尽力项，失败则跳过）。

**Day 4（Thu）—— 安全模型直觉**
- 阅读：soundness / zero-knowledge 的形式化定义（Petkus 第 1 章复习）。
- 练习：写「合规健全性」的口语化论证（违反策略 ⇒ 无有效证明）。
- 产出：`docs/security-model.md` 第一节。

**Day 5（Fri）—— GDPR 叙事 + demo**
- 阅读：GDPR「不留 PII 日志」叙事。
- 练习：把 `finance_redaction_v1` 对接私有模式 demo。
- 产出：私有模式 demo 用例。
- 检查点：验证者看不到全文但确认违反规则。

**Day 6（Sat）—— 收尾**
- 练习：私有模式测试扩展；`git commit`。

**Day 7（Sun）—— 复盘**
- 若私有模式过重，执行退路（只做「承诺 + 违规定位」），并记录到 roadmap。

---

## W6 · Agent 集成 + 合规证书

**本周目标**：LangGraph agent + 出证插桩 + 可验证证书。

**Day 1（Mon）—— 最小 agent**
- 阅读：Hugging Face Agents Course Unit 1-2；LangGraph 官方快速开始。
- 练习：搭最小 LangGraph agent（调用 1 个工具）。
- 产出：`demo/agent/` 最小 agent 跑通。

**Day 2（Tue）—— MCP 风格工具**
- 阅读：MCP 规范 "Tools" 一节。
- 练习：给 agent 接一个 MCP 风格工具（或本地函数）。
- 产出：agent + 1 工具。

**Day 3（Wed）—— 证书格式**
- 阅读：`demo/README.md` 的证书示例；DSSE/JSON 概念。
- 练习：实现证书生成 `{policy, policy_hash, response_commitment, passed, proof, ts}`。
- 产出：cert 脚本 + 示例证书。

**Day 4（Thu）—— 链上锚定（尽力）**
- 阅读：SP1 verify 合约概念。
- 练习：（尽力）SP1 链上 verify 脚本或文档化流程。
- 产出：链上验证脚本/文档。
- 检查点：能解释「链上锚定带来什么」。

**Day 5（Fri）—— 插桩出证**
- 阅读：EU AI Act Art.12 映射（按次审计）。
- 练习：在 agent 生成路径 + 工具调用后插桩出证。
- 产出：真实会话 → 可验证证书。
- 检查点：**第三方（同学）独立验证通过**。

**Day 6（Sat）—— demo 视频**
- 练习：录 30s demo；`git commit`。

**Day 7（Sun）—— 复盘**
- 口述「证书让审计者信服什么」。

---

## W7 · 评测 + 安全模型

**本周目标**：形式化安全模型草稿；成本曲线 + 四象限对比。

**Day 1（Mon）—— 形式化定义**
- 阅读：完备性/健全性/零知识形式化；VDR Leak 实验。
- 练习：把三个定义实例化到本项目。
- 产出：`docs/security-model.md` 完整草稿。

**Day 2（Tue）—— 评测脚本**
- 阅读：实验设计（变量控制、消融）。
- 练习：写评测脚本：证明时间/大小 vs 响应长度 × 规则数 × 策略大小（装好 Rust 后跑；先记录 spec 大小）。
- 产出：`bench/` 脚本 v0。

**Day 3（Wed）—— 消融（尽力）**
- 阅读：NFA vs DFA 成本直觉。
- 练习：关键词数量对 spec 大小的影响。
- 产出：消融数据。

**Day 4（Thu）—— 四象限对比**
- 阅读：ZK/TEE/形式验证/hash-chain 对比思路。
- 练习：画对比表（信任根基 / 开销 / 隐私 / 合规性）。
- 产出：对比表入库。

**Day 5（Fri）—— 相关工作**
- 阅读：Proof-of-Guardrail（TEE 派）、WITNESS、zk-regex、VDR。
- 练习：写「相关工作」段落初稿（四派定位 + 空位论证）。
- 产出：related work 草稿。

**Day 6（Sat）—— 收尾**
- 练习：图表整理；`git commit`。

**Day 7（Sun）—— 复盘**
- 口述「违反策略的轨迹为何无法通过验证」。

---

## W8 · 论文 + 发布

**本周目标**：论文初稿（8-10 页）+ 开源仓库 + 复现指南。

**Day 1（Mon）—— 论文骨架**
- 阅读：系统安全论文结构模板；精读 1 篇同类短文（Proof-of-Guardrail）的结构。
- 练习：搭论文骨架（标题 / 摘要 / 威胁模型 / 系统 / 安全模型 / 实验 / 相关工作 / 结论）。
- 产出：论文大纲。

**Day 2（Tue）—— 威胁模型 + 系统**
- 练习：填充「威胁模型」（谁能做什么、信任边界）与「系统设计」（双层架构 + ConstraintSpec 契约）。
- 产出：论文 §1-§3 初稿。

**Day 3（Wed）—— 安全模型**
- 练习：把 `docs/security-model.md` 压缩进论文「安全模型」节。
- 产出：论文 §4 初稿。

**Day 4（Thu）—— 实验**
- 练习：把 W7 评测图 + 四象限对比表整理进「实验」节。
- 产出：论文 §5 初稿。

**Day 5（Fri）—— 相关工作 + 结论**
- 练习：相关工作段落 + 结论 + 摘要润色。
- 产出：论文完整初稿。
- 检查点：**导师审阅反馈**。

**Day 6（Sat）—— 发布**
- 练习：README 复现指南；demo 视频；补 LICENSE（如 MIT）。
- 产出：最终仓库。
- 检查点：**导师按 README 从零复现通过**。

**Day 7（Sun）—— 总结**
- 提交论文给导师；记录 8 周总结 + 下一步延伸（E1-E4 → M1-M6，见 v2 计划）。

---

## 附：每周「一句话口述」检查点汇总（给导师）

| 周 | 口述内容 |
|---|---|
| W1 | 证明者知道 witness，验证者只看到公开输入和证明 |
| W2 | 黑名单为什么用 lookup（查表命中比逐词比较电路小） |
| W3 | 正则→NFA→「离线出路径，电路内只验路径」 |
| W4 | 我证明的是性质（响应满足策略），不是模型计算 |
| W5 | 私有模式披露了什么、没披露什么 |
| W6 | 证书让审计者信服什么（无需信任服务商） |
| W7 | 违反策略的轨迹为何无法通过验证（健全性） |
| W8 | 一句话总结系统价值 + 下一步延伸 |

## 附：若每周只有半天可投入

把「阅读」压缩为官方 docs + 项目注释，理论部分周末集中 2 小时补；开发任务按「必达（★）/尽力」取舍：必达 = W4 透明模式 MVP + W7 基础评测，其余尽力。
