# Proof-of-Policy · 8 周甘特图 & 看板

> 起始日按 2026-08-03（周0）排布，可整体平移。依赖关系见 v2 计划：周0→W1→W2→W3→W4(★MVP)→W5→W6→W7→W8。
> 配套：《方向2_Proof-of-Policy_8周计划_v2_零基础版.md》、`docs/learning-calendar.md`。

## 一、甘特图（Mermaid）

```mermaid
gantt
    title Proof-of-Policy · 8 周计划（2026-08-03 起，可平移）
    dateFormat YYYY-MM-DD
    axisFormat %U周
    section 学习
    周0 数学+ZK概念自学      :t0, 2026-08-03, 7d
    W1 概念+zkVM实操        :t1, 2026-08-10, 7d
    W2 电路思维+规则         :t2, 2026-08-17, 7d
    W3 正则/NFA+PII          :t3, 2026-08-24, 7d
    W4 编译器+透明模式       :t4, 2026-08-31, 7d
    W5 私有模式              :t5, 2026-09-07, 7d
    W6 Agent+证书            :t6, 2026-09-14, 7d
    W7 评测+安全模型         :t7, 2026-09-21, 7d
    W8 论文+发布             :t8, 2026-09-28, 7d
    section 开发/交付
    环境跑通(周0)            :d0, 2026-08-03, 7d
    规则库+单测(W2)          :d2, 2026-08-17, 7d
    PII 规则(W3)             :d3, 2026-08-24, 7d
    PoP v0 MVP(W4)           :d4, 2026-08-31, 7d
    PoP v1 私有(W5)          :d5, 2026-09-07, 7d
    合规证书(W6)             :d6, 2026-09-14, 7d
    成本曲线+安全模型(W7)    :d7, 2026-09-21, 7d
    论文初稿+仓库(W8)        :d8, 2026-09-28, 7d
    section 里程碑
    环境+概念口述            :milestone, m0, 2026-08-09, 0d
    规则库 v0                :milestone, m1, 2026-08-23, 0d
    ★透明模式 MVP            :milestone, m2, 2026-09-06, 0d
    demo 视频                :milestone, m3, 2026-09-20, 0d
    论文初稿                 :milestone, m4, 2026-10-04, 0d
```

## 二、关键路径

```
周0 ─► W1 ─► W2 ─► W3 ─► W4(★MVP) ─► W6 ─► W7 ─► W8
                                └─► W5(私有,可并行/压缩)
```

- **关键路径**：环境 → 规则库 → PII 正则 → 透明模式 MVP → agent 证书 → 评测 → 论文。
- **滞后砍单顺序**：W5 私有模式 → W6 agent 深度集成 → W7 消融（保透明模式 + 基础评测）。

## 三、看板（Swimlane：周 / 待办 / 进行中 / 已完成）

> 勾选即更新；每周末做一次「口述验收」（见 learning-calendar 附：每周一句话检查点）。

| 周 | 待办（本周） | 进行中 | ✅ 已完成 |
|---|---|---|---|
| **周0** | [ ] 装 Rust+SP1；[ ] 跑通 fibonacci 证明 | | [ ] 概念阅读开始 |
| **W1** | [ ] 概念笔记（三性质/R1CS）；[ ] SP1 最小证明 | | [ ] 环境跑通 |
| **W2** | [ ] KeywordBlock/LengthBound 实现+单测；[ ] 基准表 | | [ ] 规则库 v0 |
| **W3** | [ ] PatternBlock（NFA 路径）；[ ] ≥2 类 PII 规则 | | [ ] 字符串规则模块 |
| **W4** | [ ] 策略编译器；[ ] 透明模式端到端；[ ] 链上 verify | | [ ] **PoP v0（MVP）** |
| **W5** | [ ] 响应承诺；[ ] 违规定位披露；（尽力）redaction | | [ ] PoP v1 私有简化 |
| **W6** | [ ] LangGraph 插桩；[ ] 合规证书；[ ] 链上锚定 | | [ ] 证书 + demo |
| **W7** | [ ] 成本曲线；[ ] 四象限表；[ ] 安全模型草稿 | | [ ] 评测 + 模型 |
| **W8** | [ ] 论文初稿；[ ] 复现指南；[ ] demo 视频 | | [ ] 论文 + 仓库 |

## 四、周产出速查（对仓库落点）

| 周 | 落点 | 验收 |
|---|---|---|
| W1 | `docs/w1_notes.md`、SP1 例程 | 口述三性质 |
| W2 | `policydsl/model.py`、`tests/test_dsl.py` | 单测全绿 + 基准表 |
| W3 | `policy_packs/finance_redaction_v1.json`、`docs/policy-dsl.md` | ≥2 类 PII 通过 |
| W4 | `circuits/program`、`circuits/script` | PoP v0 证明→验证 |
| W5 | 私有模式模块、`docs/security-model.md` 第一节 | 验证者看不到全文 |
| W6 | `demo/`、cert 脚本 | 真实会话证书可验证 |
| W7 | `bench/`、`docs/security-model.md` | 成本曲线 + 对比表 |
| W8 | 论文 + README 复现 | 导师按 README 复现通过 |

## 五、风险与退路（速览）

| 风险 | 退路 |
|---|---|
| 正则电路成本超预算 | 砍 PII 至 2 类；保关键词+长度即达 W4 |
| 私有模式拖慢 | 降级为「承诺+违规定位」 |
| SP1 工具链安装受阻 | 周0 集中装；Python 参考层先行开发 |
| WITNESS 概念冲突 | 以「通用 DSL+开源+双隐私+形式化模型」定位 |
