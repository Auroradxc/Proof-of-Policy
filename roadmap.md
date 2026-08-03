# 8 周开发映射

> 完整计划见《方向2_Proof-of-Policy_8周计划_v2_零基础版.md》。本文件把每周里程碑对应到仓库里的具体文件与任务。

| 周 | 目标 | 仓库落点 | 验收 |
|---|---|---|---|
| 周0 | 环境 + 概念 | 本机 Rust/SP1 安装脚本说明（circuits/README.md） | `cargo prove build` 跑通官方 fibonacci |
| W1 | 概念 + zkVM 实操 | docs/architecture.md 精读；policydsl 模型理解 | 口述 R1CS/公开-私密 |
| W2 | 首批规则 | `policydsl/model.py` KeywordBlock/LengthBound + `tests/test_dsl.py` | 单测全绿；基准表 |
| W3 | PII 正则 | `policydsl` PatternBlock + `docs/policy-dsl.md` 的 NFA 设计 | ≥2 类 PII 规则通过 |
| W4 | 透明模式 MVP | `circuits/program` + `circuits/script` 填充 | PoP v0：公开响应→证明→验证 |
| W5 | 私有模式 | 响应承诺 + 违规定位（新增 `policydsl/commit.py` 等） | 验证者看不到全文 |
| W6 | Agent 集成 | `demo/` 插桩 + 证书格式 + 链上锚定 | 真实会话产出证书 |
| W7 | 评测 + 安全模型 | `bench/` 脚本 + `docs/security-model.md` | 成本曲线 + 四象限表 |
| W8 | 论文 + 发布 | 论文初稿 + 复现指南 + demo 视频 | 导师按 README 复现通过 |

## 完成度标记（Checklist）

- [ ] 周0 环境（Rust/SP1 未装，待装）
- [ ] W1 概念笔记
- [x] W2 骨架：KeywordBlock / LengthBound / PatternBlock（Python 参考层）+ 单测
- [ ] W3 NFA 路径设计
- [ ] W4 SP1 透明模式
- [ ] W5 私有模式
- [ ] W6 agent 集成 + 证书
- [ ] W7 评测 + 安全模型
- [ ] W8 论文 + 发布
