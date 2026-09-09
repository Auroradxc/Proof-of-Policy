# Proof-of-Policy · 代码开发计划（dev plan）

> 维护中 · 对应 8 周计划《方向2_Proof-of-Policy_8周计划_v2_零基础版.md》与《调研与项目计划.md》
> 文档定位：**按代码板块 × 阶段**组织，作为逐周编码 checklist。勾选即验收。

---

## 0. 当前基线（2026-09-10 实测）

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

### Phase 1 · 规则原语补全（W2 收尾）
- [ ] A：`format_check`、`tool_arg_guard`、`budget_bound` 的 model 校验 + 参考判定
- [ ] C：SP1 program 内 keyword_block / length_bound 判定
- [ ] Python 与 SP1 首条交叉验证一致；记录证明基线

### Phase 2 · 字符串/PII + NFA（W3）
- [ ] B：PII 规则（email/phone/secret 起步，IBAN 视时间）与校验位参考实现
- [ ] A：`compile.py` 填真 NFA（Thompson→transition 表，离线匹配产 witness path）
- [ ] C：SP1 内 NFA 路径验证
- [ ] ≥2–3 类 PII 规则双端判定一致
- ⚠️ 退路：正则过重时保 email/phone/secret，IBAN 后置

### Phase 3 · 策略编译器 + 透明模式 MVP ★ 必达（W4）
- [ ] A：DSL→约束编译框架（切片/合并，and，违规定位）
- [ ] C：ProofRequest serde；SP1 完整判定 + commit；script 出证/宿主验证
- [ ] `eu-ai-act-v1`、`finance-redaction-v1` 端到端
- [ ] **PoP v0**：真实响应→证明→独立验证，演示给导师

### Phase 4 · 私有模式 + 选择性披露（W5，尽力项）
- [ ] `policydsl/commit.py`：承诺 + 证据类型化切片
- [ ] 违规定位与证据披露（不见全文）
- [ ] redaction-with-proof（复用 VDR 位选择器直觉）
- [ ] Leak/不可伪造实验
- 退路：只做「承诺+违规定位」

### Phase 5 · Agent 集成 + 合规证书（W6）
- [ ] demo/ LangGraph agent + hooks
- [ ] 证书规范 `{policy, policy_hash, response_commitment, passed, proof, ts}`(DSSE/JSON)
- [ ] 链上锚定（sp1 verify 合约 / 本地 Anvil）

### Phase 6 · 评测 + 安全模型 + 发布（W7–W8）
- [ ] bench/：成本曲线 + NFA/DFA 消融 + 四象限表
- [ ] docs/security-model.md（健全性/隐私/不可伪造）
- [ ] 论文初稿 + README 复现指南

---

## 3. 关键路径与优先级

```
P0 ─► P1 ─► P2 ─► P3(透明MVP★)
                 ├─► P4 ─► P5 ─► P6
```
- 里程碑硬优先级：**P3 透明模式 MVP 必达**。
- 砍单顺序：P4 私有模式 → P5 Agent 深度 → P6 消融。
- 每阶段完成把基线写入 `roadmap.md` 勾选清单。

## 4. 已知环境对策（详见记忆 zk-policy-env-setup）

- 出证 `SP1_PROVER=cpu`（v6 合法值 cpu/cuda/mock/light/network）。
- sp1-prover 6.7.0 需 `TempDir::keep()` → 本仓库 vendored `circuits/patches/tempfile`（`[patch.crates-io]`），勿直接用官方 tempfile 3.x。
- Go/GOPROXY 需在构建环境生效（native-gnark）。
