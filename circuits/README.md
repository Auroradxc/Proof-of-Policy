# circuits/ —— SP1 证明层（Rust）

> **当前状态（2026-08-03）：骨架，不可构建**。本机未安装 Rust/SP1。
> W4 启用本层；在此之前使用 `policydsl/`（Python）完成策略作者与参考评估。

## 结构

- `program/` — SP1 **zkVM 程序**：读入 ProofRequest（响应 + ConstraintSpec），重放约束判定，`commit(passed, evidence)`。
- `script/`  — SP1 **驱动**：调用 `sp1-sdk` 生成证明；宿主机验证；可选链上验证（`sp1-contracts`）。

## 安装（W4 前执行）

```bash
# 见 SP1 官方文档（Windows 用户按官方指引）
curl -L https://sp1.succinct.xyz | bash
cargo prove install
```

## W4 任务（打开本层时）

1. 定义 ProofRequest 的 serde 结构（与 `docs/architecture.md` 的 ConstraintSpec 对齐）。
2. `program/src/main.rs`：实现每个约束 kind 的判定（keyword lookup / length range / NFA 路径验证）。
3. `script/src/main.rs`：加载 ProofRequest → `prove` → 输出 proof + public output → 宿主机 verify。
4. 交叉验证：对同一响应，比较 SP1 判定与 `policydsl.evaluate()` 的 golden。
