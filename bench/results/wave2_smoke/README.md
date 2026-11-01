# Wave 2 冒烟结果（**不是论文数字**）

本目录是 2026-11-01 在本机（24 核 / 14.6 GiB / RTX 4060 8 GB）上跑
`bench_k_entropy.py`、`bench_real_llm_e2e.py`、`bench_privacy_surface.py`
的**冒烟输出**，用途只有一个：证明脚本链路能跑通、字段形状正确。

| 文件 | 后端 | 说明 |
|---|---|---|
| `k_entropy.*` | `stub`（确定性伪模型） | 温度 0 ⇒ k=0；温度 0.7 ⇒ p_max≈0.8、k≈0.24 bit |
| `k_samples.jsonl` | `stub` | 120 条样本（6 prompt × 2 温度 × 10） |
| `real_llm_e2e.*` | 上面的 stub 样本 + `--no-prove` | prompt 级策略 P/R/F1、响应违规率、拒绝代理 |
| `privacy_surface.*` | `unproven` + `--no-prove` | 没有证明工件；`hiding=n/a` |

**不要把这些数字写进论文/报告**：

- `stub` 不是任何真实模型；它的分布是人为的 80/10/10；
- `real_llm_e2e` 的响应来自 stub，响应违规率 100% 只说明 stub 把 prompt 原文照抄；
- `privacy_surface` 的 `unproven` 没有证明工件，不能说明任何 ZK 性质。

真实结果的落点仍是 `bench/results/`：

- `k_entropy.json` / `.md`：真实模型采样；
- `real_llm_e2e.json` / `.md`：真实响应 + 策略；
- `privacy_surface.json` / `.md`：`core` / `groth16` 真证明；
- `scale-cloud.json` / `.md`：云机规模矩阵。

复现冒烟见 [`docs/runbook-wave2.md`](../../../docs/runbook-wave2.md) §6。
