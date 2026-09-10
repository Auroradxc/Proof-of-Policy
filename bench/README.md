# bench/ — 评测

两组测量，覆盖「成本 vs（响应长度 × 规则数 × 匹配模式）」：

| 脚本 | 测什么 | 用时 | 说明 |
|---|---|---|---|
| `bench_cycles.py` | **zkVM 周期数**（`pop-script --execute`，不出证） | 每点数秒 | 多点扫描；含 **pike vs naive** 消融 |
| `bench_proofs.py` | **证明墙钟时间 + 证明工件大小 + 峰值内存**（真实 SP1 证明） | 每点 ~100–150s | 点数少；每点附 `--verify` 成功确认 |
| `bench_verify.py` | **验证成本**（冷启动 CLI / vkey setup / 纯验证） | 每次 ~20s | 区分「CLI 冷启动（含构造证明器）」与「纯密码学验证」 |

运行（需先构建 `circuits`，见 `docs/reproduce.md` §2）：

```bash
python3 bench/bench_cycles.py                                  # → bench/results/cycles.{json,md}
SP1_PROVER=cpu python3 bench/bench_proofs.py                    # → bench/results/proofs.{json,md}
SP1_PROVER=cpu python3 bench/bench_verify.py --proof <proof.bin>  # → bench/results/verify.{json,md}
```

结果写入 `bench/results/`（**已入库**，供论文/文档引用）；中间产物 `bench/work/` 被忽略。
**对标**：`bench/comparison_zkagent.md`（vs zkAgent, ePrint 2026/199）。

设计要点：
- 变长响应由 `bench_cycles.response()` 生成（无害文本，确保所有约束都被完整扫描）；
- 规则数 1/3/6：1 = 仅长度；3 = +keyword+pattern；6 = +更多 keyword/pattern；
- **消融**：`match_mode=naive`（每个起点重跑 NFA，O(n²)）对照默认 `pike`（单趟 Pike VM）；两者语义一致由 `tests/test_ablation.py` 保证，评测仅比较周期数。
- naive 仅测较小长度（>2000 时 O(n²) 在 zkVM 内过慢）。
