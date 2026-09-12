# bench/ — 评测

六个脚本：前四个覆盖「成本 vs（响应长度 × 规则数 × 匹配模式）」，后两个覆盖
P2-9 的语义规则与 P1-6 的组合证明：

| 脚本 | 测什么 | 用时 | 说明 |
|---|---|---|---|
| `bench_cycles.py` | **zkVM 周期数**（`pop-script --execute`，不出证） | 每点数秒 | 长度 200→100k × 规则数 1–6 的完整矩阵；含两段式成本拟合 |
| `bench_proofs.py` | **证明墙钟时间 + 工件大小 + 峰值内存**（真实 SP1 证明） | 每点 ~90–170s | 每点**独立子进程**；OOM 如实入表（那是结论，不是故障）；`--proof-mode` 可切 core/compressed/groth16/plonk，**结果自带硬件与模式标注** |
| `bench_ablation.py` | **匹配器消融**：pike vs naive 的二次退化 | 每点数秒 | 病理构造（模式 `a+b`、输入 `a`×n）；不可加性与顺序效应见 `bench_cycles.py` 的两条探针 |
| `bench_verify.py` | **验证成本**（冷启动 CLI / vkey setup / 纯验证） | 每次 ~20s | 区分「CLI 冷启动（含构造证明器）」与「纯密码学验证」 |
| `bench_semantic.py` | **ezkl 陪伴证明的成本**（setup / prove / verify） | 真出 ezkl 证明 | **各阶段分进程**跑（叠加会 OOM）；见 `docs/design-semantic-rules.md` §8 |
| `bench_compose.py` | **组合证明的成本**（`pop-program` / `pop-infer` 两半各自 prove/verify + 组合层开销） | 真出两份 SP1 证明 | **两半分进程**跑；逐条检验「成本 ≈ 两者之和、由推理主导」这句假设 |

运行（需先构建 `circuits`，见 `docs/reproduce.md` §2）：

```bash
python3 bench/bench_cycles.py                                  # → bench/results/cycles.{json,md}
SP1_PROVER=cpu python3 bench/bench_proofs.py                    # → bench/results/proofs.{json,md}
SP1_PROVER=cpu python3 bench/bench_proofs.py --points "200,1 2000,1"   # 只补几个点（整串要引号）
SP1_PROVER=cpu python3 bench/bench_proofs.py --proof-mode compressed --points 200,1  # 换模式（本机 OOM）
python3 bench/bench_ablation.py                                 # → bench/results/ablation.{json,md}
SP1_PROVER=cpu python3 bench/bench_verify.py --proof <proof.bin>  # → bench/results/verify.{json,md}
SP1_PROVER=cpu python3 bench/bench_semantic.py                  # → bench/results/semantic.{json,md}
SP1_PROVER=cpu python3 bench/bench_compose.py                   # → bench/results/compose.{json,md}
python3 bench/bench_compose.py --render-only                    # 不出证：由已有 JSON 重渲染 .md
```

结果写入 `bench/results/`（**已入库**，供论文/文档引用）；中间产物 `bench/work/` 被忽略。
**对标**：`bench/comparison_zkagent.md`（vs zkAgent, ePrint 2026/199）。

设计要点：
- **语料**：默认 `--corpus demo`，取自仓库里**真跑出来的**工件（`scripts/examples/out/**`
  的 `response` + 示例回复），按内容去重、**剔掉命中规则的段**（命中 ⇒ 短路 ⇒ 数字不可用），
  长于语料的点由平铺得到 —— 量的因此是扫描成本的**曲线**，不是一段超长真实文本；
- 规则数 `[1, 2, 3, 4, 6]`（**刻意不是 `[1, 3, 6]`**：那三点里 keyword/pattern 两个
  解释变量近似成比例，拟合会给出物理上不成立的负单价）；
- **消融**：`match_mode=naive`（每个起点重跑 NFA，O(n²)）对照默认 `pike`（单趟 Pike VM）；
  两者语义一致由 `tests/test_ablation.py` 保证，评测仅比较周期数。
- **证明侧有内存天花板**：峰值常驻的固定地板 ~10.15 GiB，超出即 OOM。`bench_proofs.py`
  会把失败点如实写进 `rows[].error` 而不是让整轮消失 —— 见 `results/proofs.md` 的边界表。
- **证明数字是「机器 + 模式」的函数**，不是普适常数：耗时随 CPU 走、可行域随内存走，
  `core` 与 `compressed` 之间也不可比。所以 `bench_proofs.py` 把核数/CPU 型号/内存/hostname
  与 `proof_mode` 一并写进 JSON 并在 `.md` 顶部打印 —— 换机器（比如待办 T1 的云机）重跑时，
  请**另存一份 `proofs-cloud*.json`** 并列呈现，别覆盖本机这张表；
  云机 runbook 见 [`../docs/reproduce.md`](../docs/reproduce.md) §4½。
- **多采样点要用引号包住整体**：`--points "200,1 2000,1"`（`--points` 只吃一个参数）。
- naive 仅测较小长度（>2000 时 O(n²) 在 zkVM 内过慢）。
