# 规模化评测：可行域边界（WP1）

- 主机 `autodl-container-14574f97ce-6e5bc639`：16 核 / 92160 MB，Intel(R) Xeon(R) Gold 6459C
- 矩阵：长度 [10000, 50000] × 规则 [6] × 证明档 ['core']
- 生成时间：2026-11-01T20:46:31

> **口径（X1d）**：host `autodl-container-14574f97ce-6e5bc639`（cgroup 16 核 / 92160 MB；宿主 128 核 / 754 GiB 仅记录，不作配额）；binary `7f99fdb1…`；policy vkey `0x003eb14d…`；commit `cf7bb54`（binary 构建基线 `e45178b`，**post-NFA-fix**）；单进程串行（`flock /tmp/pop-proof.lock`，一次一个证明）；语料 `demo`（166 字符）。**6 规则 groth16 未跑**：同点 core 已 OOM，没有可包装的 core 成功点。

> **隐私模式（public/private）不在本表里**：`pop-script` 没有 `--mode`，公私之别住在会话层，不进 zkVM。见本文件头部说明。

## 边界表

### 证明档 `core`

| 长度 | 6 条规则 |
|---|---|
| 10000 | ✗ 被 SIGKILL 杀（本机内存不足，OOM） |
| 50000 | ✗ 被 SIGKILL 杀（本机内存不足，OOM） |

`✓` 出证成功并通过验证；`✗` 失败（原因照抄）；`·` 没跑到（预算用尽或本档在本机被跳过）。**峰值内存是这一列的主量**，耗时只作参考（`bench/results/proofs.md`：墙上耗时 ±10%、峰值内存 ±1%）。

## 结论

没有任何点成功 —— 这一轮没有可用的结论，见上面的失败原因。

## 读法（X1d 补充）

- 两个点都是 **SIGKILL（OOM）**，不是超时：`10000×6` 在 101.09 s、`50000×6` 在 99.82 s 被杀。
- 6 条规则 = 1 条 `length_bound` + 3 条 `keyword_block` + 2 条 `pattern_block`（`bench_cycles.make_policy`）。X1c 已量到 3 规则 × 10000 在本机 90 GiB 下同样 OOM；本轮把规则数翻倍后，**10000 与 50000 都在同一 ~100 s 内存墙处被内核杀死**，长度不是本轮的主变量。
- 因此 6 规则 groth16（需要再叠加 ~20 GB 包装开销）**没有尝试**：按 X1d 协议，core 不可证就不进 groth16。这不是「groth16 不行」，而是「core 在这一格先撞墙」。
