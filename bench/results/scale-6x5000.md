# 规模化评测：可行域边界（WP1）

- 主机 `autodl-container-14574f97ce-6e5bc639`：16 核 / 92160 MB，Intel(R) Xeon(R) Gold 6459C
- 矩阵：长度 [5000] × 规则 [6] × 证明档 ['core']
- 生成时间：2026-11-01T21:28:57

> **口径（X1e）**：host `autodl-container-14574f97ce-6e5bc639`（cgroup 16 核 / 92160 MB；宿主 128 核 / 754 GiB 仅记录，不作配额）；binary `7f99fdb1…`；policy vkey `0x003eb14d…`；commit `025796b`（binary 构建基线 `e45178b`，**post-NFA-fix**）；单进程串行（`flock /tmp/pop-proof.lock`，一次一个证明）；规则集 6 条 = 1 `length_bound` + 3 `keyword_block` + 2 `pattern_block`；语料 `demo`（166 字符）。
> **本点观察**：157.74 s 被 SIGKILL；`time -v` 在 SIGKILL 下不输出 Max RSS，运行中采样 RSS 67.5 GB（155 s）/ cgroup `memory.current` 94.9 GB（上限 96.6 GB）。

> **隐私模式（public/private）不在本表里**：`pop-script` 没有 `--mode`，公私之别住在会话层，不进 zkVM。见本文件头部说明。

## 边界表

### 证明档 `core`

| 长度 | 6 条规则 |
|---|---|
| 5000 | ✗ 被 SIGKILL 杀（本机内存不足，OOM） |

`✓` 出证成功并通过验证；`✗` 失败（原因照抄）；`·` 没跑到（预算用尽或本档在本机被跳过）。**峰值内存是这一列的主量**，耗时只作参考（`bench/results/proofs.md`：墙上耗时 ±10%、峰值内存 ±1%）。

## 结论

没有任何点成功 —— 这一轮没有可用的结论，见上面的失败原因。

> **6 规则边界（X1e）**：本机 90 GiB cgroup 下，6×3000 core 可行（139.66 s / 48683.9 MB / verified），6×5000 core OOM；补齐了 X1d 的 6×10000/50000 两点，最大可行长度落在 [3000, 5000)。见同目录 `scale-6x2000`、`scale-6x3000`、`scale-6x5000` 三份结果。
