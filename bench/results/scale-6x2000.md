# 规模化评测：可行域边界（WP1）

- 主机 `autodl-container-14574f97ce-6e5bc639`：16 核 / 92160 MB，Intel(R) Xeon(R) Gold 6459C
- 矩阵：长度 [2000] × 规则 [6] × 证明档 ['core']
- 生成时间：2026-11-01T21:31:30

> **口径（X1e）**：host `autodl-container-14574f97ce-6e5bc639`（cgroup 16 核 / 92160 MB；宿主 128 核 / 754 GiB 仅记录，不作配额）；binary `7f99fdb1…`；policy vkey `0x003eb14d…`；commit `025796b`（binary 构建基线 `e45178b`，**post-NFA-fix**）；单进程串行（`flock /tmp/pop-proof.lock`，一次一个证明）；规则集 6 条 = 1 `length_bound` + 3 `keyword_block` + 2 `pattern_block`；语料 `demo`（166 字符）。

> **隐私模式（public/private）不在本表里**：`pop-script` 没有 `--mode`，公私之别住在会话层，不进 zkVM。见本文件头部说明。

## 边界表

### 证明档 `core`

| 长度 | 6 条规则 |
|---|---|
| 2000 | ✓ 117.11s / 36890.0 MB |

`✓` 出证成功并通过验证；`✗` 失败（原因照抄）；`·` 没跑到（预算用尽或本档在本机被跳过）。**峰值内存是这一列的主量**，耗时只作参考（`bench/results/proofs.md`：墙上耗时 ±10%、峰值内存 ±1%）。

## 结论

本轮成功 1 个点。**可行域不是矩形**：「最大规则数 × 最大长度」这个组合不一定成功，下面按长度/规则两个方向分别报。 `core`：按长度看最大成功规则数 2000→6；按规则看最大成功长度 6→2000。 成功点的峰值常驻在 36890–36890 MB 之间。

> **6 规则边界（X1e）**：本机 90 GiB cgroup 下，6×3000 core 可行（139.66 s / 48683.9 MB / verified），6×5000 core OOM；补齐了 X1d 的 6×10000/50000 两点，最大可行长度落在 [3000, 5000)。见同目录 `scale-6x2000`、`scale-6x3000`、`scale-6x5000` 三份结果。
