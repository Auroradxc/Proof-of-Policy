# 规模化评测：可行域边界（WP1）

- 主机 `autodl-container-14574f97ce-6e5bc639`：16 核 / 92160 MB，Intel(R) Xeon(R) Gold 6459C
- 矩阵：长度 [4000] × 规则 [6] × 证明档 ['core']
- 生成时间：2026-11-01T21:59:13

> **口径（X1f）**：host `autodl-container-14574f97ce-6e5bc639`（cgroup 16 核 / 92160 MB；宿主 128 核 / 772649 MB 仅记录，不作配额）；binary `7f99fdb1…`；policy vkey `0x003eb14d…`；commit `2c78609`（binary 构建基线 `e45178b`，**post-NFA-fix**）；单进程串行（`flock /tmp/pop-proof.lock`，一次一个证明）；规则集 6 条 = 1 `length_bound` + 3 `keyword_block` + 2 `pattern_block`（pike）；语料 `demo`（166 字符）。完整读法见 [x1f-6x4000.md](../../docs/experiments/x1f-6x4000.md)。
> **本点内存条件（X1f）**：开工前 cgroup `memory.current` 35.41 GB / `memory.max` 96.64 GB，文件页缓存 31.42 GB；E1 的 Qwen 进程（3.38 GB anon）全程存活、GPU 71–88%、HF 页缓存 45 GB，未 drop caches。运行中 cgroup 峰值 94.36 GB（21:57:37，余量 2.27 GB），进程峰值 RSS 59,216.5 MB（`time -v`）。`memory.events` max 277,508 → 284,155（+6,647 次触顶回收），oom=0 / oom_kill=0；页缓存最低 30.47 GB。**成功**：162.37 s、`verified=True`、`passed=True`。

> **隐私模式（public/private）不在本表里**：`pop-script` 没有 `--mode`，公私之别住在会话层，不进 zkVM。见本文件头部说明。

## 边界表

### 证明档 `core`

| 长度 | 6 条规则 |
|---|---|
| 4000 | ✓ 162.37s / 59216.5 MB |

`✓` 出证成功并通过验证；`✗` 失败（原因照抄）；`·` 没跑到（预算用尽或本档在本机被跳过）。**峰值内存是这一列的主量**，耗时只作参考（`bench/results/proofs.md`：墙上耗时 ±10%、峰值内存 ±1%）。

## 结论

本轮成功 1 个点。**可行域不是矩形**：「最大规则数 × 最大长度」这个组合不一定成功，下面按长度/规则两个方向分别报。 `core`：按长度看最大成功规则数 4000→6；按规则看最大成功长度 6→4000。 成功点的峰值常驻在 59216–59216 MB 之间。
