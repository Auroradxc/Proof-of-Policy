# X1e：6 规则 × 5000 的 core 边界

> **状态**：`done`（2026-11-01）· 主点 **OOM**，补点 2000/3000 均 `verified=True`
> **任务**：X1e / 6 规则 × 5000 core 可行性与 6 规则边界
> **分支 / worktree**：`bhv/x1e-6x5000` · `.claude/worktrees/agent-af0872f6946745951`
> **基线**：`025796b`（binary 构建基线 `e45178b`，**post-NFA-fix**）
> **云机**：`connect.bjb2.seetacloud.com:37499`，host `autodl-container-14574f97ce-6e5bc639`
> **结果头**：cgroup **16 核 / 92160 MB**（宿主 128 核 / 772649 MB 仅记录）；
> binary sha256 `7f99fdb11a4a859c45598c384db3b98dd50426210adbc14d6b576c4d15dda49f`；
> policy vkey `0x003eb14de80339bddef2b9207ef27469088267888bb9bebb9836b4ee701fd7be`；
> 规则集 6 条 = 1 `length_bound` + 3 `keyword_block` + 2 `pattern_block`；
> 全部证明一次一个（`flock /tmp/pop-proof.lock`、`SP1_PROVER=cpu`）。

---

## 0. 一句话

- **6×5000 core 不可行**：157.74 s 被 SIGKILL（OOM），不是超时。
- **6×2000 core 可行**：117.11 s / 36,890.0 MB / `verified=True` / `passed=True`。
- **6×3000 core 可行**：139.66 s / 48,683.9 MB / `verified=True` / `passed=True`。
- 因此 6 规则在本机 90 GiB cgroup 下的最大可行长度**已证到 3000**，
  上界落在 **[3000, 5000)**；补齐了 X1d 的 6×10000/50000 OOM 两点。
- **6×5000 groth16 未跑**：core 不可证就不进入 groth16（协议）。

方法、尺度与读法见 [x1e-6x5000.md](../experiments/x1e-6x5000.md)。

## 1. 结果

| 长度 | 规则 | tier | 结果 | 耗时 | 峰值 RSS | verified |
|---:|---:|---|---|---:|---:|---|
| 2000 | 6 | core | ✓ | 117.11 s | 36,890.0 MB | ✅ |
| 3000 | 6 | core | ✓ | 139.66 s | 48,683.9 MB | ✅ |
| 5000 | 6 | core | ✗ OOM（SIGKILL） | 157.74 s | 未得到 | — |

产物：[scale-6x2000.json](../../bench/results/scale-6x2000.json) /
[scale-6x3000.json](../../bench/results/scale-6x3000.json) /
[scale-6x5000.json](../../bench/results/scale-6x5000.json)（各自 `.md` 为渲染视图，
头部含 host/binary/vkey/commit/规则集口径）。

## 2. OOM 原因

- **「RSS 67.5 GB 距 96.6 GB 还有 29 GB」是口径错觉**：67.5 GB 是 155 s 的
  `ps rss` 采样（非峰值），而同一时刻 cgroup `memory.current` 已是 **94.9 GB**，
  离 `memory.max` 96.6 GB 只剩 **1.75 GB**。
- 那 ~29 GB 差额已被同一 cgroup 的其他账目占掉：E1 的 Qwen 进程 ~3.4 GB anon、
  其它容器进程 ~0.3 GB、slab/shmem ~1.6 GB、**文件页缓存 ~22 GB**（HF 缓存 45 GB：
  Qwen 15 GB + 正在下载的 Mistral 31 GB）。
- 149→155 s，cgroup 从 78.6 GB 涨到 94.9 GB（**+2.72 GB/s**），1.75 GB 余量理论上
  **0.6 s** 耗尽；靠页缓存回收又撑了 2.7 s 才被杀。`memory.swap.max = 0`，anon 不可换出。
- **不是超时**：`timeout 900` 远未到。
- **SIGKILL 来源无法在容器内定论**：`memory.events` 为 `max 277508 / oom 0 /
  oom_kill 0`，`dmesg_restrict=1` 读不到内核日志。内核 cgroup OOM 没有留下足迹，
  现有证据更支持**容器外的平台内存守卫/上层 cgroup** 在 ~95–98% 配额时 kill；
  也可能是别人 `kill -9`（仓库 `policydsl/runtime/service.py` 同口径）。
- **不是 SP1 的 memory monitor**：它只对 executor 子进程按 `MEMORY_LIMIT`（默认
  24 GB）杀，并以 `KilledByMemoryMonitor` 错误返回；顶层 prover 无此机制。
- `time -v` 在 SIGKILL 下不打印 Max RSS，故 5000 无峰值内存数字；67.5 GB 是运行中
  采样值。完整分解见实验文档 §3.2。

## 3. 边界

- 2000 → 3000 峰值内存 +11.8 GB / +1000 字符（36.9 → 48.7 GB），成本随长度陡增；
  4000 未测（补充点按协议上限两个），所以上界是区间 `[3000, 5000)`。
- 与 X1d 对照：6×10000 / 6×50000 均在 ~100 s 被杀；5000 撑到 157.74 s。
  「长度不是 10000 与 50000 之间的主变量」这一句**不能**外推到 5000。

## 4. 串行、隔离与 E1

- 三点逐次串行，独立目录 `/root/autodl-tmp/zk-policy-x1e`，`pop-script` 软链到共享
  release binary；未修改 `zk-policy-x1d` / `zk-policy-e1`。
- **E1 未受影响**：E1 的 Qwen CUDA 采样进程全程存活，GPU 72–80% / 显存 15.2 GiB；
  本实验只用 CPU、未 kill 任何进程、未碰 GPU。开工前 X1d 遗留的一个 core 证明进程
  自行结束（非本实验 kill）。

## 5. 复现

```bash
cd /root/autodl-tmp/zk-policy-x1e
export PATH=/root/miniconda3/bin:$PATH
export SP1_PROVER=cpu GOMAXPROCS=16 RAYON_NUM_THREADS=16
export SP1_WORKER_NUM_CORE_WORKERS=8 SP1_WORKER_NUM_SETUP_WORKERS=8
export SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=16
export SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=16

flock /tmp/pop-proof.lock timeout 900 python3 bench/bench_scale.py \
  --out bench/results/scale-6x5000.json --proof-modes core --lengths 5000 --rules 6
flock /tmp/pop-proof.lock timeout 900 python3 bench/bench_scale.py \
  --out bench/results/scale-6x2000.json --proof-modes core --lengths 2000 --rules 6
flock /tmp/pop-proof.lock timeout 900 python3 bench/bench_scale.py \
  --out bench/results/scale-6x3000.json --proof-modes core --lengths 3000 --rules 6
```

## 6. 交付清单

| 文件 | 内容 |
|---|---|
| `bench/results/scale-6x5000.{json,md}` | 6×5000 core，1 ✗ OOM |
| `bench/results/scale-6x2000.{json,md}` | 6×2000 core，1 ✓ |
| `bench/results/scale-6x3000.{json,md}` | 6×3000 core，1 ✓ |
| `docs/experiments/x1e-6x5000.md` | 方法、结果、边界与 OOM 读法 |
| `docs/blockers/X1e.md` | 本文件 |

未改 core / cert / paper / circuits；未安装 Rust/SP1；未写密码或云机日志入库；
未 push。
