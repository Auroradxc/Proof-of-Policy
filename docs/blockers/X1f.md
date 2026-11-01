# X1f：6 规则 × 4000/4500 的 core 边界

> **状态**：`done`（2026-11-01）· 主点 **成功**，可选点 4500 **成功**
> **任务**：X1f / 把 6 规则 core 的可行长度上界从 `[3000, 5000)` 收窄
> **分支 / worktree**：`bhv/x1f-6x4000` · `.claude/worktrees/agent-aea8af1adf138585d`
> **基线**：`2c786096cfdb79b597a0af40f06ba46ecfea4fb6`（binary 构建基线 `e45178b`，**post-NFA-fix**）
> **云机**：`connect.bjb2.seetacloud.com:37499`，host `autodl-container-14574f97ce-6e5bc639`
> **结果头**：cgroup **16 核 / 92160 MB**（宿主 128 核 / 772649 MB 仅记录）；
> binary sha256 `7f99fdb11a4a859c45598c384db3b98dd50426210adbc14d6b576c4d15dda49f`；
> policy vkey `0x003eb14de80339bddef2b9207ef27469088267888bb9bebb9836b4ee701fd7be`；
> 规则集 6 条 = 1 `length_bound` + 3 `keyword_block` + 2 `pattern_block`；
> 全部证明一次一个（`flock /tmp/pop-proof.lock`、`SP1_PROVER=cpu`）。

---

## 0. 一句话

- **6×4000 core 可行**：162.37 s / 59,216.5 MB / `verified=True` / `passed=True`。
- **6×4500 core 可行**：181.66 s / 64,224.7 MB / `verified=True` / `passed=True`。
- **6×5000 core 不可行**（X1e：157.74 s 被 SIGKILL）。
- 因此 6 规则的可行上界从 `[3000, 5000)` 收窄为 **`[4500, 5000)`**，
  已证最大可行长度是 **4500**。
- 4500 是在 cgroup 距上限仅 **20,480 B** 时、靠回收 **5.27 GB 文件页缓存**过关的；
  这是一个**依赖页缓存条件**的边界，不是无条件的「4500 总能过」。

方法、逐点采样与读法见 [x1f-6x4000.md](../experiments/x1f-6x4000.md)；
上一轮的 5000 OOM 见 [X1e.md](X1e.md)。

## 1. 结果

| 长度 | 规则 | tier | 结果 | 耗时 | 峰值 RSS | verified | cgroup 峰值 / `memory.events` max 增量 |
|---:|---:|---|---|---:|---:|---|---:|---:|
| 3000 | 6 | core | ✓（X1e） | 139.66 s | 48,683.9 MB | ✓ | 未采样 |
| 4000 | 6 | core | ✓ | 162.37 s | 59,216.5 MB | ✓ | 94.36 GB / +6,647 |
| 4500 | 6 | core | ✓ | 181.66 s | 64,224.7 MB | ✓ | 96.637 GB / +37,185 |
| 5000 | 6 | core | ✗ OOM（SIGKILL，X1e） | 157.74 s | 未得到 | — | 94.9 GB / 0 |

产物：[scale-6x4000.json](../../bench/results/scale-6x4000.json) /
[scale-6x4000.md](../../bench/results/scale-6x4000.md) /
[scale-6x4500.json](../../bench/results/scale-6x4500.json) /
[scale-6x4500.md](../../bench/results/scale-6x4500.md)。JSON `provenance` 与
`.md` 头部均含 host / binary / vkey / commit / post-NFA-fix / 规则集 / 采样条件。

## 2. cgroup、页缓存与 `memory.events`

- **开工前**：4000 前 cgroup `memory.current` 35.41 GB、文件页缓存 31.42 GB；
  4500 前 34.47 GB / 30.48 GB（`memory.max` 均为 96.64 GB = 90 GiB，
  `memory.swap.max=0`）。同一 cgroup 里 E1 的 Qwen 进程约 3.37 GB anon 全程存活，
  GPU 69–88% / 15.2 GiB，HF 缓存 45 GB。**未 drop caches**（会干扰 E1）。
- **4000**：cgroup 峰值 94.36 GB（21:57:37，余量 2.27 GB），进程峰值 RSS
  59,216.5 MB（`time -v`）。约 21:58:35 二次上冲，`memory.events` max
  277,508 → 284,155（**+6,647**），页缓存最低 30.47 GB（约 −0.95 GB）；
  oom=0 / oom_kill=0，正常完成。
- **4500**：cgroup 峰值 **96,636,743,680 B**，`memory.max` 96,636,764,160 B，
  余量 **20,480 B**（22:01:26）；进程峰值 RSS 64,224.7 MB。`memory.events` max
  284,155 → 321,340（**+37,185**），页缓存从 30.48 GB 回收到最低 **25.21 GB**
  （**−5.27 GB**）；oom=0 / oom_kill=0，正常完成。
- `memory.events` 的 `max` 是「撞到上限并尝试回收」的累计计数，**不是 OOM**。
  本轮两次运行都把 max 推高数千到数万次却仍然成功，说明 cgroup 可以贴墙通过
  页缓存回收继续运行。
- 结论对缓存条件敏感：4500 若少了这约 5 GB 可回收页缓存，或 E1 产生更多
  活跃/脏页，就可能像 5000 一样被杀。

## 3. 5000 的 OOM 机制

- X1e 实测：157.74 s 被 SIGKILL；155 s 采样进程 RSS 67.5 GB（非峰值），同刻 cgroup
  94.9/96.6 GB（余量 1.75 GB），149→155 s cgroup 约 +2.72 GB/s；swap=0。
- 本轮补充了「撞墙但不死」的对照：4000/4500 都触发 `memory.events.max` 却靠回收
  页缓存完成。因此 5000 的失败**不是「碰一次上限」的偶发事件**，更像持续 anon
  增长耗尽可回收缓存后仍有分配需求。按 4000→4500 斜率外推，5000 进程峰值约
  69–70 GB，比 4500 再高约 5 GB——接近 4500 已动用的缓存余量（外推不是测量）。
- 容器内 `oom_kill=0` 且 `dmesg_restrict=1`，**无法区分**内核 cgroup OOM 与平台
  外部守卫的 kill；X1e 的证据更支持外部 kill。本轮没有推翻也没有确认这一点。
- 5000 **未重跑**（任务约定），5×1000 也未补测；边界是 500 字符粒度。

## 4. 残余风险与未做

- **4500 的成功余量只有 20 KB**，且依赖约 5.27 GB 页缓存回收；换一个缓存更紧的
  时刻可能翻转。它是「本轮条件下可证」，不是「无条件可证」。
- **4000 的 5 s 原始采样日志被 4500 采样器覆盖**（生成 4500 脚本时输出路径未替换
  干净）；关键采样值已写入 JSON `provenance.sampling` 与实验文档 §3.2，逐行序列
  未保留。4500 原始序列保留在云机，未入库。
- **6×5000 未重跑**；`[4500, 5000)` 中 4750 未测，上界仍是区间。
- 4000/4500 的 **groth16 未跑**：core 已贴墙，groth16 还要叠加约 20 GB 包装开销，
  按协议不进入。
- `time -v` 在 SIGKILL 下不给 Max RSS，5000 没有峰值数字；成功点的峰值以
  `time -v` 为准（MB 实为 MiB）。

## 5. 串行、隔离与 E1

- 两点逐次串行，`flock /tmp/pop-proof.lock`，一次一个证明；独立目录
  `/root/autodl-tmp/zk-policy-x1f`，`pop-script` 软链到共享的
  `/root/autodl-tmp/zk-policy/circuits/target/release/pop-script`（sha256
  `7f99fdb1…`，与 X1e 同一 binary）；未修改 `zk-policy-x1d` / `zk-policy-x1e` /
  `zk-policy-e1`。
- **E1 未受影响**：Qwen CUDA 采样进程全程存活，GPU 69–88%、显存 15.2 GiB；
  本实验只用 CPU、未 kill 任何进程、未碰 GPU、未 drop caches。
- 第一次 4000 启动时外层 shell 在 fork 前挂住（未跑证明），终止后用 `setsid`
  重启；正式计时从 21:56:11 开始。

## 6. 复现

```bash
cd /root/autodl-tmp/zk-policy-x1f
export PATH=/root/miniconda3/bin:$PATH
export SP1_PROVER=cpu GOMAXPROCS=16 RAYON_NUM_THREADS=16
export SP1_WORKER_NUM_CORE_WORKERS=8 SP1_WORKER_NUM_SETUP_WORKERS=8
export SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=16
export SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=16

flock /tmp/pop-proof.lock timeout 900 python3 bench/bench_scale.py \
  --out bench/results/scale-6x4000.json --proof-modes core --lengths 4000 --rules 6
flock /tmp/pop-proof.lock timeout 900 python3 bench/bench_scale.py \
  --out bench/results/scale-6x4500.json --proof-modes core --lengths 4500 --rules 6
```

## 7. 交付清单

| 文件 | 内容 |
|---|---|
| `bench/results/scale-6x4000.{json,md}` | 6×4000 core，1 ✓ |
| `bench/results/scale-6x4500.{json,md}` | 6×4500 core，1 ✓ |
| `docs/experiments/x1f-6x4000.md` | 方法、结果、边界、页缓存与 `memory.events` 读法 |
| `docs/blockers/X1f.md` | 本文件 |

未改 core / cert / paper / circuits；未安装 Rust/SP1；未写密码或云机日志入库；
未 push。
