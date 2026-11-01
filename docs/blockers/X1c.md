# X1c：云机 groth16 探针、多核调参与矩阵

> **状态**：`done`（2026-11-01）· groth16 首点 `verified=True`
> **任务**：X1c / 云机 groth16 owner（P0-06 / P0-07 / P0-08）
> **分支 / worktree**：`bhv/x1c-groth16` · `.claude/worktrees/agent-aec8fc1db2da5a449`
> **基线**：`e45178b`
> **云机**：`connect.bjb2.seetacloud.com:37499`，host `autodl-container-14574f97ce-6e5bc639`
> **结果头（口径）**：host **16 核 / 90 GiB（cgroup；`/proc/meminfo` 报宿主 754 GiB）**；
> binary `7f99fdb11a4a859c45598c384db3b98dd50426210adbc14d6b576c4d15dda49f`；
> 构建基线 commit `e45178b`；**post-NFA-fix**；
> policy vkey `0x003eb14de80339bddef2b9207ef27469088267888bb9bebb9836b4ee701fd7be`；
> 除显式标注的并发外，全部为**单进程（isolated）**口径。

---

## 0. 一句话

云机上 groth16 第一个可信点：**L=200 / R=1，297.3 s，峰值 30.2 GiB，`verified=True`**。
之前所有 groth16 “卡死”的根因**不是 prover 死锁**，而是 SP1 首次 setup 工件
`v6.1.0-groth16.tar.gz`（**5.79 GiB**）的 S3 单连接下载（实测 ~20 KB/s，需 86 小时量级）。
用 256 路 Range 并行把下载提到 **6.7 MB/s**（约 14 分钟）并手工播种缓存后，groth16 才第一次跑通。

在这条通路打通后：

- **A/B/C 三组调参全部 `verified=True`**（290–299 s / 29.6–30.2 GiB），差异在噪声内；
- **矩阵 18 点 = 16 ✓ / 2 OOM**（`10000×3` 的 core 与 groth16 都被 SIGKILL），用时 54.5 min；
- **隐私面 core 与 groth16 都 `ok`**：groth16 证明 2,132 B、`wrapper-only`，
  两档 canary 在证明中均为 0；
- X2 的 GPU 任务全程未受影响（GPU 80–88%、显存 15.2 GiB）。

---

## 1. 根因：卡在工件下载，不是出证

### 1.1 现象

接管时在跑的 tuned probe（PIDs 42476–42482）在 `L=200 / R=1 / groth16` 上：

- 前 ~4 分钟 CPU 时间正常增长到 **3241 s**（约 13 核，STARK 证明阶段）；
- 之后 CPU 时间**完全停涨**（60 s 内 +4 ticks），VmRSS 稳定在 9.1 GiB，42 个线程全部
  `futex_wait_queue_me` / `ep_poll`；
- `timeout 1800` 还没到，但按 CPU-stall watchdog 判据（5 分钟不增长）已应介入。

### 1.2 证据链（不是猜测）

```text
/proc/42482/fd/9  -> /root/.sp1/circuits/groth16/v6.1.0.incomplete.4SOoLF/artifacts.tar.gz
/proc/42482/fd/10 -> TCP 172.17.0.9:39316 -> 3.5.130.31:443  ESTABLISHED（AWS S3）
partial size: 20 KB/s 稳定增长（7,310,927 B 时被杀）
```

- `sp1-prover-6.7.0/src/build.rs` 的 release 路径：
  `try_install_circuit_artifacts("groth16")` →
  `https://sp1-circuits.s3-us-east-2.amazonaws.com/{SP1_CIRCUIT_VERSION}-groth16.tar.gz`
  （`SP1_CIRCUIT_VERSION = v6.1.0`），**单连接、无断点续传、无超时**；
- `curl -I` 该 URL：**Content-Length = 6,211,807,514 B（5.79 GiB）**；
- 云机历史缓存里还有 4 个 `v6.1.0.incomplete.*` 目录（16:55 / 17:05 / 17:22 / 18:17，
  分别 8.9 / 9.6 / 16.0 / 7.3 MB）——正是之前几次 groth16 尝试被杀留下的**部分下载**。

> **结论**：之前“默认参数 groth16 卡死、CPU 20 分钟不增长”是**下载等待**，
> 与 `SP1_WORKER_*` 旋钮无关。A 组（默认 workers）在本轮热缓存下 299 s 跑通，
> 直接反证了这一点。

### 1.3 解决：并行 Range 下载 + 手工播种缓存

- 256 路并发、8 MiB/块（741 块），`curl -r` + `--speed-limit 1024 --speed-time 60`
  防单块假死，逐块 size 校验、最多 30 次重试；
- 实测并行度—带宽（12 s 采样）：16 / 32 / 64 / 128 / 256 路 =
  **0.44 / 0.79 / 1.85 / 3.88 / 6.67 MB/s**（单连接仅 20–54 KB/s）；
- 全量下载结果：`concat size = 6,211,807,514` **精确匹配**、`gzip -t` **OK**、0 错误；
  解压 37.7 s → 7.9 GB（`groth16_pk.bin` 5.86 GB、`groth16_circuit.bin` 2.44 GB）；
- 缓存放在数据盘而非 overlay（后者仅 17 GB 空闲）：
  `/root/autodl-tmp/sp1-cache/groth16/v6.1.0`，写入 `.complete` 标记；
  进程用 `SP1_GROTH16_CIRCUIT_PATH=/root/autodl-tmp/sp1-cache/groth16` 指向它
  （**证明与验证同一个 env**，否则 verify 会另找缓存）。
- 播种后首个 groth16 点 297 s（STARK ~4 min + gnark wrap），不再触发下载。

---

## 2. 探针与调参 A/B/C（单进程，L=200 / R=1 / groth16）

三组都带 900 s timeout + 5 分钟 CPU-stall watchdog；每组一个独立 `--out`。

| 组 | SP1 workers（除 `GOMAXPROCS=16` 外） | 耗时 | 峰值 RSS | verified |
|---|---|---|---|---|
| **A** | 默认（不设 `SP1_WORKER_*` / `RAYON_NUM_THREADS`） | 299.1 s | 29,613.8 MB | ✅ |
| **B** | `CORE=4 SETUP=4 REC_EXEC=8 REC_PROVER=8` + `RAYON_NUM_THREADS=16` | 290.0 s | 29,653.5 MB | ✅ |
| **C** | `CORE=8 SETUP=8 REC_EXEC=16 REC_PROVER=16 PREPARE_REDUCE=16` + `RAYON=16` | 297.3 s | 30,248.9 MB | ✅ |

读法：

- 三组墙钟差 **±3%**、峰值差 **±2%**，都在本仓已记录的 ±10% / ±1–2% 复现误差内；
  即在这台 16 核机器上，**这些旋钮对这个点没有可见影响**。
- A 组（默认 workers）**没有卡死**，与 §1 的根因判断一致。
- 峰值 ~30 GiB 远高于 STARK 的 ~10.5 GiB 地板：groth16 要额外载入 5.86 GB 的
  `groth16_pk.bin` 并做外层 MSM。**90 GiB cgroup 下单点余量约 60 GiB**。
- 因为单进程已能把 16 核用到 ~13 核（前 4 分钟 3241 s CPU / 250 s ≈ 13.0 核），
  且矩阵单进程实测只需 54.5 min（预算 300 min），**矩阵采用单进程（isolated）**，
  未用并发口径 —— 并发只会污染 30 GB 级的峰值读数，而吞吐上并不需要。

原始文件：`scale-probe-tuned.{json,md}`（C）、`scale-ab-A.{json,md}`、`scale-ab-B.{json,md}`。

---

## 3. P0-06 / P0-08 矩阵（`scale-cloud.{json,md}`）

命令（单进程，C 配置）：

```bash
SP1_PROVER=cpu GOMAXPROCS=16 RAYON_NUM_THREADS=16 \
SP1_WORKER_NUM_CORE_WORKERS=8 SP1_WORKER_NUM_SETUP_WORKERS=8 \
SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=16 \
SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=16 \
SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS=16 \
SP1_GROTH16_CIRCUIT_PATH=/root/autodl-tmp/sp1-cache/groth16 \
python3 bench/bench_scale.py --out bench/results/scale-cloud.json \
  --proof-modes core,groth16 --lengths 200,2000,10000 --rules 1,2,3 --budget-min 300
```

### 3.1 运行事实

- 起止 **19:29:04 → 20:23:34（54.5 min）**，`EXIT=0`、watchdog `killed=None`；
  未用满 `--budget-min 300`（54.5/300 min）。
- **18 点 = 16 ✓ / 2 ✗**；两个失败点都是 **SIGKILL OOM**，如实保留：
  - `core 10000×3`：92.87 s 被内核杀；
  - `groth16 10000×3`：90.33 s 被内核杀。
- 所有成功点 `verified=True` 且 `passed=True`（语料未短路）。

### 3.2 core（9 点）

| 长度 | 1 条规则 | 2 条规则 | 3 条规则 |
|---|---|---|---|
| 200 | ✓ 40.46 s / 10,466.1 MB | ✓ 40.82 s / 10,584.6 MB | ✓ 50.72 s / 13,011.6 MB |
| 2000 | ✓ 39.83 s / 10,814.6 MB | ✓ 40.41 s / 10,856.1 MB | ✓ 100.3 s / 34,717.6 MB |
| 10000 | ✓ 48.07 s / 12,271.0 MB | ✓ 49.58 s / 12,912.8 MB | ✗ OOM（92.87 s） |

### 3.3 groth16（9 点）

| 长度 | 1 条规则 | 2 条规则 | 3 条规则 |
|---|---|---|---|
| 200 | ✓ 288.28 s / 30,128.3 MB | ✓ 295.90 s / 29,764.4 MB | ✓ 289.03 s / 30,713.5 MB |
| 2000 | ✓ 279.34 s / 29,700.2 MB | ✓ 284.12 s / 30,149.1 MB | ✓ 343.75 s / 35,120.0 MB |
| 10000 | ✓ 284.07 s / 31,061.3 MB | ✓ 290.51 s / 30,626.5 MB | ✗ OOM（90.33 s） |

### 3.4 读法（不要把边界读成矩形）

1. **core 地板 ~10.5 GB**（200×1 就 10,466 MB），与长度/规则近似无关；
   但 **2000×3 跳到 34.7 GB**——第 3 条规则（`pattern_block`）激活另一族正则 AIR
   chip，与本机 `bench/results/proofs.md` 记录的“2→3 条规则断崖”一致。
   `10000×3` 直接撞破 90 GiB cgroup（OOM）。
2. **groth16 全点 29.7–35.1 GB**：它并不等于“core 峰值 + 5.86 GB pk”的简单相加，
   因为 STARK 阶段与 gnark 包装阶段的内存峰不同时出现；实测额外常驻约 **+20 GB**。
3. **groth16 墙钟 279–344 s**，对长度不敏感：STARK 部分本身只有 40–50 s，
   大头是外层 groth16 证明（5.86 GB pk 载入 + 外层 MSM）。
4. **可行域不是矩形**：成功的组合是 `{200,2000,10000}×{1,2} ∪ {200,2000}×{3}`；
   `10000×3` 两档都 OOM。`scale-cloud.md` 的自动结论句
   “已量到的可行域到 3 条规则 × 10000 字符为止”是渲染器**按轴取最大值**得到的，
   **不代表 `3 条规则 × 10000 字符` 这个组合可行**；以 §3.2/§3.3 的表为准。
5. 2 条规则在 3 个长度上都轻松通过（core ≤ 12.9 GB，groth16 ≤ 30.6 GB），
   3 条规则才是墙；这与仓库已有结论（3 条 OOM，`pattern_block`）一致。

原始文件：`scale-cloud.{json,md}`。

---

## 4. P0-07 隐私面（`privacy_surface.{json,md}`）

命令（C 配置 + 热缓存；`--work-dir` 指到数据盘，避免把工件写进仓库）：

```bash
SP1_PROVER=cpu GOMAXPROCS=16 RAYON_NUM_THREADS=16 \
SP1_WORKER_NUM_CORE_WORKERS=8 SP1_WORKER_NUM_SETUP_WORKERS=8 \
SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=16 \
SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=16 \
SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS=16 \
SP1_GROTH16_CIRCUIT_PATH=/root/autodl-tmp/sp1-cache/groth16 \
python3 bench/bench_privacy_surface.py --tiers core,groth16 \
  --timeout 3600 --out-dir bench/results --work-dir /root/autodl-tmp/privacy-work
```

结果（`privacy_surface.{json,md}`，canary `POP_PRIVACY_CANARY_7f3a9c`）：

| tier | status | hiding | proof 大小 | canary 在文本 | canary 在证明 | 响应在交付物 |
|---|---|---|---:|---|---|---|
| core | ok | none | 2,793,788 B（2.66 MiB） | 0 | 0 | 0 |
| groth16 | ok | wrapper-only | **2,132 B** | 0 | 0 | 0 |

判据与读法（与脚本头部一致）：

- **负结果只是“这组探针没找到”，不是零知识证明**。`core` 的 `proof_hiding=none`
  是设计事实（STARK trace 开值可见）；本轮 canary 没命中交付物，不改变该性质。
- groth16 的 `wrapper-only` 是包装器层面的隐藏声明（非后量子）；证明从 core 的
  2.66 MiB 压到 **2,132 B**，符合它只交付 5 个公开输入的形态。
- `response_commitment = ca2b5341…` 在两档相同，且等于 `sha256(T)` —— 它是**公开、
  可离线重算的猜测-验证 oracle，设计如此**，不是泄露。
- 响应 `T` 只出现在 `vectors.json`（出证方私有输入），**不在交付物**；这是本脚本
  区分 `response_in_delivered` 与 `response_in_prover_inputs` 的原因。
- `re_execution.status=skipped`：重执行攻击需要真实模型，归 X2/E2，不在本轮。

---

## 5. X2 是否受影响

**没有。** 全程只做 CPU 证明与下载：

- 未 kill、未抢占 X2 的任何进程；未碰 `bench_k_entropy` / GPU；
- 矩阵与 probe 期间 GPU 利用率保持 **80–88%**、显存 **15.2 GiB**（X2 进程
  PID 由 39003 变为 54878，是 X2 自身重启，本任务未介入）；本任务结束后最终检查
  GPU 为 **0% / 0 MiB**（X2 已自行结束或重启，本任务未向 GPU 发过任何命令，
  也未 kill 过 X2 的任何进程）；
- 内存：本任务单点峰值 ≤ 34.7 GB（core `2000×3`）/ 30.2 GB（groth16），
  均在 90 GiB cgroup 内，未触发 cgroup OOM 之外的系统级挤兑。

---

## 6. 口径与 caveats（读表前必须知道）

1. **旧文档的“云机仍是 pre-NFA-fix binary”已过时**：
   `docs/paper-inputs/bhv-v1-b1.md` §3 / `docs/plan-m2-m6.md` 写的是旧云机 binary
   `b81e6d07…` + 旧 vkey `0x0091b406…`。本轮实测云机 binary sha256 为
   `7f99fdb1…`、policy vkey `0x003eb14d…`，即 **post-NFA-fix**（与
   `docs/paper-inputs/bhv-v1-b1.md` §5 的表一致）。本文件的结果**只进新口径**，
   不得与 pre-fix 表并列。
2. **数据库/缓存是手工播种的**：`SP1_GROTH16_CIRCUIT_PATH` 指向
   `/root/autodl-tmp/sp1-cache/groth16`，是本次为绕开 20 KB/s 下载而加的 env；
   它不改变证明语义，只改变工件位置。工件本身是官方
   `v6.1.0-groth16.tar.gz`（size + gzip 校验通过）。
3. **旋钮不在 row 里**：`bench_scale.py` 调用 `run_point` 时没有传 `extra_env`，
   所以 A/B/C 的 `SP1_WORKER_*` **不会进 JSON 的 `knobs` 字段**（行里是 `{}`）。
   本文件 §2 的表就是这三组 env 的权威记录；不要把 A/B/C 的行当成默认配置。
4. **host 以 cgroup 为准**：`bench_proofs.host_info()` 记录 `cpu_count=16`、
   `mem_total_mb=92160`（cgroup），并同时保留 `mem_total_proc_mb=772649`（宿主
   754 GiB）与 `mem_source=cgroup`，可直接审计。
5. **云机 repo 是共享 checkout**：HEAD 为 `14ed953`（非 `e45178b`），但三个 bench
   脚本的 sha256 与本地 `e45178b` 逐字节一致（`bench_scale.py` `a449f8…`、
   `bench_proofs.py` `37746a…`、`bench_privacy_surface.py` `b6ead9…`）。
6. **单进程、串行出证**：所有矩阵点都是 `bench_scale` 的“每点一个独立 pop-script”
   路径；没有同机并行两个证明。唯一的并行是 §1.3 的 **HTTP Range 下载**（非出证）。

---

## 7. 复现清单

```bash
# 1) 预热 SP1 groth16 工件（云机；256 路 Range，约 14 分钟）
/root/autodl-tmp/dl-sp1-artifacts.sh          # 分块下载 + 拼接 + gzip -t
DEST=/root/autodl-tmp/sp1-cache/groth16/v6.1.0
mkdir -p "$DEST" && tar -xzf /root/autodl-tmp/sp1dl/v6.1.0-groth16.tar.gz -C "$DEST"
touch "$DEST/.complete"
export SP1_GROTH16_CIRCUIT_PATH=/root/autodl-tmp/sp1-cache/groth16

# 2) 探针 / A/B（每组一个 --out）
SP1_PROVER=cpu GOMAXPROCS=16 python3 bench/bench_scale.py --out bench/results/scale-ab-A.json \
  --proof-modes groth16 --lengths 200 --rules 1

# 3) 矩阵（§3 命令）
# 4) 隐私面
SP1_PROVER=cpu python3 bench/bench_privacy_surface.py --tiers core,groth16 \
  --timeout 3600 --out-dir bench/results --work-dir /root/autodl-tmp/privacy-work
```

（`dl-sp1-artifacts.sh` 是本次临时脚本，放在云机 `/root/autodl-tmp`，未入库；
其逻辑见 §1.3。）

---

## 8. 交付清单（本分支新增，仅 `bench/results/*` 与本文件）

| 文件 | 内容 | 口径 |
|---|---|---|
| `bench/results/scale-probe-tuned.{json,md}` | C 配置 groth16 首点 | 单进程 · `verified=True` |
| `bench/results/scale-ab-A.{json,md}` | A 组（默认 SP1 workers） | 单进程 |
| `bench/results/scale-ab-B.{json,md}` | B 组（4/4/8/8） | 单进程 |
| `bench/results/scale-cloud.{json,md}` | 3 长度 × 3 规则 × 2 档，18 点 | 单进程 · 16 ✓ / 2 OOM |
| `bench/results/privacy_surface.{json,md}` | P0-07 隐私面（core / groth16） | 单进程 |

（同名 `.log` 也会随 rsync 拉回本地，但仓库 `.gitignore` 有 `*.log`，不入库。）

每份 `.json` 的顶层都有 `provenance` 字段，写入：binary sha256、policy vkey、
commit `e45178b`、`post_nfa_fix=true`、`concurrency=isolated`、该组的 SP1 旋钮、
工件缓存路径与校验说明。`.md` 仍是 `.json` 的渲染结果（渲染器不读 `provenance`，
只读 `host/axes/generated_at/rows`，所以视图不变；重渲染只会刷新 `generated_at`）。
