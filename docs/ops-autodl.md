# AutoDL 云机 runbook：X1 出证窗口怎么租、怎么开机、怎么跑

> **状态：新增（2026-11-01）。** 本文只回答一类问题：**在 AutoDL 上把 X1
> （P0-06 / P0-07 / P0-08）跑完，一共要买什么、开几次机、每步敲什么。**
>
> 三件事**不在**本文范围，别在这里找：
> - 通用安装清单 → [`../scripts/ops/provision_cloud.sh`](../scripts/ops/provision_cloud.sh)
> - 三阶段跑法与判据 → [`runbook-wave2.md`](runbook-wave2.md) §2
> - 跨机口径（云机数字不能和本机并列）→ [`reproduce.md`](reproduce.md) §4½
>
> **一句话**：AutoDL 上没有「纯 CPU 大内存」这个货 —— **无卡模式只有 0.5 核 / 2 GB**，
> 跑不了出证。你租的是 GPU 实例，**GPU 全程闲置**（`SP1_PROVER=cpu`），买的其实是
> 随卡附带的 CPU 与内存。按本文的两次开机跑法，**总花费在 ¥50–100 量级**。

---

## 0. 三个事实决定了整份 runbook 的形状

这一节不是背景介绍，是后面每一条建议的**依据**。读之前先认下它们：

**① 无卡模式救不了这个任务。** 官方文档口径是 `0.5 核 / 2 GB / ¥0.1 每
小时`。这个配置连 `cargo build` 都跑不动，更别说 prove。它的正确用途只有一个：
**传数据、改代码、看日志**。所以「先开无卡模式省钱地准备环境」在本任务上不成立 ——
编译和出证都必须在大机器上做，**编译时间也计费**。

**② CPU 与内存是按 GPU 数量比例给的。** 官方说明：「算力市场显示的 CPU 和内存均为
每 GPU 分配的 CPU 和内存」。1×4090 常见是 ~16 核 / ~60 GB，但也有 **12 核 / 90 GB**
的地区（§1.1）—— 同一张卡在不同可用区的资源配比并不同。2 张就翻倍。
⇒ **想要 ≥64 GiB 内存，先看「每GPU分配-内存」那一栏**；凑不到才需要选 2 张卡。

**③ 超内存不是变慢，是被 SIGKILL。** 官方原话是「超出分配内存进程会被系统 Kill
导致程序中断」。这个仓库的所有实测都建立在这个失败模式上
（[`../bench/results/proofs.md`](../bench/results/proofs.md)：12 GB 上 `(200,3)` 死在第 57 秒）。
⇒ 内存必须**一次配够**，不能指望 swap。

---

## 1. 选型：买哪一档

### 1.1 结论

| 配置 | 单价（约） | CPU / 内存 | 判定 |
|---|---:|---|---|
| 无卡模式 | ¥0.1/h | 0.5 核 / 2 GB | ❌ 只能传数据 |
| **1×RTX 4090（西北B区：12 核 / 90 GB）** | **¥1.88/h** | **12 核 / 90 GB** | ✅ **首选**：单卡就过 64 GiB 闸门（2026-11-01 实测见到的机型） |
| 1×RTX 4090D | ¥1.88/h | ~16 核 / ~60 GB | ⚠️ 内存卡在 64 GiB 闸门下，`groth16` 会被 `preflight_mode` 直接跳过 |
| 2×RTX 4090D / 4090 | ≈¥3.8/h | ~24–32 核 / ~120–180 GB | 只有单卡墙钟不可接受时才上；**换机 = 换表**（见 §2 开头） |
| 1×A100 80G | ¥5–7/h | 16–32 核 / 80–128 GB | 内存够，单价更高，不划算 |

> ⚠️ 单价与每卡资源**随可用区浮动**，以算力市场当时显示为准。同一个「RTX 4090」
> 在不同可用区可能是 16 核/60 GB、12 核/90 GB 或别的组合 —— **下单前先看那一栏**。
>
> **GPU 型号对本任务是纯粹的噪声。** 你买的是「每GPU分配-内存 + CPU」，不是算力：
> 任何给到 ≥64 GB 内存的卡都一样用，哪怕它是更便宜的 3090 或 2080Ti。
> ⇒ 在算力市场里**按「每GPU分配-内存」列筛，再比单价**，不要从 GPU 型号开始挑。

### 1.2 为什么 12 核不算少

**核数不是瓶颈，单核频率才是。** 两条都要说清，否则「12 核 vs 32 核」会被误判成致命差距：

- SP1 core prover 的默认 `NUM_CORE_WORKERS=4`（见 [`../bench/results/prover_knobs.md`](../bench/results/prover_knobs.md)），
  本机 24 线程也只用得到 4–8 个线程 —— **12 核已经能把这些 worker 铺满**。
- 但 8352V 是 **2.1 GHz 的 Cascade Lake**，本机 i7-14650HX 是 5 GHz 的 P 核。而固定开销
  （setup / splicing / 递归段）里有相当一部分是**单线程**的 ⇒ 同一个点在这台机器上
  可能比本机实测**慢 1.5–2×**。
- 墙钟本来就由固定开销主导：本机 200 字符 123 s、10k 字符 172 s —— **差 50 秒换 50 倍输入**。
  所以买更多核买不到等比例的时间，买更快的单核才买得到。

⇒ 探测点必须**同时**量 `peak_rss_mb` 与那一次的墙钟，两个数一起决定第二次买几张卡（§2.6）。

### 1.3 为什么是 64 GiB 而不是 128 GiB

`bench_scale.py` 的 `MODE_MIN_MEM_MB` 把 `groth16` 定在 **64 GiB**，出处是云机
runbook 的「硬需求、实测」——但**这个数本身从未在装得下的机器上量过**，它是在
12 GB 上被 OOM 杀出来的上界（见 [`../bench/results/compressed.md`](../bench/results/compressed.md)
对「11.0 GB 是截断值不是真峰值」的同款更正）。

已知的实测地板：

| 档 | 真峰值 | 出处 |
|---|---|---|
| `core` | **10.15–10.45 GiB**（默认旋钮）/ 9.30 GiB（`NUM_CORE_WORKERS=1`） | `bench/results/proofs.md`、`prover_knobs.md` |
| `compressed` | **13.73 GiB** | `bench/results/compressed.md` |
| `groth16` | **未知**，外推 3–4× `core` ≈ **25–40 GiB** | 本文外推，**不是实测** |

而边际成本极小（[`tdsc-plan.md`](tdsc-plan.md) §WP1：每规则 +49 MiB，每 9,800 字符
+117 MiB）—— 5 万字符 × 6 规则，`core` 也才 ≈11.3 GiB。
⇒ **峰值由固定开销主导，与矩阵规模关系不大**，这正是「一次探测就能定全局」的依据。

---

## 2. 第一次开机：只回答一个问题 —— `groth16` 真峰值多少

预算约 **¥8 / 1–2 小时**。这一次的产物不进论文，但它决定了第二次开机买几张卡。

> **为什么必须先探测**：`bench_scale.py` 的 `assert_same_host()` 会**拒绝**往另一台
> 主机量出的文件里追加；同一主机但**核数变了**会警告「耗时不可比」；`load_previous()`
> 在内存变化 >5% 时会把已量的成功行**全部作废**。所以「先租 1 卡跑一半、再升 2 卡」
> 不是省钱，是把已跑完的点全部丢掉重来。

### 2.1 开机与镜像

- **GPU 数量：1。** 优先挑「每GPU分配-内存 ≥ 90 GB」的可用区（2026-11-01 见到的是
  西北B区 344 机：12 核 / 90 GB / ¥1.88）。这一轮不要选 2 卡 —— 探测只需要一个点。
- **镜像：基础镜像 → Miniconda → Python 3.10 + Ubuntu 22.04。**
  注意 AutoDL 的「基础镜像」清单里**没有裸 Ubuntu**（只有 PyTorch / TensorFlow /
  Miniconda / tritonserver / JAX / PaddlePaddle / TensorRT / Gromacs），所以**最轻的
  一档就是 Miniconda**（几 GB，自带 Python 与 apt）。不要选 PyTorch/CUDA 那一档：
  GPU 全程闲置（`SP1_PROVER=cpu`），而 PyTorch 镜像通常占 **10–20 GB**，系统盘只有
  30 GB，选它等于开局就把编译空间吃掉一半。本仓库要求 **Python ≥ 3.10**
  （[`development.md`](development.md) §环境）；有 3.10 就选 3.10，与本机 3.10.12 对齐。
- **数据盘：勾「需要扩容」，填 100 GB。** 免费只有 50 GB，而 `rustup + cargo-prove +
  circuits/target` 约 25 GB，50 GB 是「刚好紧张」而不是「够用」。
  计费是 **0.0066 元/日/GB**（每日 24 点扣，**关机也照扣**）⇒ 100 GB ≈ ¥0.66/天 ≈ ¥20/月，
  一个 10 小时的窗口不到 ¥0.3 —— 为这点钱冒 `No space left on device` 的风险不划算。
  使用中可扩可缩，所以先按 100 GB 开，`df` 显示不够再加。

> **续跑要用「关机 / 开机」，不要「删除实例再新建」。** `assert_same_host()` 比的是
> `hostname + cpu_count`：关机再开机是**同一个容器**，hostname 不变，`bench_scale.py`
> 的续跑照常成立；删除重建则是新 hostname，**已跑完的点会被拒绝追加**
> （`✗ … 是主机 X 量的，当前是 Y`）。整台机器是同一个实验单元，这条别踩。

### 2.2 先核对「真实配额」，这一步不能跳

```bash
cat /sys/fs/cgroup/memory.max      # cgroup v2；v1 是 memory/memory.limit_in_bytes
cat /sys/fs/cgroup/cpu.max
nproc
free -g                            # 可能是宿主值，别信
```

**为什么**：`check_wave2_env.py` 和 `bench_scale.py` 的 `host_info()` **都读
`/proc/meminfo`**。容器里没挂 lxcfs 时它报的是**宿主机**内存（几百 GB），于是：

- 64 GiB 闸门**假 PASS**；
- 你把几百 GB 的机器跑出几百 GB 的读数的幻觉；
- 真实配额只有 60 GB，你会在第 40 分钟收到一个 SIGKILL。

⇒ **一律以 `cgroup` 为准**。若两者不一致，把真实配额**手写进
`bench/results/scale-cloud.json` 的 `host.mem_total_mb`**，否则那张表的自变量是假的
（这正是 `load_previous()` 用来判断「能不能续跑」的那个字段）。

> 待办（未做）：给 `check_wave2_env.py` / `bench_proofs.py:host_info()` 加一个
> cgroup 兜底，读不到 `/proc/meminfo` 的真值时回落到 `memory.max`。在那之前，
> 本文的这一节就是纪律。

### 2.3 装工具链（一条命令）

仓库带了一个 AutoDL 专用装配脚本。它**先体检再动手**：内存不够就一行不装、
直接退出，免得编译两小时后才发现 `groth16` 那档被闸门跳过。

```bash
cd /root/autodl-tmp/zk-policy
bash scripts/ops/provision_autodl.sh --check   # 只体检，秒级，不改环境
bash scripts/ops/provision_autodl.sh           # 体检 + 安装（可反复执行）
```

它替你把 AutoDL 的坑都处理了，每一条都是 2026-11-01 在 570 机（RTX 5090 /
16 vCPU / 90 GB）上实际踩出来的：

| 坑 | 现场观察 | 脚本怎么做 |
|---|---|---|
| 容器里没有 `sudo` | `sudo apt-get` → `command not found` | 是 root 就不加 `sudo` |
| `/proc/meminfo` 报**宿主**内存 | 754.5 GiB，而 cgroup 只有 **90.0 GiB** | 以 `memory.max` 为准，两个数都打出来 |
| `nproc` 报**宿主**核数 | 128 核，实际配额 **16** | 读 `cpu.max`，并行度按真实配额设 |
| 系统盘只有 30 GB | 编译到一半 `No space left on device` | 自动把 `CARGO_TARGET_DIR` 指到数据盘并写进 `~/.bashrc` |
| GitHub / go.dev 直连不稳 | `github.com` 超时、`go.dev` TLS 握手失败 | rustup→清华、Go→golang.google.cn、cargo→[rsproxy](https://rsproxy.cn) |

> **只信 cgroup。** 这台机器上 `/proc/meminfo` 754.5 GiB、cgroup 90.0 GiB、
> `nproc` 128 而实际 16 核——三个数字全部对不上。`bench_scale.py` 读的是
> `/proc/meminfo`，所以它的「64 GiB PASS」是**假 PASS**（见 §6）。

#### 手工装（脚本失败时照这个顺序）

```bash
# 1) 系统包（root 下不要 sudo）
apt-get update && apt-get install -y build-essential pkg-config libssl-dev \
    git curl jq cmake libclang-dev ca-certificates

# 2) Rust —— 走清华镜像：直连 static.rust-lang.org 单文件要 12 s
export RUSTUP_DIST_SERVER=https://mirrors.tuna.tsinghua.edu.cn/rustup
export RUSTUP_UPDATE_ROOT=https://mirrors.tuna.tsinghua.edu.cn/rustup/rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="$HOME/.cargo/bin:$PATH"

# 3) cargo 源（crates.io 索引能连、下载常卡）
mkdir -p ~/.cargo && cat > ~/.cargo/config.toml <<'TOML'
[source.crates-io]
replace-with = "rsproxy-sparse"
[source.rsproxy-sparse]
registry = "sparse+https://rsproxy.cn/index/"
TOML

# 4) SP1 —— 注意是**两步**：`curl | bash` 只装 sp1up 本身
curl -fsSL https://sp1.succinct.xyz | bash
export PATH="$HOME/.sp1/bin:$PATH"
sp1up -v v6.7.0            # 版本以 circuits/Cargo.lock 为准
cargo prove --version

# 5) 配套 Rust 工具链（见下面「SP1 工具链专门说」）
# 6) Go ≥1.24
curl -LO https://golang.google.cn/dl/go1.24.0.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
export PATH="$PATH:/usr/local/go/bin"
```

#### SP1 工具链（`prove install-toolchain`）专门说

这一步国内很折腾，三个坑叠在一起：

1. **不要开 AutoDL 学术加速。** `source /etc/network_turbo` 的代理做 TLS 中间人，
   系统 CA 里有它的根证书，`curl` 认、Rust 的 `rustls` **不认**。现象是
   `Fetching GitHub releases failed`，而同一个 URL 用 `curl` 是 200 —— 极易误判成「被墙」。
2. **它自带的下载器极慢**：实测 ~2 KB/s（393 MB 要跑一天），而 `curl` 走镜像有 1 MB/s。
3. **它不复用已有文件**：`~/.sp1/rust-toolchain-<triple>.tar.gz` 存在也会被截断重下，
   所以「先下好再跑」没用，必须绕开它。

绕法：手工解包 + `rustup toolchain link`。

```bash
# 先确认它要哪个 tag（cargo-prove 里写死的版本号）
strings "$HOME/.sp1/bin/cargo-prove" | grep -oE 'succinct-1\.[0-9]+\.[0-9]+-64bit' | sort -u
# → succinct-1.94.0-64bit

TAG=succinct-1.94.0-64bit
U="https://github.com/succinctlabs/rust/releases/download/$TAG/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz"
mkdir -p "$HOME/.sp1" && cd "$HOME/.sp1"
curl -fL -C - --retry 10 -o rt.tar.gz "https://gh-proxy.com/$U"   # 镜像，约 1 MB/s

mkdir -p "$HOME/.sp1/toolchain"
tar -C "$HOME/.sp1/toolchain" -xzf rt.tar.gz
ls "$HOME/.sp1/toolchain"                 # 里面应直接有 bin/ lib/ share/
rustup toolchain link succinct "$HOME/.sp1/toolchain"
rustup toolchain list                     # 应出现 succinct-x86_64-unknown-linux-gnu
cargo prove --version
```

> 包大小就是校验：`succinct-1.94.0-64bit` 的 x86_64 linux 包是 **384,963,362 字节**，
> 下完对一下 `stat -c %s`，对不上就是被代理截断了。

### 2.4 磁盘：**编译产物绝不能落在系统盘**

AutoDL 的系统盘只有 ~30 GB，而 `rustup + cargo-prove + circuits/target` 轻松
超过 30 GB。**先搬仓库、再设 target 目录**，顺序反了就是一次 `No space left on device`。

```bash
# 仓库放数据盘
cd /root/autodl-tmp
git clone <你的远端> zk-policy && cd zk-policy     # 或从本机 rsync 上来，见 §5.2

# 所有编译产物也放数据盘
export CARGO_TARGET_DIR=/root/autodl-tmp/cargo-target
echo 'export CARGO_TARGET_DIR=/root/autodl-tmp/cargo-target' >> ~/.bashrc

df -h /root/autodl-tmp   # 开跑前确认剩余 ≥30 GB
```

> `circuits/target/release/pop-script` 是 `make_audit_proof.sh` 里写死的路径。
> 改了 `CARGO_TARGET_DIR` 之后，那条脚本里的相对路径仍然成立（它是相对仓库根），
> 但**编译位置**变了 —— 跑 fixture 前先 `ls $CARGO_TARGET_DIR/release/pop-script`。

### 2.5 编译 + 探测（一条命令一个点）

```bash
export SP1_PROVER=cpu
ulimit -n 65535 || true

# 先编译（1–2 小时，按 16 核估；这一步也计费）
cargo build --release -p pop-script

# 体检
python3 scripts/ops/check_wave2_env.py --require P0-06_groth16

# 只跑最小的一个 groth16 点，写入**独立的**结果文件（不要碰正式表）
/usr/bin/time -v python3 bench/bench_scale.py \
  --out bench/results/scale-probe.json \
  --proof-modes groth16 --lengths 200 --rules 1
```

看两样东西：

| 看什么 | 在哪 | 判据 |
|---|---|---|
| `peak_rss_mb` | `bench/results/scale-probe.json` 的 `rows[0]` | **这是全场唯一还不知道的数** |
| 是否被 SIGKILL | 同上，`ok: false` + `error` 里带 SIGKILL | 说明 60 GB 装不下 |

### 2.6 判定表

| 探测结果 | 第二次开机怎么买 |
|---|---|
| `peak_rss_mb` < 55,000 **且** 单点墙钟 ≤ 10 min | **不用关机换机**：在**同一个实例**上直接接着跑全量（省一次 1–2 h 的编译；同主机名 ⇒ 续跑与追加都成立） |
| `peak_rss_mb` < 55,000 **但** 墙钟 > 10 min | 上 **2 卡**：内存不缺，缺的是单核频率与并行度。注意这意味着**换一台机器**，全量必须在新机器上一次跑完 |
| 55,000 – 110,000 | **2×4090D**（~120 GB 起） |
| `ok: false` / SIGKILL | 先加内存到 2 卡；仍不行再用 `NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1` 复探（`prover_knobs.md`：能压 10.9%） |

**关机**。`scale-probe.json` 留着 —— 它是「`groth16` 真峰值」这个数的**唯一证据**，
后续论文里写「需要 ≥N GB」时引的就是它。

---

## 3. 第二次开机：跑全量

预算约 **¥35–50 / 8–10 小时**。

### 3.1 规模与时间估算

`--stage all` 去重后是 **34 次真实出证**（`core` 16 点 + `groth16` 16 点 + 隐私面 2 次）。

| 阶段 | 点数 | 单点墙钟（估） | 小计 |
|---|---:|---|---|
| 编译（若换机重来） | — | — | 1–2 h |
| P0-06 `groth16`（≤10k） | 9 | 5–10 min | 1–1.5 h |
| P0-07 隐私面 | 2 | 5–15 min | 0.2–0.5 h |
| P0-08 全矩阵（含 50k） | 32（其中 9 点已跑） | 3–40 min | 4–6 h |
| **合计** | **34** | | **7–10 h** |

> ⚠️ **这些是外推，不是实测**：`core` 的行来自本机 24 线程的
> [`../bench/results/proofs.md`](../bench/results/proofs.md)；`groth16` 的行按
> `compressed/core = 2.5×` 再乘包装开销推的。**若用的是 12 核 / 2.1 GHz 那档
> （§1.1），上表还要再乘 1.5–2×**（§1.2）。真实数字唯一来源是这一轮的产物。
> 跑完请把实测值抄回本文，并把上表的「估」字去掉。

### 3.2 跑法

```bash
export SP1_PROVER=cpu
cd /root/autodl-tmp/zk-policy

# 推荐：先进 tmux，断线不断任务（见 §5.3）
tmux new -s wave2

# 全量（脚本内部串行，flock 拒绝并发）
bash scripts/ops/run_wave2_cloud.sh --stage all --budget-min 600
```

**如果论文只卡在 T1**（`groth16` + 链上验证），先只跑这一阶段，半天就能收工：

```bash
bash scripts/ops/run_wave2_cloud.sh --stage groth16 --budget-min 120   # ~1.5 h，约 ¥6
```

P0-08 的 50k 全矩阵是加分项，等论文真需要那一列时再开机。

### 3.3 中途失败了怎么办

| 现象 | 含义 | 处理 |
|---|---|---|
| 某点 `skipped：groth16 需约 65536 MB，本机只有 …` | 内存闸门没过 | **别硬跑**。要么换 2 卡，要么改 `MODE_MIN_MEM_MB` 并**在结果里写明改过** |
| 某点 `未跑（预算用尽）` | `--budget-min` 到了 | 直接**重跑同一条命令**：`bench_scale.py` 自带续跑，成功的点会跳过 |
| 某点 SIGKILL | 真 OOM | 看 §2.6，用旋钮或加内存；**不要**在同一台机器上并行跑两个证明 |
| 整个进程没了（SSH 断） | 没有 tmux / nohup | 重跑同一条命令，续跑会接上；这也是为什么 §5.3 要求先开 tmux |

---

## 4. 产物与收尾

### 4.1 必须带回本机的文件

```bash
bench/results/scale-cloud.json
bench/results/scale-cloud.md
bench/results/privacy_surface.json
bench/results/privacy_surface.md
bench/results/scale-probe.json      # 第一次开机的探测结果，别丢
```

**没有 `.json` 的数字不进论文**（[`runbook-wave2.md`](runbook-wave2.md) §7）。
`.md` 是 `bench_scale.py` 自动渲染的，**不要手改**——要改就改 `.json` 再
`--render-only` 重出。

### 4.2 入库前必做：把硬件写对

打开 `scale-cloud.json`，确认 `host` 段里的 `cpu_count` / `mem_total_mb` 是
**cgroup 的真实值**而不是宿主机的值（§2.2）。这两个字段是这张表的**自变量**：
内存写错，边界表就没有意义，而且 `load_previous()` 将来会拿它当续跑判据。

### 4.3 链上验证（P1-7 的后半段）

```bash
cd contracts && forge build && cd ..
SP1_PROVER=cpu ./scripts/anchor/anchor_e2e.sh --onchain-verify
```

⚠️ **不要把主网私钥放进租来的机器。** 这一步优先用本地 Anvil 链或测试网；
若必须接真实 RPC，用一把**只够付这次交易的测试私钥**，跑完立刻作废。
证明本身（`proof.bin`）可以在云机上出，验证可以在本机做 —— 两者不需要同一台机器。

### 4.4 关机

跑完**立刻关机**（关机后 GPU 不再计费，数据盘保留但仍按 ¥0.0066/GB/日 扣）。但：

- **数据盘在关机期间照样扣费**，一天 ¥0.66（100 GB）—— 跑完一周内不开机，就把盘缩回 50 GB；
- 关机保留有期限，**产物先 `rsync` 回本地再关**；
- 续跑**只关机、不删实例**（见 §2.1 末尾那条：删了 hostname 就变了）；
- 下次开机再改配置（1 卡 → 2 卡）**会让同一批结果作废**（§2 开头的三条机制），
  所以要么一次跑完，要么接受重跑。

---

## 5. 在云机上怎么操作（连接、传文件、后台跑）

这一节回答「人怎么在这台机器上干活」，与出证无关。

### 5.1 三种连法，按场景挑

| 方式 | 适合 | 注意 |
|---|---|---|
| **JupyterLab 网页终端** | 第一次配环境、看日志 | 页面刷新/关标签会断；**长任务别在这上面跑** |
| **SSH** | 日常主力 | 主机名与端口在控制台实例详情里，**每个实例不同**，别复制上次的 |
| **VSCode Remote** | 改代码 | 需要本地装 Remote-SSH；AutoDL 文档里有现成配置 |

### 5.2 把代码传上去

```bash
# 方案 A：git（推荐，能改能回滚）
git clone <远端> /root/autodl-tmp/zk-policy

# 方案 B：从 Windows 本机推（在**本地** PowerShell 里跑，注意是反斜杠路径）
#   WSL 盘符路径用 \\wsl.localhost\Ubuntu-22.04\...，rsync 不认 UNC，用 scp 或
#   在 WSL 里跑 rsync 更省事
rsync -avz --exclude .git --exclude target \
  /home/dong/Proof-of-Policy/03_代码仓库/zk-policy/ \
  root@<实例主机>:<端口>:/root/autodl-tmp/zk-policy/
```

> **不要**把 `.git`、`target/`、`bench/results/` 之外的大目录整个推上去 ——
> 系统盘小，而且传输本身也占用你计费的时间。

### 5.3 长任务必须挂在 tmux 里

SSH 一断，前台进程会收到 SIGHUP 直接死 —— 一个跑了 3 小时的点就这么没了。

```bash
tmux new -s wave2         # 新建会话
# ...在里面跑长任务...
# Ctrl-b 然后 d           离开（任务继续跑）
tmux ls                   # 看有哪些会话
tmux attach -t wave2      # 回来
```

不用 tmux 的替代（要自己记日志）：

```bash
nohup bash scripts/ops/run_wave2_cloud.sh --stage all --budget-min 600 \
  > /root/autodl-tmp/wave2.log 2>&1 &
tail -f /root/autodl-tmp/wave2.log
```

### 5.4 看它还在不在跑

```bash
watch -n 5 'free -g; echo ---; ps -eo pid,rss,etime,cmd --sort=-rss | head -5'
```

- `rss` 那一列就是 `bench_scale.py` 记的 `peak_rss_mb` 的同源指标；
- **只应该看到一个 `pop-script`**。看到两个就是并发，必被 OOM（脚本的 `flock`
  拦的是编排层，拦不住你手动再开一个）。

### 5.5 计费意识

AutoDL **按秒计费、开机即计费**，编译期和等你敲命令的时间都算钱。
两个习惯能省掉一半：

1. **无卡模式改代码、传数据**（¥0.1/h），**只在真要编译/证明时开机**；
2. 关机前把「下一个命令」写进一个 `run.sh`，开机后一条命令跑完，别在机器上现场调试。

另外，**数据盘是关机也扣的**：0.0066 元/日/GB，100 GB 一天 ¥0.66。跑完就把盘缩回 50 GB。

**开户先充够余额。** 按量计费在**余额见底时直接停实例**，不是「跑完再结算」—— 一个跑到第 7 小时
的 groth16 会当场消失，而 `--budget-min` 拦不住这个。按「单价 × 预计最长 13 h」再乘 2 充，
例如 ¥2.88/h 的机器充 ¥100。控制台里那一栏写「余额不足」时，实例会卡在「创建中 0.00%」。

---

## 6. 与本仓库机制的交互（读代码的人需要知道）

| 机制 | 位置 | 在 AutoDL 上会怎样 |
|---|---|---|
| 内存闸门 | `bench_scale.py:MODE_MIN_MEM_MB` / `check_wave2_env.py:MIN_MEM_GB` | 读 `/proc/meminfo`，**容器里可能是宿主值** → 见 §2.2 |
| 主机指纹 | `bench_scale.py:assert_same_host()` | 比 `hostname + cpu_count`；**换实例就拒绝追加**，换核数会警告 |
| 续跑作废 | `bench_scale.py:load_previous()`，`HOST_MEM_TOLERANCE=5%` | 内存变化 >5% ⇒ 已成功行全部作废 |
| 串行锁 | `run_wave2_cloud.sh` 的 `flock -n /tmp/pop-wave2-cloud.lock` | 同一台机器第二个编排直接退出（符合预期） |
| OOM 判定 | `bench_proofs.run_point` 接住 SIGKILL 并记成一行 | AutoDL 的超限正是 SIGKILL，能被正确记为「失败结论」而不是崩溃 |

**这五条合起来的意思**：AutoDL 上的每一次开机都是一个**不可合并的实验单元**。
这也是本文把「探测」和「全量」拆成两次开机的原因 —— 探测用独立文件，全量一次跑完。

---

## 7. 待办

- [ ] 第一次开机后，把 `scale-probe.json` 的 `peak_rss_mb` 抄回本文 §1.2 的表，
      把 `groth16` 那一行的「外推」换成实测。
- [ ] 全量跑完后，把 §3.1 的时间表换成实测值，并去掉「估」。
- [ ] 给 `host_info()` 加 cgroup 兜底（§2.2 的待办）。
- [ ] 把 §3.1 的时间表按 **12 核 / 2.1 GHz** 那档的实测重新标定一次。
