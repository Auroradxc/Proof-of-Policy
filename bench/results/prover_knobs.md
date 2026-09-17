# SP1 prover 旋钮矩阵：这条地板压得动吗（R11）

**量测机器**：24 核 `Intel(R) Core(TM) i7-14650HX`，内存 11.7 GiB（`dxq`，x86_64）。⚠️ **地板是 prover 的固定开销，但「压不压得动」是这台机器的结论** —— 换机器要重跑。

采样点 **`L=200, rules=1`**（本仓最小的真点，已坐在那条地板上）。峰值内存由 `/usr/bin/time -v` 量取，**每轮一个独立子进程**；每轮出完证再用 `pop-script --verify` 独立验一次。

| # | 配置 | 旋钮 | peak RSS (MiB) | 相对当轮基线 | 耗时 (s) | shard | 已验 | passed |
|---:|:--|:--|---:|---:|---:|---:|:--|:--|
| 1 | `default` | `（默认）` | 10,454 | +0.13% | 100.2 | ? | yes | True |
| 2 | `no-verify-intermediates` | `VERIFY_INTERMEDIATES=false` | 10,477 | +0.36% | 99.1 | ? | yes | True |
| 3 | `few-core-workers` | `NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1` | 9,302 | -10.90% | 103.5 | ? | yes | True |
| 4 | `tiny-buffers` | `CORE_BUFFER_SIZE=1 SETUP_BUFFER_SIZE=1 SPLICING_BUFFER_SIZE=1 RECURSION_PROVER_BUFFER_SIZE=1 RECURSION_EXECUTOR_BUFFER_SIZE=1 PREPARE_REDUCE_BUFFER_SIZE=1 DEFERRED_BUFFER_SIZE=1` | 10,509 | +0.66% | 97.5 | ? | yes | True |
| 5 | `low-concurrency` | `NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1 NUM_SETUP_WORKERS=1 SETUP_BUFFER_SIZE=1 NUM_SPLICING_WORKERS=1 SPLICING_BUFFER_SIZE=1 NUM_RECURSION_PROVER_WORKERS=1 RECURSION_PROVER_BUFFER_SIZE=1 NUM_RECURSION_EXECUTOR_WORKERS=1 RECURSION_EXECUTOR_BUFFER_SIZE=1 NUM_PREPARE_REDUCE_WORKERS=1 PREPARE_REDUCE_BUFFER_SIZE=1 NUM_DEFERRED_WORKERS=1 DEFERRED_BUFFER_SIZE=1` | 9,350 | -10.44% | 101.4 | ? | yes | True |
| 6 | `default-again` | `（默认）` | 10,426 | -0.13% | 94.7 | ? | yes | True |

⚠️ **`shard` 那一列的 `?`：这一列本轮一个都没数出来** —— 不是漏了。SP1 只在日志级别含 debug 时才打印 shard 边界（`sp1-prover-6.7.0/src/worker/controller/splicing.rs:204` 的 `tracing::debug!("starting new shard …")`），而未设 `RUST_LOG` 时默认级别是 `off`（`sp1-core-machine-6.7.0/src/utils/logger.rs:22`）。真出证是本实验的主量测，为拿这一列去开 debug 日志会**改变被量的东西**（日志本身要内存、要时间），所以宁可让它空着。⚠️ **空着并不挡结论**：本轮量出来的是「**谁**在占内存」—— 是 worker 数（上表 `NUM_CORE_WORKERS` 那一行），不是 shard 数。dev-plan §5.7.17 记了这一点，并逐句标明哪句是**量到的**、哪句是**推的**。

## 解读

**当轮基线 10,440 MiB**（首尾两次 default 相差 0.26%），判据是「压低 ≥5%」（即 ≤9,918 MiB）。

> 读法：**这条 ±0.13% 的底噪就是本次的分辨率** —— 小于它的差不能当成信号，无论正负。

**降下来的配置**（≥门槛且证明仍有效）：

- `few-core-workers`：9,302 MiB（-10.90%，103.5 s）—— `NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1`
- `low-concurrency`：9,350 MiB（-10.44%，101.4 s）—— `NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1 NUM_SETUP_WORKERS=1 SETUP_BUFFER_SIZE=1 NUM_SPLICING_WORKERS=1 SPLICING_BUFFER_SIZE=1 NUM_RECURSION_PROVER_WORKERS=1 RECURSION_PROVER_BUFFER_SIZE=1 NUM_RECURSION_EXECUTOR_WORKERS=1 RECURSION_EXECUTOR_BUFFER_SIZE=1 NUM_PREPARE_REDUCE_WORKERS=1 PREPARE_REDUCE_BUFFER_SIZE=1 NUM_DEFERRED_WORKERS=1 DEFERRED_BUFFER_SIZE=1`

⇒ **写成推荐配置**（判据是事先定的，不是事后挑的）。

其中**旋钮最少**的是 `few-core-workers`（2 个）—— **推荐从它开始**。其余几个都是它的超集，与它相差 `low-concurrency` +0.47%：都远小于 5% 的门槛，即「多加的那些旋钮既没帮上忙、也没明显碍事」；而**动得越少，越不会顺带影响别的路径**（别的证明模式、别的 shard 数）。

## 复跑

```
SP1_PROVER=cpu python3 bench/bench_prover_knobs.py
```

旋钮名字与默认值出自 `sp1-prover-6.7.0/src/worker/config.rs`；「它们在本仓路径上」由 `sp1-sdk-6.7.0/src/blocking/cpu/mod.rs` 的 `CpuProver` → `SP1LocalNodeBuilder` 链路确认。
