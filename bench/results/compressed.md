# Real SP1 compressed proof: wall time, artifact size, peak memory

**量测机器**：24 核 `Intel(R) Core(TM) i7-14650HX`，WSL2，**内存上限 14 GiB**（`/mnt/c/Users/ly/.wslconfig` 设 `memory=15GB swap=4GB`；宿主物理 15.74 GiB）。⚠️ 与 [`proofs.md`](proofs.md)（core，11.7 GiB）**不是同一张表**：本文件是在**把 WSL2 内存上限 12→14 GiB 之后**量的，跨表对照先对齐这台机器的内存配置。

语料：`eu_agent_reply.txt`（167 字符，`policy_packs/eu_ai_act_v1.json`）。峰值内存由 `/usr/bin/time -v` 量取，独立进程。

| mode | config | time (s) | proof (KiB) | peak RSS (MiB) | verified | RESULT |
|---:|:--|---:|---:|---:|:--|:--|
| compressed | 默认 | 302.4 | 1242.9 | 14060.1 | yes | `pop-verify` `verified:true`；`verify_cert.py` `RESULT: PASS`（14 项） |
| compressed | core+recursion worker=1 | — | — | — | — | 12 GiB 下仍 OOM（见下「负结果」） |

关键数字（默认配置那次）：

- 墙钟 **5:02.44**；峰值常驻 **14,397,520 kB ≈ 13.73 GiB**；证明体积 **1,272,546 B ≈ 1.24 MiB**（对比 core ~2.7 MiB，压掉约一半）。
- 独立验证：`pop-verify --meta proof.bin.verify.json` → `verified: true`（verifier-only，无证明器状态）；
  `verify_cert.py --proof …` → 14 项全 PASS（签名 / `verify_only` / 公值 / vkey / `proof_outcome` / `proof_mode` /
  `policy_hash` / `response_binding` / `trace_binding` / `trace_seal`(skipped) / `semantic`(无) / `anchor`）。

## 更正：compressed 的**真峰值是 ~13.7 GiB，不是 11.0 GB**

`docs/plan-p7.md`、`reproduce.md`、`advisor-report.md` 等此前写的「compressed 峰值 11.0 GB」是**错误的量测口径**——
那是进程在 **12 GB 上限下被 OOM killer 杀在 ~11 GB 的截断值**，`time -v` 只量到死前那一点，进程**还没爬到真峰值**。
真峰值要在装得下的环境里才量得到，就是本文件的 ~13.7 GiB（14 GiB 上限下成功跑完）。

由此修正可行性口径：**`compressed` 需 ≥14 GiB**（`reproduce.md` §11「≥16 GB」的估计方向正确，数字略保守）；**`groth16`/`plonk` 仍 ≥32–64 GB**，不受本文件影响。

## 解锁手段：WSL2 内存上限是配置、不是硬件

这台机器的「12 GB」是 `C:\Users\ly\.wslconfig` 里的 `memory=12GB` 手动上限，而宿主物理内存有 15.74 GiB。
把上限改成 `memory=15GB`（+ `swap=4GB`）并 `wsl --shutdown` 重启后，compressed 即在本机出证——
**不必租机**。代价：宿主 16 GB 物理内存里 Windows 已占 ~11 GB，出证期间宿主会压缩/换页（本次 5:02 里系统态
耗时 732 s，比 core 的 ~2 分钟明显更「磨」），但结论不变、证明有效。

## 负结果：递归 worker 旋钮对 compressed 无效

同一台机器、`memory=12GB` 时代，把 core 与递归两段 worker 全降到 1
（`SP1_WORKER_NUM_CORE_WORKERS=1 CORE_BUFFER_SIZE=1 NUM_RECURSION_PROVER_WORKERS=1 RECURSION_PROVER_BUFFER_SIZE=1 NUM_RECURSION_EXECUTOR_WORKERS=1 RECURSION_EXECUTOR_BUFFER_SIZE=1`），
compressed **仍在 ~11.07 GiB（截断值）被 SIGKILL**，耗时 3:15。结论：**`NUM_CORE_WORKERS 4→1` 能压 core 地板 -11%
（见 [`prover_knobs.md`](prover_knobs.md)），但递归阶段的固定开销不是 worker 并行度绑定的**，这套旋钮救不了 compressed。
递归固定开销的唯一现实解法是**加内存**（本文件的做法）。

## 另见

- core 的默认矩阵与地板/台阶：见 [`proofs.md`](proofs.md)。
- 「地板本身压得动吗」的旋钮实验（只对 core 有效）：见 [`prover_knobs.md`](prover_knobs.md) / [`prover_knobs_cliff.md`](prover_knobs_cliff.md)。
- 复现命令与 verifier-only 审计路径：见 [`../../docs/reproduce.md`](../../docs/reproduce.md) §11。
