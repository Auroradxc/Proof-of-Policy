# 证明路径 DoS：`a+b` vs `a^n`（P1-11）

机器：**24 核 / 14.6 GiB**（Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.35）。病理模式 `a+b`，输入 `a` × `n`（无 `b` ⇒ 必然不匹配 ⇒ 扫到底）。

驱动：`/tmp/pop-script-v1`，sha256 `b81e6d072bb04a3d…`。

## 执行路径（`pop-script --execute`，不出证）

| n | pike (cycles) | naive (cycles) | naive/pike | pike 周期/字符 | naive 周期/字符 | pike exec ms | naive exec ms |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 643,906 | 12,382,732 | 19.2× | 6439.1 | 123827.3 | 22488 | 22860 |
| 200 | 1,145,221 | 48,638,958 | 42.5× | 5726.1 | 243194.8 | 22562 | 24479 |
| 400 | 2,143,629 | 193,207,142 | 90.1× | 5359.1 | 483017.9 | 29255 | 31251 |

**读法**：pike 的每字符周期基本不变（线性）；naive 的每字符周期随 n 翻倍（二次）。这条差异在**执行路径**上已经出现，证明路径只是把它放大。（`exec ms` 含驱动固定启动开销，绝对值不要与 Python 参考层横比。）

### Python 参考层墙钟（旁证，不走 zkVM）

| n | pike 中位 ms | naive 中位 ms | naive/pike |
|---:|---:|---:|---:|
| 100 | 0.051 | 2.751 | 54.1× |
| 200 | 0.110 | 11.377 | 103.3× |
| 400 | 0.244 | 41.198 | 169.0× |

## 证明路径（`--proof-mode core`，串行 `flock /tmp/pop-proof.lock`）

| 点 | cycles | prove 墙钟 s | 峰值 RSS MiB | 状态 | 说明 |
|---|---:|---:|---:|---|---|
| pike n=100 | 643906 | 122.2 | 11695.1 | `ok` | 证明成功 |
| naive n=25 | — | 153.2 | 12137.3 | `ok` | 证明成功 |
| naive n=50 | — | 226.5 | 13771.6 | `oom_or_killed` | OOM / SIGKILL —— **如实记录为结果** |

## 结论（分层写，不要混）

1. **生产语义 pike 的执行成本是线性的**：n=100→400，周期/字符基本不变。对抗长输入不会让 pike 的匹配本身二次膨胀。
2. **消融旋钮 `match_mode=naive` 是二次的**：若把它当成生产配置，同样的对抗输入会让执行周期 ~4× 增长（n 翻倍），证明路径随之变慢/变重。
3. **证明路径的成本跟周期数走，但有一个 ~10 GiB 的固定内存地板**（SP1 core setup）。本机 14.6 GiB 只够**串行**跑小 n；naive 的较大 n 在本机不可行 —— 这一条是**资源边界**，不是语义结论。
4. OOM / timeout 都作为结果保留在上表；没有把失败点从表里删掉。

## 边界与下一步

* 本机 14.6 GiB，**不要与其它 agent 并行跑 SP1**；脚本已用 `flock /tmp/pop-proof.lock` 串行化，并在可用内存低于阈值时跳过（记 `skipped_insufficient_memory`）。
* naive 的大 n（≥100）与任何 n=400 的证明路径点留给云机（64–128 GiB）；本机只报执行路径的周期数与可完成的小 n 证明。
* 本实验证明的是**成本增长阶**，不是「pike 部署下存在 DoS」；pike 的线性成本仍可能被超长输入拖慢，但那是一个线性常数问题，不是这里量的二次爆炸。

## 注释（机器/二进制/判定自检）

* 本 worktree 无构建产物（circuits/target/release/pop-script 不存在）；本表用显式指定的驱动 /tmp/pop-script-v1（sha256 见 binary.sha256）。其执行周期数与 bench/results/ablation.md 一致（643,906 vs 643,894），说明是同一份实现的构建产物。

## 复现

```bash
python3 bench/bench_dos.py --no-prove --out-dir bench/results
python3 bench/bench_dos.py --prove-points pike:100,naive:25,naive:50 --out-dir bench/results
```

证明点很贵，**可累积**：本次未重跑的点从既有结果文件原样保留，并在表里标 `source=retained_from_previous_run`。`--no-prove` 只刷新执行路径，不会抹掉已记录的证明/OOM 结果。

