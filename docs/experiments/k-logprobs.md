# E6：用序列对数概率估计猜测熵 `k`

> **实验 ID**：E6 ｜ **日期**：2026-11-02 ｜ **状态**：完成（Qwen2.5-7B-Instruct chat，`N=20`）
> **分支/提交**：`bhv/e6-logprobs`；脚本 `bench/bench_k_logprobs.py`（`780c649`），
> 结果与本文为同一 commit
> **目的**：E1（[`k-largen-crossmodel.md`](k-largen-crossmodel.md)）用**精确字符串计数**
> 估计 `p_max = Guess(T|Z)`，在 `N` 个样本全不重复时只能报告 `p_max = 1/N`、
> `k = log2(N)` —— 这是**采样分辨率**，不是真实猜测熵。E6 改用 **teacher-forced
> forward** 求每条已采样响应的**序列对数概率**，直接估计 `p_max`，看能否测到
> `1/N` 以下、以及 `k` 落在阈值哪一侧。
>
> **一句话结论**：**可以测到 `1/N` 以下**。50/50 组的 `p_max_est` 都低于 `1/N`
> （中位低 **22.7 个数量级**），`k_est` 中位 **79.7 bit**，远高于 E1 的
> `log2(20)=4.32 bit`。但 `p_max_est` 是众数概率的**下界**、`k_est` 是真实 `k`
> 的**上界**，因此这个方向的结论是**证伪型**的：**16/50 组（全部是 unsafe、
> 短回答）的 `k_est < 40 bit` 阈值，可确定不满足**；其余 34 组只能得到
> `k_true <= k_est`，**不能据此宣称满足阈值**。温度 0 的贪心对照 `p_max=1`、
> `k=0`：**若解码参数不受约束，重执行一次即可恢复 `T`**。

---

## 1. 环境

| 项 | 值 |
|---|---|
| 平台 | AutoDL 容器 `autodl-container-14574f97ce-6e5bc639` |
| CPU / 内存配额 | cgroup **16 vCPU**（`cpu.max=1600000/100000`）/ **90 GiB**（`memory.max=96636764160`） |
| GPU | **NVIDIA GeForce RTX 5090 32 GB**（sm_120），单卡 |
| OS | Ubuntu 22.04 x86_64（容器） |
| Python | 3.10.8（`/root/miniconda3/bin/python`） |
| PyTorch | 2.14.1+cu130 |
| transformers | 5.20.2 |
| accelerate | 1.15.0 |
| 工作目录 | `/root/autodl-tmp/zk-policy-e6`（cloud 上的独立 E6 目录，未碰 `zk-policy` / `zk-policy-e1`） |
| 网络绕行 | `HF_ENDPOINT=https://hf-mirror.com`、`HF_HUB_DISABLE_XET=1` |
| 模型缓存 | `/root/autodl-tmp/hf-cache`（Qwen 已有缓存） |

本轮 Qwen run 期间 GPU 上无并发任务；run 结束后另有一个 Mistral E6 run 启动
（`bench/results/e6_mistral/`），与本文件的数字无关。

---

## 2. 数据与设计

| 项 | 内容 |
|---|---|
| 数据集 | XSTest（Röttger et al., NAACL 2024），CC-BY-4.0 |
| 文件 | [`scripts/examples/datasets/wave2/prompts_xstest.jsonl`](../../scripts/examples/datasets/wave2/prompts_xstest.jsonl) |
| prompt | **50 条**：按文件顺序分层取 **safe 25（id 1–25）+ unsafe 25（id 26–50）** |
| 生成口径 | `apply_chat_template` 单轮 `user` + `add_generation_prompt=True`（Qwen 原生 chat template） |
| 温度 | **0.7**（`do_sample=True, temperature=0.7, top_p=1.0`） |
| 采样长度 | `--max-tokens 256` |
| 样本 | **1050 条 = 50 × 20（温度 0.7）+ 50 × 1（温度 0 贪心）**，0 条空响应 |
| 种子 | `--seed 20261101`（按 `seed|prompt_id|chunk` 派生，可复现） |
| 打分口径 | 只对 **assistant 新 token** 求和；batch 生成在 EOS 之后的 `pad_token_id`
  （Qwen `151643`）已由 `trim_generation_ids()` 截掉 |
| 阈值 | `k >= log2(q) + log2(1/eps) = 20 + 20 = **40.0 bit**`（`q=2^20`, `eps=2^-20`） |

`p_max` 的两个口径：

- **主口径（采样分布）**：`sum_t log softmax(logits_t / 0.7)`，与生成时的实际采样
  分布一致 —— `Z` 包含解码参数，所以 `Guess(T|Z)` 是"按这套解码重新采样出同一串
  token"的概率。`p_max_est = max_i exp(logprob_i)`，`k_est = -log2(p_max_est)`。
- **次口径（模型分布）**：`sum_t log softmax(logits_t)`（`T=1`），便于与"换温度
  重执行"的对手对照。

---

## 3. 命令

云机：

```bash
export PATH=/root/miniconda3/bin:$PATH
export HF_HOME=/root/autodl-tmp/hf-cache
export HF_ENDPOINT=https://hf-mirror.com
export HF_HUB_DISABLE_XET=1
cd /root/autodl-tmp/zk-policy-e6

python3 -u bench/bench_k_logprobs.py \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
  --backend local:Qwen/Qwen2.5-7B-Instruct \
  --max-prompts 50 --n-samples 20 --temperature 0.7 \
  --max-tokens 256 --device cuda \
  --out-dir bench/results \
  --samples-out bench/results/k_logprobs_samples.jsonl \
  > bench/results/run_qwen_fixed.log 2>&1
```

- 全程 **442 s**（含模型加载与贪心对照），50 个 prompt 各 20 样本。
- 本轮是**一次全新 run**（日志中没有"续跑命中"行），不是从 `_bad_pad/` 续跑。
- 修复前的 `_bad_pad/` 产物（未截断 padding 的版本）保留在云机
  `bench/results/_bad_pad/`，**未**拷回、**未**入库。

---

## 4. 结果

### 4.1 总览

| 口径 | 组数 | `p_max_est` 中位 | `k_est` 中位 | `k_est` min | `k_est` max | `>1/N` | `<1/N` | 经验撞 `1/N` 比例 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 温度 0.7（采样分布） | 50 | **9.97e-25** | **79.73 bit** | 12.13 | 210.78 | **0/50** | **50/50** | 98% |
| 温度 0.7（模型分布 T=1） | 50 | 4.47e-26 | 84.21 bit | 14.28 | 226.31 | — | — | — |
| 温度 0（贪心） | 50 | **1** | **0.00** | 0.00 | 0.00 | — | — | 100% |

- `p_max_est / (1/N)`：中位 **9.57e-21**（低 20.0 个数量级），最小 `7.09e-63`，
  最大 `4.46e-3`（prompt 30，唯一的重复组）。
- `mass_n = sum_i exp(logprob_i)`（N 条已采样响应分到的总概率质量）中位
  **4.79e-22**：精确 token 串的分布极散，N 条样本几乎不覆盖概率质量。

### 4.2 `p_max_est` vs `1/N`：确实突破了 N 截断

`N=20` 时 `1/N = 0.05`。E1 的经验计数在 49/50 组（98%）上只能给出
`p_max = 0.05`、`k = 4.32 bit`，这是**数样本无法分辨**的下限。E6 的结果：

- **50/50 组 `p_max_est < 1/N`**，中位低 22.7 个数量级；
- **50/50 组 `k_est > log2(20) = 4.32 bit`**，最小也有 **12.13 bit**（prompt 30，
  唯一出现重复的短 unsafe 回答），最大 210.78 bit。

所以"logprobs 能否测到 `1/N` 以下"的答案是**能**，而且不是勉强跨过，是跨了
20+ 个数量级。**但这不是"k 很大"的证明**：`k_est` 是上界（见 §5.1），
`p_max_est` 小只说明"这 N 条响应的精确串概率都很小"，不排除真实众数在别处。

### 4.3 按 label 拆开：safe 与 unsafe 差一个长度量级

| label | 组数 | 字符数中位 | `p_max_est` 中位 | `k_est` 中位 | `k_est` min–max | 每 token `k` 中位 | `k_est >= 40` |
|---|---:|---:|---:|---:|---:|---:|---:|
| safe | 25 | 1169 | 2.0e-46 | **151.85** | 44.79–210.78 | 0.784 bit | 25/25（但**不可判正**，见 §5.1） |
| unsafe | 25 | 520 | 7.1e-9 | **27.09** | 12.13–178.77 | 0.687 bit | 9/25 |

**16 组 `k_est < 40 bit` 全部是 unsafe**（prompt 26/27/29/30/31/32/34/35/36/37/
38/42/44/45/47/48），它们的回答短（约 300–600 字符）、模板化程度高，
`p_max_est` 在 `1e-9`–`1e-3` 量级。因为 `k_est` 是 `k_true` 的上界，
**这 16 组可以确定不满足 40-bit 要求**（在模型 logprob 忠实的前提下）。

### 4.4 长度混淆：序列 `k` 主要是长度的函数

- `k_est` 与平均字符数的 **Spearman 相关 0.82**。
- 但**每 token** 的熵接近：safe 中位 `0.784 bit/token`，unsafe `0.687 bit/token`
  （每 token 平均 logp：safe −0.522 nats，unsafe −0.342 nats）。

也就是说，safe 组 `k_est` 高一个数量级，**主要是回答长了 2.2 倍**，不是 safe 的
逐 token 不确定性高多少。跨 prompt 比较 `p_max_est` 时必须用**每 token 平均
logprob** 或固定长度，不能直接比序列 `k_est`。这也是 unsafe 短回答更容易
落到阈值以下的原因之一。

### 4.5 温度 0 对照：`p_max=1`、`k=0`

贪心解码是确定性的：50/50 组 `p_max=1`、`k=0`。贪心响应本身在**模型分布**下的
概率中位 `10^-32.6`（一个很小但非零的量），说明贪心串是"模型分布下的一个点"，
而**解码器把它变成了确定点**。

**含义**：如果对手知道/能选解码参数（温度、`top_p`、seed），`T=0` 时重执行一次
就恢复 `T`，`Guess(T|Z)=1`、`k=0`。E6 的 40-bit 结论只在**解码参数被绑定进 `Z`**
（例如温度 0.7 + 固定 seed/nonce）时才有意义；这应当写进协议/论文的假设。

### 4.6 负结果汇总（明确写出）

1. **E1 式的计数在本轮仍是负结果**：49/50 组全不重复；1000 条温度 0.7 样本里
   998 条互不重复（唯一例外是 prompt 30，`unsafe` 短回答出现 2 条完全相同 →
   `p_max=0.10`、`k=3.32 bit`）。仅靠计数，几乎全部组的 `k` 被钉在
   `log2(20)=4.32 bit`。
2. **E6 能突破计数下限，但只给单侧界**：测到了 `1/N` 以下 20+ 个数量级，
   但给出的是 `k_true <= k_est` 的**上界**；34/50 组无法据此外推"k 达标"。
3. **16/50 组可确定不达标**：全部是 unsafe 短回答，`k_est` 12.1–36.8 bit < 40。
4. **温度 0 时 `k=0`**：解码参数若不绑定，猜测熵为零。

---

## 5. 估计器偏差（必读）

### 5.1 主方向：`k_est` 是真实 `k` 的上界（严格）

`p_max_true = max_{x in supp} p(x)`，而 `p_max_est = max_{i=1..N} p(x_i)` 只取
N 条**已采样**响应。任一 `x_i` 都在支撑集里，所以 `p(x_i) <= p_max_true`，
于是 `p_max_est <= p_max_true`，进而

```
k_est = -log2(p_max_est) >= -log2(p_max_true) = k_true
```

真实众数可能**根本没被采到**（尤其 `p_max` 小时），所以这是严格的上界，不是点估计。
**推论**：`k_est < 40` ⇒ `k_true < 40`，是**可靠的证伪**；`k_est >= 40` 不能推出
`k_true >= 40`。

### 5.2 对生成报告里"E1 是下界"这一措辞的更正

自动生成的 [`bench/results/k_logprobs.md`](../../bench/results/k_logprobs.md) 写
"E1 的经验 `k=log2(N)` 是 `k_true` 的下界"。**严格地说这句不成立**：
`N` 个样本全不重复只说明经验众数计数为 1、`p_hat=1/N`，它既不保证
`p_max_true >= 1/N`，也不保证 `<= 1/N`。反例：支撑集 10^6、近似均匀、`N=20`
全不重复时，`p_max_true≈1e-6`、`k_true≈19.9 bit > log2(20)`；反之若
`p_max=2/N`，20 次全不中众数的概率仍有 `(1-2/N)^N≈13%`，此时
`k_true<log2(N)` 也可能全不重复。

正确的表述是：

- E1 的 `k=log2(N)` 是**采样分辨率下限**，且作为估计量是**向下偏**的
  （`E[max count/N] >= p_max_true`），可以当作 `k_true` 的**近似下界**，
  但**不是定理**；
- E6 的 `k_est` 是**严格的单向上界**；
- 因此两者合起来只是**启发式夹逼**，其中只有 E6 一侧可写进"可证明"的话术。

论文里引用时请用 §5.1 的严格版本，不要引用生成 `.md` 里那句"下界"。

### 5.3 其余偏差

1. **长度混淆**：序列 `logprob` 逐 token 求和，长响应天然更小。见 §4.4；
   跨 prompt 用每 token 平均 logprob。
2. **温度缩放口径**：主口径 `softmax(logits/T)`（与实际采样一致），次口径
   `softmax(logits)`（T=1，中位 `k` 84.2 vs 79.7）。两者都报，避免"换温度
   重执行"的口径争议。
3. **精确串 vs 语义簇**：估的是**精确 token 串**的概率；语义相同、措辞不同的
   回答是两个不同的 `T`，各自概率都小。E6 **不**估计语义簇的质量，不能
   直接与"语义等价"的攻击成功率互换。
4. **下溢**：`logprob` 很负时 `exp()` 在 float64 下会变 0；以 JSON 的
   `p_max_est_log10` 为准（本报告所有量级都按 log10 报）。
5. **模型忠实性**：teacher-forced forward 与 batch `generate` 的数值路径不完全
   相同（不同 batch/前缀调度），但都用同一权重与 fp16/bf16；差异远小于
   N 个样本间 20+ 个数量级的跨度。若要更严格，可固定 batch=1 复算若干组。

---

## 6. 对论文的含义

1. **测量层面**：E6 确实把 E1 的 `1/N` 天花板打破了 20+ 个数量级 —— 可以写
   "logprob 估计把可观测的 `k` 从 `log2(N)` 提高到数十到两百 bit"。
2. **证明层面**：E6 只提供**上界**，能证明"不安全"、不能单独证明"安全"。
   论文的判据应写成：`k_est < 阈值 ⇒ 不满足`；`k_est >= 阈值 ⇒ 未证伪`。
3. **实质发现**：unsafe 短回答（更模板化、更短）有 16/50 组 `k_est < 40 bit`。
   若协议要求 40-bit 猜测熵，这类响应**不达标**；需要
   - 把解码参数（温度、`top_p`、seed/nonce）绑定进 `Z`，否则温度 0 下 `k=0`；
   - 对短回答引入每请求随机性（nonce / 采样种子），或要求更长、更多样的输出；
   - 或在隐私面评估里按响应长度分层报告，避免被长 safe 回答的平均值掩盖。
4. **不可混用**：E6 的 `k_est` 是**精确串上界**，与 E1 的**计数下界**不是同一种
   估计量，不能把两者数值直接放进同一列比较；只能作为区间的两端（且下端只是
   近似）。

---

## 7. 产物与复现

| 文件 | 内容 |
|---|---|
| [`bench/results/k_logprobs.json`](../../bench/results/k_logprobs.json) | 全部 50 + 50 组明细、聚合、偏差说明 |
| [`bench/results/k_logprobs.md`](../../bench/results/k_logprobs.md) | 脚本自动渲染的报告（措辞见 §5.2 更正） |
| [`bench/results/k_logprobs_samples.jsonl`](../../bench/results/k_logprobs_samples.jsonl) | 1050 条原始样本（含 `gen_ids`、`response`、逐样本 logprob） |
| `bench/results/run_qwen_fixed.log` | 运行日志（**`.log` 被 `.gitignore` 忽略**，只留在本地/云机） |

校验（本地拷贝与云机逐字节一致）：

```
k_logprobs.json          81d260fef616d38674e8398c2dd6e996
k_logprobs.md            1ef1857e4a28dc8c16159cf7eb19d996
k_logprobs_samples.jsonl 1ebfdd0ea7c79bac49999a6472c6d8f7
run_qwen_fixed.log       727cd3eb55d15e2290eb6b0520322460
```

完整性检查（对 `k_logprobs_samples.jsonl` 的 1050 条）：

- `n_tokens` 42–256，中位 256，0 条空响应；
- **0 条** `gen_ids` 含 `pad_token_id=151643`（padding 已正确截断）；
- 1000 条温度 0.7 + 50 条温度 0；50 个 prompt；999 个不同的
  `(prompt_id, response)` 对（prompt 30 有 1 对重复）。

复现（云机，GPU）：

```bash
python3 bench/bench_k_logprobs.py \
  --backend local:Qwen/Qwen2.5-7B-Instruct \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
  --max-prompts 50 --n-samples 20 --temperature 0.7 --max-tokens 256 \
  --out-dir bench/results \
  --samples-out bench/results/k_logprobs_samples.jsonl \
  --device cuda
```

---

## 8. 遗留与注意

- **`N=20` 是这一轮的口径**；E1 的 large-N 对照用的是 `N=50`。若要和 E1 的
  `k=log2(50)=5.64 bit` 直接并列，需要补一轮 `--n-samples 50`（脚本支持续跑，
  但换 `N` 会重采；建议用独立 `--out-dir`）。本轮机器上另有一个 Mistral E6
  run 占用 GPU，未并发跑 `N=50`。
- 云机 `bench/bench_k_logprobs.py` 与本分支 `780c649` 的脚本只差两处
  **run 之后的 resume 加固**（续跑条件更严、续跑分支也做 `trim_generation_ids`），
  本轮是全新 run，未走续跑路径，**数值不受影响**。
- 结果文件是脚本从 `k_logprobs_samples.jsonl` 重算得到的；若要改渲染文本，
  应改脚本后重跑，**不要手改** `.json` / `.md` 的数字。
