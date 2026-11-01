# E1：更大 N 与跨模型 `k`

> **实验 ID**：E1 ｜ **日期**：2026-11-01 ｜ **状态**：完成
> **分支/提交**：`bhv/e1-k`，基线 `cf7bb54e06f2524885de0e335d7ff1a4250ddaeb`
> **目的**：把 X2/X2c 的猜测熵 `k` 从 `N=10/20` 的采样上限里解放出来，并在同一批
> prompt 上做 Qwen / DeepSeek / Mistral 的跨模型对照。
>
> **一句话结论**：`N=50` 下 Qwen2.5-7B（chat）**50/50 组、50 个样本全不重复**，
> `p_max = 1/50`、`k = log2(50) = 5.644 bit` —— 这只是 **k 的下界**，真实熵仍未
> 测出。DeepSeek-chat 在 `N=20` 下有 **4/50 组出现重复**（都是拒绝模板原样重复，
> `p_max=0.10`、`k=3.32 bit`），首次在这批数据上突破了 `log2(N)` 上限；
> Mistral-7B-Instruct-v0.3 与 Qwen 一样全部唯一。`p_max < 1/N` 在有限样本内
> **数学上不可能**，本实验能区分的是 `p_max = 1/N`（撞上限）与 `> 1/N`（有重复）。

---

## 1. 环境

| 项 | 值 |
|---|---|
| 平台 | AutoDL 容器 `autodl-container-14574f97ce-6e5bc639` |
| CPU / 内存配额 | cgroup **16 vCPU**（`cpu.max=1600000/100000`）/ **90 GiB**（`memory.max=96636764160`） |
| GPU | **NVIDIA GeForce RTX 5090 32 GB**（sm_120），单卡、单 GPU 任务 |
| OS | Ubuntu 22.04 x86_64（容器） |
| Python | 3.10.8（`/root/miniconda3/bin/python`） |
| PyTorch | 2.14.1+cu130 |
| transformers | 5.20.2 |
| accelerate | 1.15.0 |
| 模型缓存 | `/root/autodl-tmp/hf-cache`（复用 Qwen 缓存；Mistral 新下载） |
| 工作目录 | `/root/autodl-tmp/zk-policy-e1`（独立目录，未碰 `zk-policy` / `zk-policy-x2c`） |
| 网络绕行 | `HF_ENDPOINT=https://hf-mirror.com`、`HF_HUB_DISABLE_XET=1` |
| DeepSeek 客户端 | 本机 WSL2 Ubuntu 22.04，调 `https://api.deepseek.com`，本地不做推理 |

- 采样期间 X1d 未在云机上跑证明；本任务 GPU 显存峰值约 15.2 GiB，主机 RSS 约
  3.4 GiB，未与证明任务抢 CPU/内存。
- 云机上 `X2c` 的 `bench_k_entropy.py` 与本分支基线逐字节一致
  （md5 `9397da892b7c3f910018364cac5596d5`），没有改 bench 代码。

---

## 2. 数据与设计

| 项 | 内容 |
|---|---|
| 数据集 | XSTest（Röttger et al., NAACL 2024），CC-BY-4.0 |
| 文件 | [`scripts/examples/datasets/wave2/prompts_xstest.jsonl`](../../scripts/examples/datasets/wave2/prompts_xstest.jsonl) |
| prompt | **50 条**：按文件顺序分层取 **safe 25（id 1–25）+ unsafe 25（id 26–50）** |
| 生成口径 | Qwen / Mistral：`apply_chat_template` 单轮 `user` + `add_generation_prompt=True`；DeepSeek：原生 chat API |
| 温度 | 主实验 **0.7**（`do_sample=True, temperature=0.7, top_p=1.0`）；Qwen 另加温度 0 的 `N=5` 对照 |
| 采样长度 | `--max-tokens 256`（见 §6 关于 API 侧未生效的说明） |
| 主实验样本 | Qwen **2500** 条 = 50 prompt × 50 采样（温度 0.7） |
| 对照样本 | Qwen 温度 0 **250** 条 = 50 × 5 |
| 跨模型样本 | DeepSeek **1000** 条 = 50 × 20；Mistral **1000** 条 = 50 × 20 |
| 总计 | **4750 条真实样本，0 error**（见各 samples 文件的 `error` 字段） |

`k` 的估计沿用 X2/X2c：对每组响应用**精确字符串**计数，
`p_max = max_v count(v)/N`，`k = -log2(p_max)`，并给出 Wilson 区间。

---

## 3. 命令

云机（Qwen / Mistral；温度 0.7）：

```bash
export PATH=/root/miniconda3/bin:$PATH
export HF_HOME=/root/autodl-tmp/hf-cache
export HF_ENDPOINT=https://hf-mirror.com
export HF_HUB_DISABLE_XET=1
cd /root/autodl-tmp/zk-policy-e1

# Qwen largeN：50 prompt × 50 采样，温度 0.7
python3 bench/bench_k_entropy.py \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
  --backend local:Qwen/Qwen2.5-7B-Instruct --chat-template \
  --max-prompts 50 --n-samples 50 --temperatures 0.7 --max-tokens 256 \
  --out-dir bench/results/_e1_largen \
  --samples-out bench/results/k_samples_largeN.jsonl \
  --device cuda --resume

# Qwen 温度 0 对照：50 prompt × 5 采样
python3 bench/bench_k_entropy.py \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
  --backend local:Qwen/Qwen2.5-7B-Instruct --chat-template \
  --max-prompts 50 --n-samples 5 --temperatures 0 --max-tokens 256 \
  --out-dir bench/results/_e1_largen_t0 \
  --samples-out bench/results/k_samples_largeN_t0.jsonl \
  --device cuda --resume

# Mistral（第三个模型）：50 prompt × 20 采样，温度 0.7
python3 bench/bench_k_entropy.py \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
  --backend local:mistralai/Mistral-7B-Instruct-v0.3 --chat-template \
  --max-prompts 50 --n-samples 20 --temperatures 0.7 --max-tokens 256 \
  --out-dir bench/results/_e1_mistral \
  --samples-out bench/results/k_samples_crossmodel_mistral.jsonl \
  --device cuda --resume
```

DeepSeek（本机；key 只从 `/tmp/deepseek-key` 读入进程环境，未写入仓库/结果/日志）：

```bash
OPENAI_API_KEY=$(cat /tmp/deepseek-key) \
OPENAI_BASE_URL=https://api.deepseek.com \
OPENAI_API_BASE=https://api.deepseek.com \
python3 bench/bench_k_entropy.py \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
  --backend openai:deepseek-chat \
  --max-prompts 50 --n-samples 20 --temperatures 0.7 --max-tokens 256 \
  --out-dir bench/results/_e1_deepseek \
  --samples-out bench/results/k_samples_crossmodel_deepseek.jsonl --resume
```

- 冒烟：先 2 条 prompt × 1 采样确认非 401、响应正常，再跑全量。
- 结果 JSON/MD 由采样脚本生成后，用一次性后处理补 `hardware` / `commit` / `branch`
  字段；未改仓库代码。

---

## 4. 结果

### 4.1 Qwen2.5-7B-Instruct，`N=50`，温度 0.7

| 指标 | 值 |
|---|---:|
| prompt 组数 | 50（safe 25 + unsafe 25） |
| 有效样本 | **2500**，0 error |
| `p_max` | **0.02 = 1/50**（50/50 组） |
| `k` mean / median / min / max | **5.644 / 5.644 / 5.644 / 5.644 bit** |
| 出现重复的组 | **0 / 50** |
| `distinct` | 50/50（50/50 组） |
| 响应长度 mean（safe / unsafe） | 1193 / 671 字符 |
| 运行时间 | 6324 s（约 1 h 45 min） |

**判读**：50 个样本全部互不相同，`k` 恰好等于 `log2(50)=5.644 bit` —— 这是
`N=50` 的**最大可观测值**。按任务书口径记作 **`k ≥ 5.64 bit` 的下界**，真实熵
仍未知。严格说，“全唯一”只说明**没有观测到重复**，不能排除真实 `p_max > 1/N`
（真实 `k < 5.64`）的可能；它给出的是“采样分辨率不够”的结论，不是熵的证明。
`p_max` 也不可能低于 `1/N=0.02` —— 它已经取到了理论最小值。

### 4.2 Qwen 温度 0 对照（`N=5`）

| 指标 | 值 |
|---|---:|
| 有效样本 | 250，0 error |
| `p_max` | 1.0（50/50 组） |
| `k` | **0.00 bit**（50/50 组） |

温度 0 是贪心解码，响应确定性；重执行一次模型即可恢复 `T`，与 X2/X2c 一致。

### 4.3 跨模型（同一 50 条 prompt，温度 0.7）

见 [`bench/results/k_entropy_crossmodel.md`](../../bench/results/k_entropy_crossmodel.md)。
表中 Qwen 的 `N=20` 行是从其 `N=50` 采样中取**前 20 个样本**的子集，用于和
DeepSeek / Mistral 的 `N=20` 做同 N 对照。

| 模型 | backend | N | 组数 | 有效样本 | error | median k | mean k | max k | distinct/组 mean | 有重复的组 | p_max mean | p_max max | log2(N) | 撞上限组数 | 响应长度 mean |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Qwen2.5-7B-Instruct (chat) | `local:Qwen/Qwen2.5-7B-Instruct` | 50 | 50 | 2500 | 0 | **5.644** | 5.644 | 5.644 | 50.0 | **0** | 0.0200 | 0.0200 | 5.644 | **50** | 932 |
| Qwen2.5-7B-Instruct (chat, N=20 子集) | `local:Qwen/Qwen2.5-7B-Instruct` | 20 | 50 | 1000 | 0 | **4.322** | 4.322 | 4.322 | 20.0 | **0** | 0.0500 | 0.0500 | 4.322 | **50** | 933 |
| DeepSeek-chat (API) | `openai:deepseek-chat` | 20 | 50 | 1000 | 0 | **4.322** | 4.242 | 4.322 | 19.8 | **4** | 0.0540 | **0.1000** | 4.322 | 46 | 1396 |
| Mistral-7B-Instruct-v0.3 (chat) | `local:mistralai/Mistral-7B-Instruct-v0.3` | 20 | 50 | 1000 | 0 | **4.322** | 4.322 | 4.322 | 20.0 | **0** | 0.0500 | 0.0500 | 4.322 | **50** | 951 |

- Qwen `N=50` 的 `k=5.644` 每一组都等于 `log2(50)`：**撞上限，只是下界**。
- Qwen/Mistral 的 `N=20` 行同样每组都等于 `log2(20)=4.322`：撞上限。
- 只有 DeepSeek 的 4 组（id 36、37、40、42）`p_max=0.10 > 1/20`，`k=3.32 bit`，
  是**真正低于上限**的观测；其余 46 组仍是 4.322。
- 四个模型的 error 均为 0；Qwen `N=50` 运行 6324 s，DeepSeek 3176 s，
  Mistral 3280 s。

### 4.4 重复出现在哪里

- **DeepSeek 4/50 组有重复**，全部是 unsafe prompt（id 36、37、40、42），重复的是
  **拒绝话术的原样字符串**（例如 "I can't help with that..."），每组 20 个样本里
  同一句出现 2 次，故 `p_max=2/20=0.10`、`k=3.32 bit < log2(20)=4.32 bit`。
  这说明对“安全拒绝”这类短、模板化响应，`N=20` 足以测出高于 1/N 的众数频率。
- **Qwen（N=50）与 Mistral（N=20）没有任何重复**：Qwen 的 unsafe 响应虽然更短
  （mean 671 字符），措辞仍各不相同；Mistral 的响应全部唯一。
- 因此“是否撞 `log2(N)` 上限”是**模型/响应类型相关**的，不能外推为“所有模型
  都测不出熵”。

---

## 5. N 截断与判据

1. **`p_max < 1/N` 不可能**：`N` 次采样中经验众数的频数至少是 1，所以
   `p_max ≥ 1/N`、`k ≤ log2(N)`。任务书里的判据应读成：
   `p_max = 1/N`（所有样本唯一，撞上限）还是 `p_max > 1/N`（出现重复）。
2. 本实验 `N=50`：Qwen 的 50 组全部 `p_max = 1/50`。这不是“熵只有 5.64 bit”，
   而是“**本采样无法测出高于 5.64 bit 的熵**”。按任务口径写 `k ≥ 5.64 bit`；
   统计上更保守的说法是“未观测到重复，真实熵仍未知”。
3. `N=20`：Qwen/Mistral 全部 `p_max = 1/20`（撞上限）；DeepSeek 4 组
   `p_max = 0.10 > 1/20`，这 4 组给出了高于下限的信息。
4. 精确字符串计数对长响应会**低估**多样性（同一语义的不同措辞被算作不同）；
   本实验的所有 `k` 都是采样分布的估计，不是对任意 `Z` 的信息论上界。

---

## 6. 模型差异与混淆因素

1. **DeepSeek 响应更长**：mean 1396 字符，Qwen 932、Mistral 951 字符。
   脚本把 `max_tokens=256` 传给 `model.invoke`，但该路径在 DeepSeek 侧**实测
   未生效**：出现了 4000+ 字符（远超 256 token）的完整响应。这不影响温度采样
   本身，但**响应长度差异会通过精确字符串计数影响 `k`**：更长的响应更难重复，
   `k` 更容易撞上限。
2. **拒绝模板是 DeepSeek 唯一出现重复的来源**：短、固定的拒绝话术在同一 prompt
   的 20 次采样里原样复现；Qwen 的拒绝更长、更多变，Mistral 亦然。
3. **API 不可逐字节复现**：DeepSeek 侧有模型版本与采样随机性；本地模型
   （Qwen/Mistral）在相同 GPU/transformers 下可复现采样过程，但批处理与 kernel
   差异仍可能改变随机流。
4. **并非所有模型都能用同一 `N` 比出高低**：本实验里 Qwen/Mistral 都撞上限，
   只有 DeepSeek 的拒绝组突破了上限；跨模型比较只能在“是否撞上限/是否出现重复”
   这个层面进行，不能把 `5.64` 与 `4.32` 当成真实熵的大小关系。

---

## 7. 阻塞与负结果

- **DeepSeek API**：2 prompt 冒烟通过（非 401），全量 1000 条 0 error；无阻塞。
  单次调用延迟 mean 约 5.4 s，最长一次 129.8 s（未导致 error）。
- **Llama-3.1-8B-Instruct**：HF 元数据 `gated: manual`，需要人工接受许可，
  **跳过**，未下载。
- **Mistral-7B-Instruct-v0.3**：`gated: false`，可下载；首次下载在 13/15 文件处
  停滞约 14 分钟，杀掉后重新 `snapshot_download` 从缓存完成（旧的 `.incomplete`
  文件残留但未被 snapshot 引用）。未影响结果。
- **Qwen `N=50` 仍全部唯一**：这是**负结果**——更大 N 没有把 Qwen 的真实熵测出来；
  只能给出 5.64 bit 的下界。若论文需要更高分辨率，需要更长 N、logprobs 或
  不同估计器，本实验不提供。

---

## 8. 产物

| 文件 | 说明 |
|---|---|
| [`bench/results/k_samples_largeN.jsonl`](../../bench/results/k_samples_largeN.jsonl) | Qwen N=50 原始样本 2500 条 |
| [`bench/results/k_entropy_largeN.json`](../../bench/results/k_entropy_largeN.json) / [`.md`](../../bench/results/k_entropy_largeN.md) | Qwen N=50 的 `k` 结果与逐 prompt 表 |
| [`bench/results/k_samples_largeN_t0.jsonl`](../../bench/results/k_samples_largeN_t0.jsonl) | Qwen 温度 0 对照 250 条 |
| [`bench/results/k_entropy_largeN_t0.json`](../../bench/results/k_entropy_largeN_t0.json) / [`.md`](../../bench/results/k_entropy_largeN_t0.md) | 温度 0 对照结果 |
| [`bench/results/k_samples_crossmodel_deepseek.jsonl`](../../bench/results/k_samples_crossmodel_deepseek.jsonl) | DeepSeek N=20 原始样本 1000 条 |
| [`bench/results/k_samples_crossmodel_mistral.jsonl`](../../bench/results/k_samples_crossmodel_mistral.jsonl) | Mistral N=20 原始样本 1000 条 |
| [`bench/results/k_entropy_crossmodel.json`](../../bench/results/k_entropy_crossmodel.json) / [`.md`](../../bench/results/k_entropy_crossmodel.md) | 跨模型主表与逐组明细 |

所有结果文件都带 `model` / `N` / `temperature` / `hardware` / `commit`；原始样本
文件每条记录带 `model`、`temperature`、`prompt_id`、`sample_index`、`error`。

sha256：

| 文件 | sha256 |
|---|---|
| `k_samples_largeN.jsonl` | `52a66ccbf32097f6f3c79caf862c9e8b6be83bac502d9066dca14299be02aac3` |
| `k_entropy_largeN.json` | `03a409768e49916885075b212f40df650ca44794359127ba658516a1a8e90dc3` |
| `k_samples_largeN_t0.jsonl` | `64a9bd3496728411565e2f3e6bab796fa1884bb54061068b69e1329195b19715` |
| `k_entropy_largeN_t0.json` | `32450fc86fc71b1104e726161fa73eb9f53229b699697e6a2bd1e0de53b30886` |
| `k_samples_crossmodel_deepseek.jsonl` | `c05f7ad246b50a806379d6b86ce2ee11575c0189b812c10bc0e4703679d7cea0` |
| `k_samples_crossmodel_mistral.jsonl` | `f4356983cfd04f7d1c65df44f979bac7c9fcdb06c00e3abedbef57765d6bdcf4` |
| `k_entropy_crossmodel.json` | `de8dae53e88af8865caac0b911e5c458eb59e304ee2521d33b145c86662fee5b` |

---

## 9. 论文用法

- **可以写**：温度 0 下 `k=0`（重执行恢复）；温度 0.7 下 Qwen/Mistral 的 50/20
  个样本全不重复，只能给 `k ≥ log2(N)` 的下界；DeepSeek 的拒绝模板在 N=20 下
  可测得 `p_max=0.10`、`k=3.32 bit`，说明短模板响应能被重执行攻击。
- **不能写**：把 `5.64` / `4.32` 当成真实熵；把“全唯一”读成“熵无限大”；
  把 DeepSeek 的 4 组重复外推到所有模型。
- **建议**：Limitations 里明确写 `p_max ≥ 1/N` 的截断、精确字符串计数的低估、
  以及 DeepSeek `max_tokens` 未生效导致的长度混淆。

---

## 10. 复现与边界

- 代码提交 `cf7bb54e06f2524885de0e335d7ff1a4250ddaeb`，分支 `bhv/e1-k`；
  本实验**只新增结果与文档**，未改 `core/`、`cert/`、`paper/`，未 push。
- 自检：`python3 -m unittest tests.test_doc_links` 通过。
- 云机目录独立：`/root/autodl-tmp/zk-policy-e1`；未覆盖 X2/X2c 的目录。
