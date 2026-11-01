# 跨模型实测猜测熵 `k`（E1）

**生成时间**：2026-11-01T15:41:40Z  
**提交**：`cf7bb54e06f2524885de0e335d7ff1a4250ddaeb`（分支 `bhv/e1-k`）  
**prompts**：`scripts/examples/datasets/wave2/prompts_xstest.jsonl`（50 条：XSTest 分层 safe 25 + unsafe 25）  
**温度**：0.7  
**chat template**：Qwen / Mistral 开启（单轮 user）；DeepSeek 走 chat API 本身  

## 主表

| 模型 | backend | N | 组数 | 有效样本 | error | median k | mean k | max k | distinct/组 mean | 有重复的组 | p_max mean | p_max max | log2(N) | 撞上限组数 | 响应长度 mean |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Qwen2.5-7B-Instruct (chat, N=50) | `local:Qwen/Qwen2.5-7B-Instruct` | 50 | 50 | 2500 | 0 | 5.644 | 5.644 | 5.644 | 50.0 | 0 | 0.0200 | 0.0200 | 5.644 | 50 | 932 |
| Qwen2.5-7B-Instruct (chat, N=20 子集) | `local:Qwen/Qwen2.5-7B-Instruct` | 20 | 50 | 1000 | 0 | 4.322 | 4.322 | 4.322 | 20.0 | 0 | 0.0500 | 0.0500 | 4.322 | 50 | 933 |
| DeepSeek-chat (API, N=20) | `openai:deepseek-chat` | 20 | 50 | 1000 | 0 | 4.322 | 4.242 | 4.322 | 19.8 | 4 | 0.0540 | 0.1000 | 4.322 | 46 | 1396 |
| Mistral-7B-Instruct-v0.3 (chat, N=20) | `local:mistralai/Mistral-7B-Instruct-v0.3` | 20 | 50 | 1000 | 0 | 4.322 | 4.322 | 4.322 | 20.0 | 0 | 0.0500 | 0.0500 | 4.322 | 50 | 951 |

## 怎么读

- **`p_max < 1/N` 在有限 N 次采样里不可能**：最小可能的经验众数频率就是 `1/N`（所有样本互不相同）。因此本表能区分的是 `p_max = 1/N`（全唯一、撞上限）与 `p_max > 1/N`（出现重复）。`k = log2(N)` 是**该 N 下的最大可观测估计**，按任务口径记作下界；严格说，全唯一只说明未观测到重复，不能排除真实 `p_max > 1/N`（真实 `k` 更小）的可能，真实熵仍未知。
- `median k` 一列若等于 `log2(N)`，说明该模型在该温度下 **N 个样本里没有重复**；真实 `k` 可能更高，本实验无法给出上界。
- 不同 N 的模型不能直接比 `k` 绝对值；同 N 的列才可比。Qwen 的 N=20 行是从其 N=50 采样中取前 20 个样本的子集，用于与 DeepSeek / Mistral 的 N=20 对照。
- 精确字符串计数会低估长响应的多样性；API 采样与本地采样都不可逐字节复现。

## 复现

```bash
# Qwen（云机 GPU，chat template）
python3 bench/bench_k_entropy.py --backend local:Qwen/Qwen2.5-7B-Instruct \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl --chat-template \
  --max-prompts 50 --n-samples 50 --temperatures 0.7 --device cuda
# DeepSeek（API）
OPENAI_API_KEY=... OPENAI_BASE_URL=https://api.deepseek.com \
  OPENAI_API_BASE=https://api.deepseek.com \
  python3 bench/bench_k_entropy.py --backend openai:deepseek-chat \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
  --max-prompts 50 --n-samples 20 --temperatures 0.7
# Mistral（云机 GPU，chat template）
python3 bench/bench_k_entropy.py --backend local:mistralai/Mistral-7B-Instruct-v0.3 \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl --chat-template \
  --max-prompts 50 --n-samples 20 --temperatures 0.7 --device cuda
```

## 环境

- 云机：AutoDL container autodl-container-14574f97ce-6e5bc639，16 vCPU (cgroup cpu.max 1600000/100000)，90.0 GiB，NVIDIA GeForce RTX 5090 32 GB (sm_120)，Python 3.10.8，torch 2.14.1+cu130，transformers 5.20.2。
- DeepSeek：WSL2 Ubuntu 22.04 (client host) 调 `https://api.deepseek.com`，本地不做推理。
- 代码提交 `cf7bb54e06f2524885de0e335d7ff1a4250ddaeb`（分支 `bhv/e1-k`），只新增结果与文档。
