# X2c blocker / 环境记录：chat-template 口径重跑

> **状态**：2026-11-01，X2c（P0-09 / P0-10 的 chat 口径对照）交付记录，分支
> `bhv/x2c-chat`（基线 `763cfc6`，X2 合并后）。**没有未解决的阻塞**：chat 口径的
> 400 条真实样本与端到端均已完成，并与 X2 的续写口径做了同 prompt 对照。

## 一句话

给 `bench_k_entropy.py` 的 `LocalBackend` 加了可选的 `--chat-template`（单轮
`user` 消息 + `apply_chat_template(add_generation_prompt=True)`，解码只取新 token），
在**同一台** RTX 5090 上重跑 20 prompt × 10 采样 × 2 温度 = **400 条 chat 口径样本**。
结果与 X2 的续写口径同型：温度 0 时 `k=0`；温度 0.7 时 20/20 组 10 个样本互不
相同，`k = log2(10) = 3.32 bit`（`N=10` 的估计上限）。端到端的拒绝代理率从
续写口径的 15% 升到 **35%**，响应违规率从 100% 降到 **90%**。

## 环境与并行

- 云机 cgroup **16 CPU / 90 GiB**，RTX 5090 32 GB；模型复用
  `/root/autodl-tmp/hf-cache`（未重新下载）。
- **X1c 的 groth16 同时在跑**。启动前可用内存约 45 GiB，运行中约 29 GiB
  （X1c 的 `pop-script` RSS 约 10.6 GiB + 本任务的 7B fp16 约 15 GiB 显存 /
  3.4 GiB 主机内存），未触发 OOM；没有杀 X1c、没有与它抢 GPU。
- 本任务使用独立目录 `/root/autodl-tmp/zk-policy-x2c/`，未覆盖 X2 的目录。

## 代码改动（只改了一个文件）

`bench/bench_k_entropy.py`：

- `LocalBackend(..., chat_template=False)`；开启时把 prompt 包成
  `[{"role": "user", "content": prompt}]`，经
  `tok.apply_chat_template(..., tokenize=False, add_generation_prompt=True)`
  得到 `text`，再对 `text` tokenize；生成后只解码新 token。
- 新增 `--chat-template`（`store_true`，缺省关闭，旧续写行为完全不变）。
- 只影响 `--backend local:`；`stub` / `openai:` / `anthropic:` 路径未改。
- `k_entropy.json/md` 里记录 `chat_template` 与 `+chat_template` 模型名，
  复现命令自动带上该 flag；报告里补了 `N` 截断说明。

## 方法边界（论文必须写）

1. **XSTest 标签是 prompt 级**，响应级没有 ground truth；`response_policy`
   只报运行指标。
2. **`refusal_proxy` 是前缀启发式**，不是人工标注。
3. **`k` 被 `N` 截断**：`p_max ≥ 1/N`，故 `k ≤ log2(N)`。本任务 `N=10`，
   温度 0.7 的 20 组全部 10/10 互不相同，`k=3.32` 恰好是上限，不是真实熵；
   X2 的 `N=20` 上限是 4.32 bit，两边数值不可直接比较。
4. **chat 口径与续写口径不同**：chat 模板改变了输入分布和停止行为，因此
   `k`、响应长度、拒绝率都只能在各自口径内解读。`--chat-template` 缺省关闭，
   保证 X2 结果可原样重跑。
5. **端到端取的是温度 0 的贪心响应**：`pick=first` 取 `sample_index=0`，
   样本文件里同一 prompt 先写温度 0，故报告中 20 条响应均为 temperature 0。
6. **90% 响应违规率不是模型真实有害率**：`safety_xstest_v1` 是关键词策略，
   safe prompt 的正常回答也常被判违规（chat 口径 9/10），这反映策略误报。

## 未做

- **未跑 SP1 真证明**：按任务用 `--no-prove` 做 host check，且不与 X1c 抢证明。
- **未改 core / cert / paper / circuits**；未 push。
- 未把密码、模型缓存或云机日志写进仓库。

## 产物

- [`bench/results/x2_chat/k_entropy_chat.md`](../../bench/results/x2_chat/k_entropy_chat.md) /
  [`k_entropy.json`](../../bench/results/x2_chat/k_entropy.json)
- [`bench/results/x2_chat/k_samples_chat.jsonl`](../../bench/results/x2_chat/k_samples_chat.jsonl)（400 条）
- [`bench/results/x2_chat/real_llm_e2e_chat.md`](../../bench/results/x2_chat/real_llm_e2e_chat.md) /
  [`real_llm_e2e.json`](../../bench/results/x2_chat/real_llm_e2e.json)
- [`bench/results/x2_chat/compare_chat_vs_continuation.md`](../../bench/results/x2_chat/compare_chat_vs_continuation.md)
- 对照：`bench/results/x2_chat/no_template/`（同 20 prompt、`N=5`、关闭 chat template；
  200 条、0 error。温度 0 的 100 条响应与 X2 **逐字节相同**，端到端指标与 X2 同批
  20 prompt 完全一致，证明旧口径未被本改动破坏）
