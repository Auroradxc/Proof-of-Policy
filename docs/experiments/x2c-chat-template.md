# X2c 实验记录：Qwen2.5-7B chat-template 口径的 `k` 与端到端

> **实验 ID**：X2c ｜ **日期**：2026-11-01 ｜ **状态**：完成并合并
> **分支/提交**：`bhv/x2c-chat` → `47f367a`；合并 `9033d4f`
> **目的**：给 X2 的“裸续写”口径补上 **chat template** 口径，隔离“模型是在续写
> prompt 还是在对话作答”对 `k` 与端到端指标的影响。
>
> **一句话结论**：chat template 不改变“温度 0 下 `k=0`”这一结论；它主要把
> unsafe prompt 的拒绝从 **3/10 提到 7/10**，响应违规率从 **100% 降到 90%**。
> `k` 的绝对值仍被采样数 `N` 截断，不能当真实熵。

---

## 1. 实验环境

| 项 | 值 |
|---|---|
| 平台 | AutoDL 云机（`autodl-container-14574f97ce-6e5bc639`） |
| CPU/内存配额 | cgroup **16 CPU / 90 GiB**（`/proc/meminfo` 报宿主 754 GiB，以 cgroup 为准） |
| GPU | **NVIDIA GeForce RTX 5090 32 GB**（sm_120）；X2c 占用约 **15.2 GiB** |
| OS | Ubuntu 22.04 x86_64（云机容器） |
| Python | 3.10.8（`/root/miniconda3/bin/python`） |
| PyTorch | 2.14.1+cu130 |
| transformers | 5.20.2 |
| accelerate | 1.15.0 |
| 模型 | `Qwen/Qwen2.5-7B-Instruct`（fp16） |
| 模型缓存 | `/root/autodl-tmp/hf-cache`（复用 X2 已下载的 14 个文件，未重下） |
| 网络绕行 | `HF_ENDPOINT=https://hf-mirror.com`；`HF_HUB_DISABLE_XET=1`（镜像不代理 Xet）；`HF_HOME=/root/autodl-tmp/hf-cache`（系统盘仅 17 GB） |
| 并行 | X1c 同时在同机跑 groth16（CPU/内存）；X2c 只用 GPU，启动时可用内存约 45 GiB、运行中约 29 GiB，未 OOM、未杀 X1c |

依赖冲突记录：`brotlipy 0.7.0` 与 `httpx2` 不兼容，已 `pip uninstall brotlipy`。

---

## 2. 数据

| 项 | 内容 |
|---|---|
| 数据集 | XSTest（Röttger et al., NAACL 2024），**CC-BY-4.0** |
| 归一化文件 | [`scripts/examples/datasets/wave2/prompts_xstest.jsonl`](../../scripts/examples/datasets/wave2/prompts_xstest.jsonl)，450 条（safe 250 / unsafe 200） |
| 本实验 prompt | **20 条**：safe `1–10` + unsafe `26–35`（按文件顺序分层取前 10+10） |
| 策略包 | [`policy_packs/safety_xstest_v1.json`](../../policy_packs/safety_xstest_v1.json)（XSTest focus 词的黑名单） |
| chat 样本 | **400 条** = 20 prompt × 10 采样 × 温度 `{0, 0.7}`，0 error |
| 无模板对照 | **200 条** = 同 20 prompt × 5 采样 × 温度 `{0, 0.7}`，0 error |
| 采样长度 | 脚本默认 `--max-tokens 256`；响应实际长度 mean 974.9 字符 |
| 温度 0 | 贪心解码（`do_sample=False`） |
| 温度 0.7 | `do_sample=True, temperature=0.7, top_p=1.0` |

数据文件：

- chat 原始样本：[`bench/results/x2_chat/k_samples_chat.jsonl`](../../bench/results/x2_chat/k_samples_chat.jsonl)（400 行）
- chat `k` 结果：[`bench/results/x2_chat/k_entropy_chat.md`](../../bench/results/x2_chat/k_entropy_chat.md)
- chat 端到端：[`bench/results/x2_chat/real_llm_e2e_chat.md`](../../bench/results/x2_chat/real_llm_e2e_chat.md)
- 无模板对照：[`bench/results/x2_chat/no_template/k_samples.jsonl`](../../bench/results/x2_chat/no_template/k_samples.jsonl)（200 行）

---

## 3. 步骤

### 3.1 代码改动（`bench/bench_k_entropy.py`）

1. `LocalBackend` 新增 `chat_template: bool = False`。
2. `generate()` 在开启时把 prompt 包成单轮 `user` 消息：

   ```python
   messages = [{"role": "user", "content": prompt}]
   text = self.tok.apply_chat_template(
       messages, tokenize=False, add_generation_prompt=True)
   ```

   然后对 `text` 做 tokenize；生成后只解码**新 token**。
3. 新增 CLI `--chat-template`（`store_true`，缺省关闭）；只作用于
   `--backend local:`，stub/OpenAI/Anthropic 路径不变。
4. `k_entropy.json/md` 记录 `chat_template` 与 `+chat_template` 模型名，
   复现命令自动带 flag；报告增加 `N` 截断说明。
5. 自检：`python3 -m py_compile bench/bench_k_entropy.py`；云机上用 Qwen
   tokenizer 对 2 条 prompt 冒烟通过。

### 3.2 云机运行

```bash
export PATH=/root/miniconda3/bin:$PATH
export HF_HOME=/root/autodl-tmp/hf-cache
export HF_ENDPOINT=https://hf-mirror.com
export HF_HUB_DISABLE_XET=1

cd /root/autodl-tmp/zk-policy-x2c
setsid nohup python3 bench/bench_k_entropy.py \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
  --backend local:Qwen/Qwen2.5-7B-Instruct --chat-template \
  --max-prompts 20 --n-samples 10 --temperatures 0,0.7 \
  --out-dir bench/results/x2_chat \
  --samples-out bench/results/x2_chat/k_samples_chat.jsonl \
  --device cuda --resume \
  > bench/results/x2_chat/run_chat.log 2>&1 &
```

- 400 条样本，运行日志末行 `... 400 samples, 1056s`（约 17.6 分钟，含采样）。
- 生成后自动写 `k_entropy.json/md`。

### 3.3 端到端

```bash
python3 bench/bench_real_llm_e2e.py \
  --samples bench/results/x2_chat/k_samples_chat.jsonl \
  --policy policy_packs/safety_xstest_v1.json \
  --out-dir bench/results/x2_chat --no-prove
```

- `--no-prove` 只做 host check；不跑 SP1。
- 每个 prompt 取 `sample_index=0`，即**温度 0 的贪心响应**。

### 3.4 无模板对照

同 20 prompt、关闭 `--chat-template`、`--n-samples 5`、温度 `{0,0.7}`，
输出到 `bench/results/x2_chat/no_template/`。用于确认：

- `--chat-template` 缺省关闭时旧口径未被破坏；
- 同批温度 0 响应与 X2 逐字节相同。

---

## 4. 结果

### 4.1 `k`（N=10）

| 温度 | 组数 | mean / median | min / max | `k=0` 比例 | `k<40 bit` 比例 |
|---|---:|---:|---:|---:|---:|
| 0.0 | 20 | **0.00 / 0.00** | 0.00 / 0.00 | 100% | 100% |
| 0.7 | 20 | **3.32 / 3.32** | 3.32 / 3.32 | 0% | 100% |

- 温度 0：20/20 组 `p_max=1`、`k=0` ⇒ 贪心解码下重执行一次模型即可恢复 `T`。
- 温度 0.7：20/20 组 **10/10 响应互不相同**，`p_max=1/10`，
  `k=log₂10 = 3.32 bit` —— **恰好是 N=10 的估计上限**，不是真实熵。
- 因此 `k<40 bit` 的 100% **不能**读成“隐藏失败”；只能读成
  “本采样无法测出高于 3.32 bit 的熵”。

### 4.2 端到端（温度 0 贪心响应）

**prompt 级策略质量**（与 XSTest 标签比）：

| TP | FP | TN | FN | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|---:|---:|
| 8 | 8 | 2 | 2 | **0.5000** | **0.8000** | **0.6154** |

> 这与 X2 续写口径完全相同：同一策略判同一批 prompt，与模型输出口径无关。

**响应级运行指标**：

| 指标 | 值 |
|---|---|
| 响应违规 | **18 / 20 = 90.00%** |
| 拒绝代理率 | **35.00%**（7/20，全部在 unsafe） |
| safe 拒绝 | 0/10 |
| unsafe 拒绝 | **7/10** |
| 响应长度 mean / median | **974.9 / 1135** 字符（min 269，max 1461） |
| safe 响应 mean 长度 | 1215.3 字符 |
| unsafe 响应 mean 长度 | 734.4 字符 |

**拒绝代理（前缀启发式）**：

| TP | FP | TN | FN | Precision | Recall | F1 |
|---:|---:|---:|---:|---:|---:|---:|
| 7 | 0 | 10 | 3 | **1.0000** | **0.7000** | **0.8235** |

### 4.3 chat vs 续写（同 20 prompts）

| 指标 | chat（N=10） | X2 续写（N=20） | 无模板同批（N=5） |
|---|---:|---:|---:|
| `k` 温度 0 | 0.00 | 0.00 | 0.00 |
| `k` 温度 0.7 | **3.32**（log₂10） | **4.32**（log₂20） | **2.32**（log₂5） |
| 响应违规率 | **90%** | **100%** | 100% |
| 拒绝代理率 | **35%** | **15%** | 15% |
| 拒绝代理 F1 | **0.8235** | 0.4615 | 0.4615 |
| unsafe 拒绝 | **7/10** | 3/10 | 3/10 |
| safe 拒绝 | 0/10 | 0/10 | 0/10 |
| 长度 mean / median | 974.9 / 1135 | 986.6 / 1109.5 | 986.6 / 1109.5 |

**无模板对照的有效性**：200 条中 100 条温度 0 响应与 X2 **逐字节相同**；
端到端指标与 X2 同批 20 prompt 完全一致。这确认两次运行用的是同一批 prompt、
同一模型、同一贪心解码，`--chat-template` 缺省关闭时旧口径未被破坏。

---

## 5. 解读与边界

1. **chat template 主要改变拒绝行为**：拒绝代理率 15% → 35%，unsafe 拒绝
   3/10 → 7/10；响应违规率 100% → 90%。这说明 X2 的低拒绝率很大程度是
   **续写口径的产物**，不是对话模型的实际拒答倾向。
2. **90% 响应违规率不是模型真实有害率**：`safety_xstest_v1` 是关键词黑名单，
   chat 口径下 safe prompt 的正常回答也有 9/10 被判违规；响应级没有 ground
   truth。论文必须写“策略质量 ≠ 证明正确性”。
3. **`k` 的绝对值不可跨列比较**：三列分别撞 `log₂10`、`log₂20`、`log₂5` 的
   采样上限；只能定性读“温度 0 确定性、温度 0.7 采不到重复”。真正的隐藏
   上界需要更大 N、logprobs 或不同估计器，本实验不提供。
4. **XSTest 标签是 prompt 级**；拒绝代理是前缀启发式（`I can't` / `I'm sorry`
   / `As an AI` / `抱歉`），不是人工标注。
5. **规模**：20 prompts、单一模型 Qwen2.5-7B、单机；不能外推到所有模型/提示。
6. **未跑 SP1 真证明**：X2c 只做 host check；与 X1c 的 groth16 并行，未抢资源。

---

## 6. 产物与可复现性

| 文件 | 说明 | sha256 |
|---|---|---|
| `bench/results/x2_chat/k_samples_chat.jsonl` | 400 条 chat 样本 | `4e066047ea61cd48bac41610e4c07a41f280eeb786fbe2c98bc0c4ffbe92f1b9` |
| `bench/results/x2_chat/k_entropy.json` | 聚合与逐 prompt `k` | `bc893c5d03033965b1d1682da4704b5b7fbb984eac91352a54348dd0f9915a57` |
| `bench/results/x2_chat/real_llm_e2e.json` | 端到端原始结果 | `60bb965c1fa2f7346371ee4596be011e3de9ef3a04eac7db909d08eefedd9371` |
| `bench/results/x2_chat/no_template/k_samples.jsonl` | 200 条无模板对照 | `105fa402eec797089e17fe5c090e861261ba6255558502462f0e504374e65baf` |

报告文件：

- [`bench/results/x2_chat/k_entropy_chat.md`](../../bench/results/x2_chat/k_entropy_chat.md)
- [`bench/results/x2_chat/real_llm_e2e_chat.md`](../../bench/results/x2_chat/real_llm_e2e_chat.md)
- [`bench/results/x2_chat/compare_chat_vs_continuation.md`](../../bench/results/x2_chat/compare_chat_vs_continuation.md)
- [`docs/blockers/X2c.md`](../blockers/X2c.md)

提交：`47f367a`（分支 `bhv/x2c-chat`），合并 `9033d4f`（`tdsc-conversion`）。

---

## 7. 复现命令

```bash
# 1) chat 口径采样（云机 GPU）
python3 bench/bench_k_entropy.py \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
  --backend local:Qwen/Qwen2.5-7B-Instruct --chat-template \
  --max-prompts 20 --n-samples 10 --temperatures 0,0.7 \
  --out-dir bench/results/x2_chat \
  --samples-out bench/results/x2_chat/k_samples_chat.jsonl \
  --device cuda --resume

# 2) 端到端（host check）
python3 bench/bench_real_llm_e2e.py \
  --samples bench/results/x2_chat/k_samples_chat.jsonl \
  --policy policy_packs/safety_xstest_v1.json \
  --out-dir bench/results/x2_chat --no-prove

# 3) 无模板对照
python3 bench/bench_k_entropy.py \
  --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
  --backend local:Qwen/Qwen2.5-7B-Instruct \
  --max-prompts 20 --n-samples 5 --temperatures 0,0.7 \
  --out-dir bench/results/x2_chat/no_template \
  --samples-out bench/results/x2_chat/no_template/k_samples.jsonl \
  --device cuda --resume
```

---

## 8. 论文用法（给 P）

- **可以写**：温度 0 下 `k=0`（贪心确定性 ⇒ 重执行恢复），chat 与续写一致；
  chat 口径下 unsafe 拒绝 7/10、拒绝代理 F1 0.8235，说明 X2 的低拒绝率是
  续写口径产物；prompt 级策略 P/R/F1 0.5/0.8/0.6154，策略质量与证明正确性
  分开。
- **不能写**：`k<40` 或 `k=3.32` 作为真实熵；90% 响应违规率作为模型有害率；
  拒绝代理作为人工标注。
- **建议**：§5.10 用 `k=0` + chat e2e；把 `k` 的 N 截断与 X2 的续写口径差异
  放进 Limitations；不要用 X2c 覆盖 X2 的 2000 条大样本 `k` 表，两者口径
  不同、不可混表。
