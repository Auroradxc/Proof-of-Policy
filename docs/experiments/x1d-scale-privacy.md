# 实验 4+5：规模拓展（6 规则 / 50k）与真实响应隐私面（X1d）

> 状态：`done`（2026-11-01）。分支 `bhv/x1d-extended`，基线 `cf7bb54`。
> 云机 cgroup 16 核 / 92160 MB；binary `7f99fdb1…`；policy vkey `0x003eb14d…`；
> **post-NFA-fix**；全部证明串行（`flock /tmp/pop-proof.lock`）。
> 详细环境与 blocker 见 [X1d.md](../blockers/X1d.md)；上一轮基线见
> [X1c.md](../blockers/X1c.md)。

本文件记录两点：**规模边界往 6 规则 / 50k 推**，以及**把隐私面从 canary 换成
真实 LLM 响应**。两者都不改核心代码，只加基准与结果。

---

## 1. 实验 4a：6 规则 × {10000, 50000}（core）

### 1.1 动机

X1c 在 90 GiB 云机上量到：3 规则 × 10000 的 core 与 groth16 **都 OOM**。
本轮把规则数翻倍到 6（1 length + 3 keyword + 2 pattern），长度取 10000 与 50000，
回答两个问题：

1. 90 GiB 是否足够把「大策略包 × 长响应」推过去？
2. 如果 core 能过，groth16 需要多少额外内存/时间？

### 1.2 结果

| 长度 | 规则 | tier | 结果 | 耗时 | 峰值内存 |
|---:|---:|---|---|---:|---|
| 10000 | 6 | core | ✗ OOM（SIGKILL） | 101.09 s | 未完成 |
| 50000 | 6 | core | ✗ OOM（SIGKILL） | 99.82 s | 未完成 |

- 两个点都**不是超时**：外层 `timeout 3600` 远未到，进程在 ~100 s 被内核 SIGKILL。
- 长度从 10000 到 50000 没有改变「墙」的位置（都在 ~100 s 被杀），说明本轮先撞到的是
  **规则数/正则 chip 的内存台阶**，不是文本长度的线性增长。
- 与 X1c 的 3 规则 × 10000 OOM 一致；6 规则在 90 GiB 下仍不可行。
- **6 规则 groth16 未跑**：协议要求 core 先可证；core 两点都不可证，故没有可包装的
  core 成功点。跳过是结论的一部分，不是遗漏。

### 1.3 产物

[scale-extended.json](../../bench/results/scale-extended.json) /
[scale-extended.md](../../bench/results/scale-extended.md)。JSON 顶层 `provenance`
记录 host / binary / vkey / commit / 串行口径 / 语料 / “groth16 skipped” 的原因。

---

## 2. 实验 4b：真实 `eu_ai_act_v1` 出证

### 2.1 设置

- 策略：`policy_packs/eu_ai_act_v1.json`，3 条规则（keyword + length + pattern），
  policy_hash `5b5fd101…`。这是**真实策略包**，不是 `bench_cycles.make_policy`
  的合成 1/2/3 规则策略。
- 响应：`scripts/examples/eu_agent_reply.txt`（167 字符，sha256 `3036f3a2…`）。
- 模式：`--mode public`。
- 出证：`scripts/prove/issue_cert.py`；核心/包装两档；`/usr/bin/time -v` 量峰值。
- 验证：`scripts/verify/verify_cert.py --proof --response`。

### 2.2 结果

| tier | 结果 | 墙钟 | 峰值 RSS | `proof.bin` | `cert.json` | hiding | verify |
|---|---|---:|---:|---:|---:|---|---|
| core | ok | 48.82 s | 12,382.7 MB | 2,793,531 B | 1,846 B | none | PASS |
| groth16 | ok | 301.19 s | 30,073.9 MB | 1,874 B | 1,850 B | wrapper-only | PASS |

- 两次验证都覆盖 `signature` / `proof_verify` / `proof_outcome` / `proof_vkey` /
  `proof_sha256` / `proof_mode` / `policy_hash` / **`response_binding` 现场重算**
  （core `1654219c…`，groth16 `b3ee6a3e…`；nonce 不同）。
- `passed=True`、`violations=[]`。
- 与 X1c 的 `agent_content_v1` 相比，EU pack 同为 3 规则且含 pattern：core 48.8 s
  （X1c 矩阵 3 规则 × 200 为 50.7 s），groth16 301 s（X1c 279–344 s），
  **同量级**。EU 响应更短，但规则集合不同，不能逐点相减。

### 2.3 读法

- core 不是 witness-hiding：`proof_hiding=none`；groth16 的 1,874 B 证明来自包装器，
  是 `wrapper-only`（非后量子）。
- public 模式下响应是**出证方输入**（`vectors.json`）；交付物只有承诺/绑定。
- `response_commitment = sha256(T)` 公开可重算 —— 这是设计中的猜测-验证 oracle，
  不是泄露；真正的攻击面是重执行（E2）。

产物：[eu_ai_act_proof.json](../../bench/results/eu_ai_act_proof.json) /
[eu_ai_act_proof.md](../../bench/results/eu_ai_act_proof.md)。

---

## 3. 实验 5：真实响应的隐私面

### 3.1 样本

从 `bench/results/x2_chat/k_samples_chat.jsonl` 的 400 条真实响应里，按
`agent_content_v1` 的关键词/正则筛出 11 条命中；取 prompt_id=8：

| 字段 | 值 |
|---|---|
| label / type | `safe` / `homonyms` |
| model | `local:Qwen/Qwen2.5-7B-Instruct@cuda+chat_template` |
| 长度 | 1,451 字符 |
| sha256 | `085ed861…` |
| 触发 | `no_bad_topics.keywords=exploit` |

这正是一个值得记录的情形：**数据集标签是 safe（安全语境下的同形词），但策略
关键词规则仍然判违规**。证书如实记录 `passed=false`，而不是替样本背书。

### 3.2 探针改动

`bench/bench_privacy_surface.py` 新增：

- `--response-file`：替代内置 canary 响应；不带时行为完全不变（原 canary 冒烟保留）。
- 响应**精确子串**：整条 + 逐行（≥16 字符，最多 200 行），分别搜交付物与私有输入。
- 策略**规则名/正文**：从 pack 读 name 与 params 字面量，分交付物/私有输入搜索。
- `response_commitment` oracle：发布值 vs `sha256(T)` vs `response_binding`。
- `--out-name`：本次输出 `privacy_surface_real`。
- 表格中的 proof 大小只算 `proof.bin`；旁证单列。

### 3.3 结果（core / groth16）

| tier | hiding | `proof.bin` | canary 文本/证明 | 响应整条在交付物 | 响应行交付物 | 响应行私有输入 | 策略名交付物 | oracle |
|---|---|---|---:|---|---:|---:|---:|---|
| core | none | 2,815,724 B | 0 / 0 | 0 | 0/7 | 7/7 | 1 | 匹配 |
| groth16 | wrapper-only | 2,131 B | 0 / 0 | 0 | 0/7 | 7/7 | 1 | 匹配 |

- 两档证书 `verify_cert` 均 `RESULT: PASS`；outcome `passed=false`、
  violation `no_bad_topics(keyword_block)`，公开值只有证据承诺。
- **策略名 1 处**是证书公开的违规规则名，不是响应；规则正文 0 命中。
- **响应整条在私有输入里 0** 是 JSON 转义（换行→`\n`）造成的字节不匹配；
  逐行探针 7/7 命中私有输入。交付物两档都是 0/7。
- `response_commitment` 两档相同（`085ed861…`），因为它是 `sha256(T)`；
  `response_binding` 因 nonce 不同而不同（core `f18c89d5…`、groth16 `4a31631f…`）。

### 3.4 结论的边界（必须原样带进论文）

1. **探针 0 命中不是零知识证明**。它只说明这组 canary/子串/策略字面量没有出现在
   交付物里；换一种编码、压缩或旁路仍可能泄露。
2. **core `hiding=none`**：STARK trace 开值明文可见，这是设计事实。
3. **groth16 `wrapper-only`**：包装器层面的见证隐藏，**非后量子**；不能写成
   “zero-knowledge” 而不加限定。
4. **策略是公开输入**：规则名/正文命中交付物不是 `T` 泄露。
5. **`response_commitment` 是公开 oracle**：它使“猜测-验证”成立；真正的恢复攻击是
   重执行，归 E2 / `bench_k_entropy.py`。

产物：[privacy_surface_real.json](../../bench/results/privacy_surface_real.json) /
[privacy_surface_real.md](../../bench/results/privacy_surface_real.md)。

---

## 4. 对论文/汇报的三句话

1. **规模墙是内存，不是时间**：6 规则 × 10000/50000 在 90 GiB 上 ~100 s 被 SIGKILL；
   3 规则 × 10000 在 X1c 也已 OOM。可行域要向更大策略包推进，需要更大内存或更省的
   规则编码。
2. **真实策略可出证且可独立验证**：EU AI Act 3 规则 core 48.8 s / 12.4 GB，
   groth16 301 s / 30.1 GB / 1,874 B，两档 `verify_cert` 全 PASS（含响应绑定重算）。
3. **隐私面的负结果要带着边界说**：真实响应在 core/groth16 交付物中 0 命中，
   但 core 本就不隐藏见证，groth16 只到 wrapper-only；`canary=0 ≠ ZK`。
