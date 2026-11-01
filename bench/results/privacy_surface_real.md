# 隐私面探针（P0-07 / Wave 2 X1）

**生成时间**：2026-11-01T13:10:25Z  **pack**：`/root/autodl-tmp/zk-policy-x1d/policy_packs/agent_content_v1.json`  
**canary**：`POP_PRIVACY_CANARY_7f3a9c`  **响应来源**：`file:/root/autodl-tmp/x1d-work/real_response.txt`  **响应哈希**：`085ed861a97b7dbc…`（1451 字符）

**口径**：host `autodl-container-14574f97ce-6e5bc639`（cgroup 16 核 / 92160 MB）；binary `7f99fdb1…`；policy vkey `0x003eb14de80339bddef2b9207ef27469088267888bb9bebb9836b4ee701fd7be`；commit `cf7bb54e06f2524885de0e335d7ff1a4250ddaeb`（post-NFA-fix=True）；isolated: one proof process at a time under flock /tmp/pop-proof.lock。

| tier | status | hiding | proof 大小 | canary 在文本 | canary 在证明 | 响应整条在交付物 | 响应行命中交付物 | 策略名命中交付物 |
|---|---|---|---:|---|---|---|---|---|
| core | ok | none | 2815724 B | 0 | 0 | 0 | 0 | 1 |
| groth16 | ok | wrapper-only | 2131 B | 0 | 0 | 0 | 0 | 1 |

响应探针：两档响应下，整条与逐行精确子串分别在**交付物**（`cert.json` / `payload.json` / `proof*`）与**出证方私有输入**（`vectors.json` / `results.json`）里搜。策略规则名/正文是**公开输入**，命中和响应命中必须分开读。

**真实响应来源**：`bench/results/x2_chat/k_samples_chat.jsonl` 的 prompt_id=`8`（label=`safe`，type=`homonyms`，model=`local:Qwen/Qwen2.5-7B-Instruct@cuda+chat_template`）；触发规则：no_bad_topics.keywords=exploit。

## 逐档明细

### `core`（status=ok，hiding=none）

- 证明工件：`proof.bin` 2815724 B（全部 `proof*` 旁证合计 5632025 B）。
- 证书 outcome：passed=False；violations=no_bad_topics(keyword_block)（公开值只给证据承诺，不给证据明文）。
- 响应整条：交付物 0 处 / 私有输入 0 处。
- 响应逐行子串（探 7 行）：交付物 0 行 / 私有输入 7 行。
- 策略规则名：交付物 1 处；规则正文字面量：交付物 0 处。
- `response_commitment` oracle：published=`085ed861a97b7dbc74c144588574b2c7f0caa3618f2cd8cdf46d7f652b805510`，`sha256(T)` 匹配=True。

### `groth16`（status=ok，hiding=wrapper-only）

- 证明工件：`proof.bin` 2131 B（全部 `proof*` 旁证合计 3542 B）。
- 证书 outcome：passed=False；violations=no_bad_topics(keyword_block)（公开值只给证据承诺，不给证据明文）。
- 响应整条：交付物 0 处 / 私有输入 0 处。
- 响应逐行子串（探 7 行）：交付物 0 行 / 私有输入 7 行。
- 策略规则名：交付物 1 处；规则正文字面量：交付物 0 处。
- `response_commitment` oracle：published=`085ed861a97b7dbc74c144588574b2c7f0caa3618f2cd8cdf46d7f652b805510`，`sha256(T)` 匹配=True。

## 怎么读

- **响应/canary 出现在交付物里 > 0** = 该档**确定泄露** `T` 的明文；`core`/`compressed` 的 trace 开值本来就明文可见，这一档 `hiding=none`。
- **命中 = 0 只说明这一组探针没找到，不是零知识证明**；`groth16/plonk` 才在包装器层面隐藏见证（非后量子）。
- `response_commitment` 是公开、可离线重算的 `T` 的函数 —— 它本来就是猜测-验证 oracle；真正的攻击是**重执行**（E2）。
- 策略规则名/正文命中交付物**不是** `T` 泄露：策略是公开输入。本例的 1 处策略名命中是证书公开的**违规规则名**（`no_bad_topics`），不是响应。
- 「响应整条在私有输入」为 0 有个技术原因：`vectors.json` 把换行转义成 `\n`，整条字节串对不上；逐行探针在私有输入里 7/7 命中，说明原文确实在**出证方输入**里 —— 那本来就不是交付物。
- `re_execution.status=skipped` 是诚实的：本脚本不跑模型；`bench_k_entropy.py` 负责测 `k`。

## 复现

```bash
python3 bench/bench_privacy_surface.py --tiers core --no-prove --out-dir bench/results
# 云机（真实响应）：
SP1_PROVER=cpu python3 bench/bench_privacy_surface.py --tiers core,groth16 \
  --response-file /path/to/real_response.txt --out-name privacy_surface_real
```
