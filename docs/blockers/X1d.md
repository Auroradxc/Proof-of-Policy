# X1d：规模拓展（6 规则 / 50k）与真实响应隐私面

> **状态**：`done`（2026-11-01）· 6 规则两点 **OOM**，EU AI Act core/groth16 均 `PASS`，
> 真实响应隐私面 core/groth16 均 `ok`
> **任务**：X1d / 实验 4（规模拓展）+ 实验 5（真实响应隐私面）
> **分支 / worktree**：`bhv/x1d-extended` · `.claude/worktrees/agent-a6c787e6fc0c189b7`
> **基线**：`cf7bb54`
> **云机**：`connect.bjb2.seetacloud.com:37499`，host `autodl-container-14574f97ce-6e5bc639`
> **结果头（口径）**：cgroup **16 核 / 92160 MB**（宿主 128 核 / 754 GiB 仅记录）；
> binary sha256 `7f99fdb11a4a859c45598c384db3b98dd50426210adbc14d6b576c4d15dda49f`；
> policy vkey `0x003eb14de80339bddef2b9207ef27469088267888bb9bebb9836b4ee701fd7be`；
> 构建基线 `e45178b`、**post-NFA-fix**；groth16 缓存
> `/root/autodl-tmp/sp1-cache/groth16`（官方 v6.1.0，手工播种）；
> **全部证明一次一个**（`flock /tmp/pop-proof.lock`，`SP1_PROVER=cpu`、`GOMAXPROCS=16`）。

---

## 0. 一句话

- **6 规则 × {10000, 50000} 字符（core）两个点都被 SIGKILL（OOM）**：
  101.09 s / 99.82 s。按协议 core 不可证就不进 groth16，因此 **6 规则 groth16 未跑**。
- 真实 `eu_ai_act_v1`（3 规则含 `pattern_block`）用 `--mode public` 出证两档：
  **core 48.82 s / 12.4 GB / 2,793,531 B**，**groth16 301.19 s / 30.1 GB / 1,874 B**；
  两档 `verify_cert.py --proof --response` 均 `RESULT: PASS`。
- 真实 chat 响应（prompt_id=8，含 “exploit”）隐私面：
  **core `hiding=none`、groth16 `wrapper-only`；响应整条/逐行子串在交付物中 0 命中，
  `response_commitment = sha256(T)` 可离线重算**。`canary=0` 只是探针负结果，**不是**
  ZK 证明。

---

## 1. 实验 4：规模拓展

### 1.1 6 规则 × {10000, 50000}（core）

命令（云机独立目录，单进程，外层 `timeout 3600`）：

```bash
cd /root/autodl-tmp/zk-policy-x1d
flock /tmp/pop-proof.lock env SP1_PROVER=cpu GOMAXPROCS=16 \
  SP1_GROTH16_CIRCUIT_PATH=/root/autodl-tmp/sp1-cache/groth16 \
  timeout 3600 python3 bench/bench_scale.py \
    --out bench/results/scale-extended.json \
    --proof-modes core --lengths 10000,50000 --rules 6
```

| 长度 | 规则 | tier | 结果 | 耗时 | 说明 |
|---:|---:|---|---|---:|---|
| 10000 | 6 | core | ✗ OOM | 101.09 s | SIGKILL，内核内存不足 |
| 50000 | 6 | core | ✗ OOM | 99.82 s | SIGKILL，内核内存不足 |

读法：

- 6 条规则 = 1 条 `length_bound` + 3 条 `keyword_block` + 2 条 `pattern_block`
  （`bench_cycles.make_policy`）。X1c 已量到 3 规则 × 10000 在 90 GiB 下 OOM；
  本轮规则数翻倍后，**10000 与 50000 都在同一 ~100 s 内存墙处被杀**，长度不是主变量。
- 两个失败点是 **OOM 而不是超时**：进程在 ~100 s 就被内核杀掉，没有「再等等」的空间。
- **6 规则 groth16 未尝试**：按实验设计，core 不可证就不进入 groth16（后者还要叠加
  约 +20 GB 的包装开销）。这不是「groth16 不行」，而是「core 在这一格先撞墙」。

产物：[scale-extended.json](../../bench/results/scale-extended.json) /
[scale-extended.md](../../bench/results/scale-extended.md)（含 `provenance`）。

### 1.2 真实 `eu_ai_act_v1`（core / groth16）

策略 3 条规则：`banned_high_risk_topics`（keyword）、`disclosure_length`（length）、
`no_pii_email`（pattern）；响应 `scripts/examples/eu_agent_reply.txt`（167 字符，
sha256 `3036f3a2…`）；**`--mode public`**。

| tier | 结果 | 墙钟 | 峰值 RSS | `proof.bin` | `cert.json` | hiding | verified |
|---|---|---:|---:|---:|---:|---|---|
| core | ok | **48.82 s** | **12,382.7 MB** | **2,793,531 B** | 1,846 B | none | ✅ PASS |
| groth16 | ok | **301.19 s** | **30,073.9 MB** | **1,874 B** | 1,850 B | wrapper-only | ✅ PASS |

- 两档独立验证均 `RESULT: PASS`，含 **response_binding 由送达的 T′ 现场重算**：
  core `1654219c…`、groth16 `b3ee6a3e…`（两次 nonce 不同，绑定不同）。
- `passed=True`、`violations=[]`：示例回复满足三条规则。
- core 的 12.4 GB 落在 PROVER 地板 ~10.5 GB 之上；groth16 的 30.1 GB 与 X1c 的
  `agent_content_v1`（29.7–35.1 GB）同量级。
- **隐藏性**：core `hiding=none`；groth16 `wrapper-only`（非后量子）。

产物：[eu_ai_act_proof.json](../../bench/results/eu_ai_act_proof.json) /
[eu_ai_act_proof.md](../../bench/results/eu_ai_act_proof.md)。

---

## 2. 实验 5：真实响应隐私面

### 2.1 代码改动（仅 `bench/bench_privacy_surface.py`）

- 新增 `--response-file`：用真实响应替代内置 canary 文本；**缺省行为不变**
  （不带该参数仍是原来的 canary 冒烟响应）。
- 新增 `--out-name`：本次写 `privacy_surface_real.{json,md}`。
- 探针扩展：
  1. **响应精确子串**：整条 + 逐行（长度 ≥16 的非空行，最多 200 行）分别在
     **交付物**（`cert.json` / `payload.json` / `proof*`）与**出证方私有输入**
     （`vectors.json` / `results.json`）中搜索；
  2. **策略规则名 / 正文**：从 pack 读规则名与 `params` 里的字符串字面量，
     同样分交付物/私有输入搜索（策略是公开输入，命中不构成 `T` 泄露）；
  3. **`response_commitment` oracle**：发布值、`sha256(T)`、是否离线重算一致、
     `response_binding`；
  4. 保留原 canary 探针与 `re_execution=skipped`。
- `proof 大小` 只算真正的 `proof.bin`，旁证（`.pv`/`.bytes`/`.meta`）单列。

### 2.2 样本选择

从 `bench/results/x2_chat/k_samples_chat.jsonl`（400 条）筛出 11 条命中
`agent_content_v1` 关键词的响应；取 prompt_id=8（label=safe、type=homonyms、
Qwen2.5-7B-Instruct、1451 字符）——它在安全语境里使用 “exploit”，**仍然触发
`no_bad_topics` 关键词规则**，正好覆盖「合规模型输出 + 策略违规」这一情形。

### 2.3 结果（`--tiers core,groth16`，`--mode private` 默认）

| tier | status | hiding | `proof.bin` | canary 文本/证明 | 响应整条在交付物 | 响应行命中交付物 | 响应行命中私有输入 | 策略名在交付物 | oracle |
|---|---|---|---:|---|---:|---:|---:|---:|---|
| core | ok | none | 2,815,724 B | 0 / 0 | 0 | 0/7 | 7/7 | 1 | `sha256(T)` 匹配 ✅ |
| groth16 | ok | wrapper-only | 2,131 B | 0 / 0 | 0 | 0/7 | 7/7 | 1 | `sha256(T)` 匹配 ✅ |

- 两档 `verify_cert.py --proof --response` 均 `RESULT: PASS`。
- 证明 outcome：`passed=false`、`violations=[no_bad_topics(keyword_block)]`；
  公开值只给**规则名 + 证据承诺**，不给证据明文。
- **策略名 1 处命中**是证书公开的违规规则名（`no_bad_topics` 也出现在 `proof.bin`
  的公开值里），**不是响应**；规则正文字面量在交付物中 0 命中。
- **响应整条在私有输入里也是 0** 是 JSON 转义所致（`vectors.json` 把换行写成 `\n`）；
  逐行探针在私有输入里 7/7 命中，证明确实在**出证方输入**里 —— 那本来就不是交付物。
- `response_commitment = 085ed861… = sha256(T)`，两档相同；它是公开、可离线重算的
  猜测-验证 oracle，设计如此。真正的攻击是**重执行**（E2），不在本轮。

### 2.4 必须写进论文的边界

1. **`canary=0` / 响应子串 0 命中 ≠ 零知识证明**，只说明这组探针没找到。
2. **core 的 `hiding=none` 是设计事实**：STARK trace 开值明文可见；本轮 0 命中
   不改变该性质。
3. groth16 的 `wrapper-only` 是包装器层面的隐藏声明，**非后量子**。
4. 策略规则名/正文是公开输入，命中交付物不是 `T` 泄露。
5. 真实响应的样本标签是 prompt 级（XSTest），响应级合规由策略判定；本例的
   `passed=false` 是策略结果，不是样本标签。

产物：[privacy_surface_real.json](../../bench/results/privacy_surface_real.json) /
[privacy_surface_real.md](../../bench/results/privacy_surface_real.md)。

---

## 3. 串行与隔离

- 所有证明任务（6 规则 core、EU core、EU groth16、隐私面 core+groth16）都串行，
  每次一个进程，统一 `flock /tmp/pop-proof.lock`。
- 使用独立云目录 `/root/autodl-tmp/zk-policy-x1d`（rsync worktree，排除
  `.git`/`circuits/target`/`.claude`/`bench/results`/`scripts/examples/out`），
  `pop-script` 软链到 `/root/autodl-tmp/zk-policy/circuits/target/release/pop-script`
  （未修改该共享 checkout）。证明工件放 `/root/autodl-tmp/x1d-work/`。
- 未使用 GPU；未与其他出证任务并发。

## 4. 未做 / blocker

1. **6 规则 × 10000 / 50000 core 均 OOM**：这是本轮唯一的 blocker。
   在这台 90 GiB cgroup 上，6 规则策略（3 keyword + 2 pattern）超出可行域；
   需要更大内存、或换更省内存的规则/编码方式才能继续。
2. 因 (1)，**6 规则 groth16 未跑**。
3. 未改 core / cert / paper / circuits；未 push。
4. 未把密码、云机日志写进仓库（`*.log` 被 `.gitignore` 忽略）。

## 5. 复现清单

```bash
# 1) 6 规则 core 两点（预期 OOM）
flock /tmp/pop-proof.lock env SP1_PROVER=cpu GOMAXPROCS=16 \
  timeout 3600 python3 bench/bench_scale.py \
    --out bench/results/scale-extended.json \
    --proof-modes core --lengths 10000,50000 --rules 6

# 2) EU AI Act（public，core / groth16）
flock /tmp/pop-proof.lock env SP1_PROVER=cpu GOMAXPROCS=16 \
  SP1_GROTH16_CIRCUIT_PATH=/root/autodl-tmp/sp1-cache/groth16 \
  python3 scripts/prove/issue_cert.py --pack policy_packs/eu_ai_act_v1.json \
    --response scripts/examples/eu_agent_reply.txt \
    --out-dir /root/autodl-tmp/x1d-work/eu-groth16 \
    --mode public --proof-mode groth16

# 3) 真实响应隐私面
flock /tmp/pop-proof.lock env SP1_PROVER=cpu GOMAXPROCS=16 \
  SP1_GROTH16_CIRCUIT_PATH=/root/autodl-tmp/sp1-cache/groth16 \
  python3 bench/bench_privacy_surface.py --tiers core,groth16 \
    --response-file /root/autodl-tmp/x1d-work/real_response.txt \
    --out-name privacy_surface_real --out-dir bench/results \
    --work-dir /root/autodl-tmp/x1d-work/privacy-real --timeout 1200
```

## 6. 交付清单（仅 `bench/*`、`bench/results/*`、本文件与实验文档）

| 文件 | 内容 |
|---|---|
| `bench/bench_privacy_surface.py` | `--response-file` / `--out-name` + 响应/策略/oracle 探针 |
| `bench/results/scale-extended.{json,md}` | 6 规则 × {10000,50000} core，2 ✗ OOM |
| `bench/results/eu_ai_act_proof.{json,md}` | 真实 EU pack 的 core/groth16 出证点 |
| `bench/results/privacy_surface_real.{json,md}` | 真实 chat 响应的 core/groth16 隐私面 |
| `docs/experiments/x1d-scale-privacy.md` | 方法、结果与读法 |
