# Wave 2 使用手册（X1 云机 / X2 真模型 / X3 语义与推理）

> **状态：维护中（2026-11-01）。** 配套 [`plan-bhv.md`](plan-bhv.md) 的 M2 与
> [`plan-parallel.md`](plan-parallel.md) 的 Wave 2。本文只回答：
> **Wave 2 现在能预启动什么、资源到位后怎么跑、产出在哪、失败了怎么办。**
>
> **一句话**：Wave 2 的**脚本与数据集已经就绪**，现在就能用 `stub` / `--no-prove`
> 跑通全链路；**真实的重任务**（groth16、真模型采样）等云机/GPU/API 到位后，
> 用本文的命令直接开跑。三条线（X1/X2/X3）可以同时准备，但**证明与采样各自串行**。

---

## 0. 现在就能做 vs 必须等资源

| 现在就能做（`[LOCAL]`） | 必须等资源 |
|---|---|
| 数据准备：XSTest 450 条 + smoke 20 条 | `[CLOUD]` P0-06/07/08：groth16、隐私面、规模矩阵 |
| `bench_k_entropy.py --backend stub` 冒烟 | `[GPU/API]` P0-09/10：真实 LLM 采样与端到端 |
| `bench_real_llm_e2e.py --no-prove` 冒烟 | `[GPU/CLOUD]` P2-01/02：真语义模型、真推理证明 |
| `bench_privacy_surface.py --tiers unproven --no-prove` 冒烟 | `[CLOUD]` P0-07 的 `core`/`groth16` 真探针 |
| `check_wave2_env.py` 体检 | 云机/GPU 开通 |
| 云机 provisioning 清单 | 实际安装（sudo 由用户终端执行） |

> **“预启动”不是阻塞**：X1/X2 的脚本、数据集、冒烟路径都已经落盘；资源一到，
> 只需换 `--backend` / `--tiers` / `--stage`，不用再写代码。

---

## 1. 文件地图

| 文件 | 用途 |
|---|---|
| [`scripts/datasets/prepare_wave2.py`](../scripts/datasets/prepare_wave2.py) | XSTest（+ 可选 τ-bench/Enron）→ 归一化 JSONL + manifest |
| [`scripts/examples/datasets/wave2/prompts_xstest.jsonl`](../scripts/examples/datasets/wave2/prompts_xstest.jsonl) | 450 条 XSTest（safe 250 / unsafe 200） |
| [`scripts/examples/datasets/wave2/prompts_smoke.jsonl`](../scripts/examples/datasets/wave2/prompts_smoke.jsonl) | 20 条冒烟集 |
| [`scripts/ops/check_wave2_env.py`](../scripts/ops/check_wave2_env.py) | 资源/依赖体检（RAM/GPU/toolchain/API key） |
| [`scripts/ops/provision_cloud.sh`](../scripts/ops/provision_cloud.sh) | 云机安装清单（只打印，不执行 sudo） |
| [`scripts/ops/run_wave2_cloud.sh`](../scripts/ops/run_wave2_cloud.sh) | X1 编排：P0-06 → P0-07 → P0-08，串行 + flock |
| [`bench/bench_k_entropy.py`](../bench/bench_k_entropy.py) | X2：采样 + 实测 `k` |
| [`bench/bench_real_llm_e2e.py`](../bench/bench_real_llm_e2e.py) | X2：响应级策略检查 + 可选证书 |
| [`bench/bench_privacy_surface.py`](../bench/bench_privacy_surface.py) | X1：P0-07 隐私面探针 |
| [`bench/bench_scale.py`](../bench/bench_scale.py) | X1：P0-06/P0-08 规模矩阵（已有，含续跑/预算闸） |
| [`bench/bench_proofs.py`](../bench/bench_proofs.py) | X1：单点时间/大小/内存（已有） |

---

## 2. X1 云机证明（`[CLOUD]`）

### 2.1 机器要求

| 项 | 要求 |
|---|---|
| RAM | **≥64 GiB**（128 GiB 推荐；12 GiB 上 groth16 必 OOM） |
| vCPU | ≥32 |
| 磁盘 | ≥200 GB SSD |
| OS | Ubuntu 22.04 x86-64 |
| 工具链 | Rust stable + `cargo-prove` v6.7.0 + Go ≥1.24 |

### 2.2 安装（逐条复制到你的终端）

> **在 AutoDL 上租机**（无卡模式为什么不可用、买几张卡、云机上怎么连/传文件/挂 tmux）
> 见 [`ops-autodl.md`](ops-autodl.md)。那一篇只管「租哪台、怎么操作」，
> 通用安装清单仍是下面这两条。

```bash
bash scripts/ops/provision_cloud.sh          # 打印清单
# 按清单执行；sudo 行请在你自己的终端跑
bash scripts/ops/provision_cloud.sh --verify # 只跑体检
```

### 2.3 体检

```bash
python3 scripts/ops/check_wave2_env.py --require P0-06_groth16,P0-08_scale
```

- 全 PASS 才开跑；`P0-06` 要求 `MemTotal ≥ 64 GiB` 且 `cargo-prove` 可用。
- 本机（14.6 GiB / RTX 4060 8 GB）会显示 `P0-06 ⛔`，这是**预期的**。

### 2.4 跑法（三阶段，内部串行）

```bash
# 阶段 1：groth16 首轮（先看一个点能不能过，再放大）
bash scripts/ops/run_wave2_cloud.sh --stage groth16 --budget-min 60
bash scripts/ops/run_wave2_cloud.sh --stage groth16 --budget-min 600

# 阶段 2：隐私面探针（core + groth16）
bash scripts/ops/run_wave2_cloud.sh --stage surface --timeout 3600

# 阶段 3：全矩阵（core + groth16，含 50k 长度）
bash scripts/ops/run_wave2_cloud.sh --stage scale --budget-min 600
```

**规则**：

- **一次只跑一个证明进程**。脚本用 `flock -n /tmp/pop-wave2-cloud.lock` 拒绝并发；
  每个 `core` 证明固定地板 ~10.15 GiB，groth16 更高。
- **续跑**：`bench_scale.py` 自带续跑；中断后重跑同一条命令，成功的点会跳过。
- **预算闸**：`--budget-min` 超时后把剩余点标成「未跑（预算用尽）」，不假装跑完。
- **不要**在云机上跑全量 `unittest discover`（抢内存/CPU，且部分测试需要本机工件）。

### 2.5 产物

| 文件 | 内容 |
|---|---|
| `bench/results/scale-cloud.json` / `.md` | P0-06/P0-08：规则 × 长度 × 证明档的时间/大小/峰值内存/边界 |
| `bench/results/privacy_surface.json` / `.md` | P0-07：每档的 canary 明文探针、公开值、承诺 oracle、witness-hiding |

### 2.6 判据

- **P0-06**：至少 3 规则 × 10k 字符的 `groth16` 能出证并验证通过；
  若仍 OOM，按 `plan-bhv.md` §7 fallback：改标题为 “Succinct” 并收窄 ZK 措辞。
- **P0-07**：`core` 的证明工件里 canary 命中（确定泄露 trace）；`groth16`
  的交付物里无 canary/无响应明文；`response_commitment` 仍是公开可重算的 oracle。
- **P0-08**：≥6 规则 × 10k 字符（最好 50k）可证；给出成本曲线，明确“12 GB 台阶是机器限制”。

---

## 3. X2 真模型（`[GPU/API]`）

### 3.1 数据集

```bash
# 已准备好（本批已生成）
ls scripts/examples/datasets/wave2/
#   prompts_xstest.jsonl   450 条
#   prompts_smoke.jsonl    20 条
#   manifest.json          来源/许可证/计数/sha256
#   README.md

# 重新生成 / 换源
python3 scripts/datasets/prepare_wave2.py --download          # 从 GitHub 原始 CSV
python3 scripts/datasets/prepare_wave2.py --taubench /path/to/tau2/airline/tasks.json
```

- XSTest：CC-BY-4.0；HF `walledai/XSTest` 是 **gated**，本脚本用 GitHub 原始 CSV。
- τ-bench / Enron：可选；不影响 `k` 测量。τ²-bench 的 airline tasks 在
  `sierra-research/tau2-bench/data/tau2/domains/airline/tasks.json`。

### 3.2 采样 + 实测 `k`

**冒烟（无需 key/GPU）**：

```bash
python3 bench/bench_k_entropy.py --backend stub \
    --prompts scripts/examples/datasets/wave2/prompts_smoke.jsonl \
    --max-prompts 6 --n-samples 10 --temperatures 0,0.7 --out-dir bench/results
# 预期：temp=0 median k=0；temp=0.7 median k≈0.24（stub 的 80/10/10 分布）
```

**API（OpenAI 兼容端点）**：

```bash
export OPENAI_API_KEY=...
# 若环境里有 OPENAI_API_BASE/OPENAI_BASE_URL 指向别的端点，先确认地址
python3 bench/bench_k_entropy.py \
    --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
    --backend openai:gpt-4o-mini \
    --max-prompts 50 --n-samples 20 --temperatures 0,0.7 \
    --out-dir bench/results --resume
```

**本地显卡**：

```bash
python3 -m pip install --user transformers accelerate
# 8 GB 显存：3B 级 + 4bit；8B fp16 装不下
python3 bench/bench_k_entropy.py \
    --prompts scripts/examples/datasets/wave2/prompts_xstest.jsonl \
    --backend local:Qwen/Qwen2.5-3B-Instruct --load-in-4bit --device cuda \
    --max-prompts 30 --n-samples 10 --temperatures 0,0.7 \
    --out-dir bench/results --resume
```

**参数与成本**：

| 项 | 建议 |
|---|---|
| prompt 数 | 冒烟 6；正式 50（safe/unsafe 分层） |
| 每 prompt 采样 | 10–50；API 用 20，本地可 50 |
| 温度 | `0,0.7`（贪心 vs 采样） |
| 成本 | API 约 $0.5–5 / 50 prompts × 20 samples（取决于模型）；本地 GPU 电费 |
| 时间 | API 几分钟；本地 3B 4bit 约几十分钟（视显存/量化） |

**产物**：

| 文件 | 内容 |
|---|---|
| `bench/results/k_samples.jsonl` | 原始样本（prompt_id, temperature, sample_index, response, latency） |
| `bench/results/k_entropy.json` / `.md` | 每 prompt 的 `p_max`/`k`、按温度汇总、阈值比例 |

**怎么读**：

- 温度 0 若确定，`p_max=1`、`k=0` ⇒ 重执行一次模型即可恢复 `T`，与证明系统无关。
- 温度 > 0 时看 `k < 阈值` 的比例（阈值默认 `log2(q)+log2(1/eps)=40 bit`），
  不要只看平均值。
- 精确字符串计数会低估长响应的多样性；`N` 只有 20–50；这是**采样分布估计**，
  不是信息论上界。

### 3.3 端到端（响应级策略 + 可选证书）

```bash
# 冒烟：host check（证书标 unproven）
python3 bench/bench_real_llm_e2e.py \
    --samples bench/results/k_samples.jsonl \
    --policy policy_packs/safety_xstest_v1.json \
    --out-dir bench/results --no-prove

# 少量真证明（每条 ~2–3 分钟、~10 GiB；串行）
SP1_PROVER=cpu python3 bench/bench_real_llm_e2e.py \
    --samples bench/results/k_samples.jsonl \
    --policy policy_packs/agent_content_v1.json \
    --out-dir bench/results --prove-limit 3 --proof-mode core
```

**产物**：`bench/results/real_llm_e2e.json` / `.md`。

**诚实边界**：

- XSTest 标签是 **prompt 级**；响应级没有 ground truth。
- `policy_prompt` 是策略本身的 P/R/F1（复现 `xstest2pack.py`）；
- `response_policy` 只报运行指标（违规率/拒绝率），**不是准确率**；
- `refusal_proxy` 是前缀启发式，不是人工标注。

---

## 4. X3 语义 / 推理（`[GPU/CLOUD]`，最高风险）

### 4.1 现状

- **P2-01 真语义模型**：当前随包是演示用小模型；要换成真实分类器
  （如 DistilBERT/DeBERTa toxic head 或 Llama Guard），导出 ONNX，再走 ezkl。
  `check_wave2_env.py` 的 `P2-01_semantic` 会检查 `ezkl`/`onnxruntime`。
- **P2-02 真推理证明**：当前组合的推理半是代理 MLP；换成小 transformer
  （GPT-2 small 一类）需要 zkML 框架与大量内存/时间。**若做不出，明确降级为
  “机制演示”**，不要把组合写成端到端结论。

### 4.2 预启动

1. 先写选型报告（模型、参数量、ONNX 大小、ezkl 证明时间/内存、XSTest 准确率）；
2. 用 `bench_semantic_real.py`（待 X3 落地）跑**不 prove** 的准确率/延迟；
3. 只有在准确率与成本都可接受时，再跑 ezkl 真证明。

### 4.3 判据

- P2-01：真实分类器在 XSTest 上有可报告的准确率；ezkl 证明能出且验证通过；
  明确“语义规则只支持公开模式”（`encode(T)` 泄露原文）。
- P2-02：要么交付小 transformer 的真证明；要么在论文里明确 demote，组合只证机制。

---

## 5. 体检与故障排查

```bash
python3 scripts/ops/check_wave2_env.py
python3 scripts/ops/check_wave2_env.py --require P0-06_groth16 --json
```

| 现象 | 原因 | 处理 |
|---|---|---|
| `P0-06 ⛔ total RAM 14.6 < 64` | 本机内存不够 | 换云机；或改标题/收窄 ZK 措辞 |
| `cargo-prove NO` | SP1 未装 | 跑 `scripts/ops/provision_cloud.sh` 第 3 步 |
| `groth16` 在 ~87 s 被 SIGKILL | OOM | 确认没有并发证明；换 ≥64 GB；先跑单点 |
| `transformers=False` | 未装 | `pip install --user transformers accelerate` |
| `OPENAI_API_KEY` 存在但 401 | key 无效/端点不对 | `check_wave2_env.py` 会提示 `OPENAI_API_BASE`；unset 或设对端点 |
| `k_samples.jsonl` 很大 | 采样多 | 用 `--resume`，不要重复采样；必要时 `--max-prompts` 缩小 |
| 隐私面 `canary_in_proof=0` | 该档确实隐藏，或探针没覆盖 | **不能**据此宣称零知识；看 `proof_hiding` 与 `sp1-zk-audit.md` |

---

## 6. 验收命令（Wave 2 预启动）

```bash
# 数据
python3 scripts/datasets/prepare_wave2.py --xstest-csv /tmp/xstest_prompts.csv
test -s scripts/examples/datasets/wave2/prompts_xstest.jsonl && echo OK

# X2 冒烟
python3 bench/bench_k_entropy.py --backend stub \
    --prompts scripts/examples/datasets/wave2/prompts_smoke.jsonl \
    --max-prompts 6 --n-samples 10 --temperatures 0,0.7 --out-dir bench/results
python3 bench/bench_real_llm_e2e.py --samples bench/results/k_samples.jsonl \
    --policy policy_packs/safety_xstest_v1.json --out-dir bench/results --no-prove

# X1 冒烟（不需要真证明）
python3 bench/bench_privacy_surface.py --tiers unproven --no-prove \
    --out-dir bench/results --work-dir /tmp/pop_privacy_smoke

# 环境体检
python3 scripts/ops/check_wave2_env.py
```

**预期**：

- `k_entropy.md`：temp=0 median k=0；temp=0.7 median k≈0.24（stub）。
- `real_llm_e2e.md`：有 prompt 级 P/R/F1、响应违规率、拒绝代理表。
- `privacy_surface.md`：`unproven` → `hiding=n/a`、`canary_in_proof=0`、status ok。
- `check_wave2_env.py`：本机 `P0-06 ⛔`（内存不足）、`P0-09_local_llm ⛔`（缺 transformers），
  这是预期的；云机/装依赖后应转 PASS。

> **已入库的冒烟输出**在 [`../bench/results/wave2_smoke/`](../bench/results/wave2_smoke/README.md)
> （`stub` / `unproven`，**不是论文数字**）。真实结果仍写 `bench/results/` 下的同名文件；
> 不要把 `wave2_smoke/` 的数抄进论文。

---

## 7. 与任务计划的对应

| 任务 | 脚本 / 数据 | 资源 |
|---|---|---|
| P0-06 groth16 | `run_wave2_cloud.sh --stage groth16` | `[CLOUD]` |
| P0-07 隐私面 | `run_wave2_cloud.sh --stage surface` / `bench_privacy_surface.py` | `[CLOUD]` |
| P0-08 规模 | `run_wave2_cloud.sh --stage scale` / `bench_scale.py` | `[CLOUD]` |
| P0-09 实测 `k` | `bench_k_entropy.py` | `[GPU/API]` |
| P0-10 端到端 | `bench_real_llm_e2e.py` | `[GPU/API]` |
| P2-01 真语义 | `bench_semantic_real.py`（待 X3） | `[GPU/CLOUD]` |
| P2-02 真推理 | 选型报告 + zkML 原型 | `[GPU/CLOUD]` |

> 结果文件命名统一在 `bench/results/`；每个文件都应有同名的 `.json` 与 `.md`，
> 且 `.md` 内含复现命令与诚实边界。**没有 `.json` 的数字不进论文。**
