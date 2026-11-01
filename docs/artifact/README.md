# Artifact 复现：纯 Python 层 + 证书/验证链路

> **范围一句话**：本目录让第三方复现 PoP 的 **Python 参考层、证书/账本与第三方
> 验证链路**，**不需要 SP1 出证、不需要云机、不需要真实 LLM**。
>
> **本 artifact 不覆盖**：SP1 `core` / `groth16` 证明、6 规则云机规模矩阵、
> 真实 LLM 的猜测熵 `k`、DeepSeek 端到端会话、真实语义分类器。这些是**仓库结果**，
> 入口在本文件 §5，**不在镜像里**。纯 Python 镜像只跑 42 项单元测试，不等于
> 「复现了 ZK 证明」。
>
> 对应代码基线：commit `1c1fc60`（`merge: E1 更大 N 与跨模型 k`）。
> 发布 Zenodo 时应把 `<FULL_GIT_COMMIT_SHA>` 回填为实际发布 commit；换 commit 后，
> `policy_hash`、证书数量、测试条数都可能变化。引用数字时请连同
> **commit + 结果文件**一起引（见 §7）。

---

## 1. 两条复现路径

| 路径 | 需要什么 | 覆盖什么 | 耗时 |
|---|---|---|---|
| **A. Docker（纯 Python）** | Docker engine | 策略承诺、Ed25519 证书、序列化契约（42 项测试） | 首次构建取决于网络；运行约 1 s |
| **B. 宿主机（完整 demo fast）** | Python 3.10+、框架依赖、Rust + SP1 工具链（只构建宿主驱动 `pop-script`，**不出证**） | A 的全部 + 8 条 demo 支路的宿主校验 + 第三方 `verify_session` | 已构建驱动时约 10 s |

两条路径都**不应**被称为「复现了 SP1 证明」。fast 模式下的 `PASS` 表示宿主判定与
证书/账本链路自洽，证书的 `proof_mode` 是 `unproven`。真出证见
[`docs/reproduce.md`](../reproduce.md) §3–§7，需要约 10 GiB 内存（`groth16` 约
30 GiB、约 5 分钟/点）。

---

## 2. 路径 A：Docker（纯 Python）

镜像定义在 [`Dockerfile`](../../Dockerfile)，构建上下文由
[`.dockerignore`](../../.dockerignore) 控制：`.git`、`circuits/target`、`bench/results`、
`scripts/examples/out`、`.pop-keys`、`*.key`、`*.pem` 等不会进入镜像；`policydsl/`、
`scripts/`、`policy_packs/`、`tests/`、`docs/`、`semantic/` 会保留。

```bash
docker build -t pop-artifact .
docker run --rm pop-artifact
```

预期输出（最后几行）：

```text
..........................................
----------------------------------------------------------------------
Ran 42 tests in ...s

OK
```

默认命令是：

```text
python3 -m unittest tests.test_policy_commit tests.test_cert \
                       tests.test_serialize
```

其中 [`tests.test_policy_commit`](../../tests/test_policy_commit.py) 覆盖带盐策略承诺
（BHV 定理 D / E4a）与枚举攻击边界；`tests.test_cert` 覆盖 Ed25519 签名/验签；
`tests.test_serialize` 覆盖 Python ↔ 电路契约。

**扩展命令**（容器里 `WORKDIR=/app`、`PYTHONPATH=/app`，可直接跑）：

```bash
# 更多纯 Python 测试
docker run --rm pop-artifact python3 -m unittest tests.test_dsl tests.test_normalize
# 编译策略包并打印 ConstraintSpec（JSON）
docker run --rm pop-artifact python3 -m policydsl compile policy_packs/eu_ai_act_v1.json
# 交互式 shell
docker run --rm -it pop-artifact bash
```

> **为什么默认不含两项测试**：
> `tests.test_doc_links` 会检查 Markdown 里的仓库内链接，而镜像按 `.dockerignore`
> 排除了 `bench/results/`（若干 docs 链接指向其中的 `.md`）；
> `tests.test_scripts_layout` 会导入 `scripts/datasets/*.py`，其中一个在模块级
> `import numpy`，而本镜像只装 `cryptography`。两项都在宿主机执行：
>
> ```bash
> python3 -m unittest tests.test_doc_links tests.test_scripts_layout -v
> ```
>
> **镜像大小 / 构建状态**：M6（2026-11-01，基线 `1c1fc60`）复查时 Docker engine
> **仍不可用**，因此**没有实测镜像大小**，也没有执行 `docker build` / `docker run`。
> 已做的等价检查（Dockerfile 结构、338 个文件的构建上下文（不含 Dockerfile/
> `.dockerignore` 自身）、默认 CMD 42 项测试、宿主脚本 `RESULT: PASS`）记录在 [`docs/blockers/M6.md`](../blockers/M6.md)；
> 首次记录见 [`docs/blockers/A4.md`](../blockers/A4.md)。投稿材料不得写「镜像已实测」。

---

## 3. 路径 B：宿主机（完整 demo fast）

### 3.1 前置

```bash
# Python 3.10+；demo 支路①需要 LangChain 离线桩（其余支路缺依赖会 SKIP）
python3 -m pip install -r requirements-frameworks.txt
```

宿主驱动 `circuits/target/release/pop-script` 必须存在。缺失时复现脚本会自动执行
`cd circuits && cargo build --release -p pop-script`；这一步需要 **Rust + SP1 工具链**，
但**不产生证明**、不占 ~10 GiB 内存。已有驱动时跳过。

### 3.2 一条命令

```bash
bash scripts/ops/reproduce_artifact.sh
```

可选参数：

```bash
bash scripts/ops/reproduce_artifact.sh --out-dir /tmp/pop-artifact   # 改产物目录
bash scripts/ops/reproduce_artifact.sh --no-build                    # 缺驱动时直接报错
```

脚本依次执行：

1. `python3 -m policydsl compile policy_packs/eu_ai_act_v1.json`（打印 `policy_hash`，
   基线 `1c1fc60` 实测 `5b5fd101…`）；
2. [`scripts/demo/demo_all.sh`](../../scripts/demo/demo_all.sh) 的 **fast** 模式
   （8 条支路走宿主校验，等价于各驱动的 `--no-prove`；不产生 SP1 证明）；
3. `scripts/verify/verify_session.py`（第三方只用公开产物复算）；
4. `tests.test_policy_commit` + `tests.test_doc_links`（纯 Python 冒烟）。

### 3.3 预期输出

demo 汇总表里每条支路是 **PASS 或 SKIP，不能有 FAIL**：

```text
=== 支路汇总 ===
key          支路               结果   墙钟(s) 峰值(KB)  驱动
...
policy       公开模式主干       PASS   ...
private      私有模式           PASS   ...
semantic     语义规则(P2-9)     SKIP   ...   ↳ 缺 semantic/artifacts/{kzg.srs,model.compiled} ...
compose      组合证明(P1-6)     PASS   ...
session      会话聚合(P2-10)    PASS   ...
multiparty   多证明者(P2-11)    PASS   ...
anchor       链上锚定(P7-c)      PASS 或 SKIP（缺 foundry 时）
verify       第三方独立验证      PASS   ...
汇总：没有 FAIL
```

SKIP 是「缺可选依赖」，不是失败。随后 `verify_session.py` 应打印 11 项 `[PASS]` 与末行：

```text
RESULT: PASS
```

M6 在基线 `1c1fc60` 上的实测：**13 张证书、11 项检查全 PASS**；最后一步
**17 项测试 OK**；脚本末尾 `RESULT: PASS`。这些数字会随 demo 内容变化，不应当作
跨 commit 的固定值。

> ⚠️ `verify_session.py` 的 `RESULT: PASS` 表示**证书与账本/链验证通过**，不表示
> 「所有证书的 `outcome.passed` 都是 true」—— demo 故意包含违规样本，有些证书会
> 如实记录 `passed=false`。两件事分开读，详见
> [`docs/development.md`](../development.md) §3.5。

### 3.4 产物路径

默认 `OUT_DIR=scripts/examples/out/artifact/`（已 gitignore）：

```text
scripts/examples/out/artifact/
├── policy.spec.json              # 编译后的 ConstraintSpec（含 policy_hash）
└── all/
    ├── REPORT.md                 # 8 条支路的汇总报告（PASS/FAIL/SKIP + 耗时/峰值）
    ├── policy/session.json       # 公开模式主干的会话包（第三方验证的输入）
    ├── policy/ …                  # 该支路的证书/账本/证明占位
    ├── private/ compose/ session/ multiparty/ anchor/
    └── logs/*.log                # 每条支路的完整日志
```

`--out-dir` 只改根目录，内部结构不变。

---

## 4. 最新结果入口（X1c / X1d / E1 / E2 / E3）

> 这些文件在**仓库里**，不在 Docker 镜像里（`bench/results/` 被 `.dockerignore`
> 排除）。每份结果都带 host / binary / vkey / commit 口径；**不要跨机器或跨
> `proof_mode` 混表**。

| 编号 | 内容 | 结果文件（入口） | 实验说明 |
|---|---|---|---|
| **X1c** | 云机 groth16 探针与 18 点矩阵（16 ✓ / 2 OOM）；隐私面 canary 探针 | [`scale-cloud.md`](../../bench/results/scale-cloud.md)、[`scale-probe-tuned.md`](../../bench/results/scale-probe-tuned.md)、[`scale-ab-A.md`](../../bench/results/scale-ab-A.md)、[`scale-ab-B.md`](../../bench/results/scale-ab-B.md)、[`privacy_surface.md`](../../bench/results/privacy_surface.md) | [`X1c.md`](../blockers/X1c.md) |
| **X1d** | 真实 `eu_ai_act_v1` 的 core/groth16 出证；6 规则 × {10k,50k} OOM；真实 chat 响应隐私面 | [`eu_ai_act_proof.md`](../../bench/results/eu_ai_act_proof.md)、[`scale-extended.md`](../../bench/results/scale-extended.md)、[`privacy_surface_real.md`](../../bench/results/privacy_surface_real.md) | [`x1d-scale-privacy.md`](../experiments/x1d-scale-privacy.md)、[`X1d.md`](../blockers/X1d.md) |
| **X1e / X1f** | 6 规则 × {2000,3000,4000,4500,5000} core；可行边界落在 [4500,5000) | [`scale-6x2000.md`](../../bench/results/scale-6x2000.md)、[`scale-6x3000.md`](../../bench/results/scale-6x3000.md)、[`scale-6x4000.md`](../../bench/results/scale-6x4000.md)、[`scale-6x4500.md`](../../bench/results/scale-6x4500.md)、[`scale-6x5000.md`](../../bench/results/scale-6x5000.md) | [`x1e-6x5000.md`](../experiments/x1e-6x5000.md)、[`x1f-6x4000.md`](../experiments/x1f-6x4000.md) |
| **E1** | 真实模型猜测熵 `k`：Qwen N=50、跨模型 N=20；N 截断判读 | [`k_entropy_largeN.md`](../../bench/results/k_entropy_largeN.md)、[`k_entropy_crossmodel.md`](../../bench/results/k_entropy_crossmodel.md)、`k_samples_largeN.jsonl`、`k_samples_crossmodel_{deepseek,mistral}.jsonl` | [`k-largen-crossmodel.md`](../experiments/k-largen-crossmodel.md) |
| **E2** | 策略语料级推断攻击（300 候选 × 真实响应 × L0/L1/L2）；**L2 证据承诺可链接** | [`policy_corpus_infer.md`](../../bench/results/policy_corpus_infer.md) | [`policy-corpus-inference.md`](../experiments/policy-corpus-inference.md) |
| **E3** | 真实 DeepSeek agent 端到端会话（19 证书，第三方验证 PASS，无 SP1） | [`agent_e2e_deepseek.md`](../../bench/results/agent_e2e_deepseek.md) | [`agent-e2e-deepseek.md`](../experiments/agent-e2e-deepseek.md) |
| **A11** | 真实语义分类器可行性 → **demote**（AUC 0.583、recall 0.5%、F1 0.010） | [`semantic_feasibility.md`](../../bench/results/semantic_feasibility.md) | 同文件 §8 |

### 4.1 关键读数（只列能指回文件的事实）

- **X1c**：`core` 与 `groth16` 各 9 点；16 ✓ / 2 OOM（`10000×3` 两档都 SIGKILL）。
  `groth16` 成功点 **279–344 s / 29.7–35.1 GB / verified=True**；
  `core` 地板约 **10.5 GB**，`2000×3` 跳到 **34.7 GB**。
- **X1d**：真实 `eu_ai_act_v1`（3 规则含 `pattern_block`）——`core`
  **48.82 s / 12.38 GB / 2,793,531 B**，`groth16` **301.19 s / 30.07 GB / 1,874 B**；
  两档 `verify_cert.py --proof --response` 均 `RESULT: PASS`。`groth16` 的
  `hiding=wrapper-only`（非后量子）。
- **X1e/X1f**：6 规则 `core` 在 2000/3000/4000/4500 字符成功
  （117.11/139.66/162.37/181.66 s；36.9/48.7/59.2/64.2 GB），**5000 字符 OOM**；
  6 规则 `groth16` 未跑。
- **E1**：Qwen N=50 的 50 组全部 `distinct=50`，因此只能读到
  **`k = log2(50) = 5.644 bit` 的 N 截断值**；N=20 的 Qwen/Mistral 同为 4.322，
  DeepSeek mean 4.242（4 组有重复）。这些都 **远低于 40 bit 阈值**，但
  **N 截断不能证明真实熵的上界**。
- **E2**：300 候选构造性 holdout 的 top-1：L0 **0.500**、L1 **0.068**、
  L2（实际承诺载荷）**0.382**、L2-count-only **0.014**；L2 承诺字典攻击覆盖样本
  top-1 **0.207**。真实响应 holdout：L0 0.449 / L1 0.076 / L2 0.112。
- **E3**：真实 DeepSeek 6 轮、**19 张证书**、`verify_session.py` 11 项全 PASS；
  宿主回调均值 **10.8 ms/轮**；**没有 SP1 证明**（`unproven`）。
- **A11**：toxic 分类器在 XSTest 上主阈值 recall **0.50%**、F1 **0.010**、
  ROC-AUC **0.583**；判定 **demote**，不能把 XSTest accuracy 当作策略质量。

**这些数字的边界**：`core` 不是 ZK；`groth16` 只是 wrapper-level 隐藏、非后量子；
`k` 受 N 截断；E2 是证书层（直接读证明公开值仍看到 raw `rule`/`kind`）；
E3 是机制演示，不是「模型合规」；A11 是失败可行性评估，不是可用 guardrail。

---

## 5. 不覆盖什么（重要）

| 不覆盖 | 原因 / 去哪看 |
|---|---|
| **SP1 `core` / `groth16` / compressed 真证明、链上验证合约** | 需要 ≥32–64 GB 云机与 foundry 工具链；`core` 约 10.5 GB 天花板、`groth16` 约 30 GB；见 §4 与 [`docs/reproduce.md`](../reproduce.md) §4½ |
| **6 规则 > 4500 字符、6 规则 groth16** | 90 GiB cgroup 下 `6×5000` core OOM、6 规则 groth16 未跑；见 [`scale-6x5000.md`](../../bench/results/scale-6x5000.md) 与 [`x1e-6x5000.md`](../experiments/x1e-6x5000.md) |
| **真实 LLM 的猜测熵 `k`、真实 provider 端到端** | 需要 API key/GPU 与采样预算；结果已入库（§4），但**不在镜像里**，也不是本脚本的复现范围 |
| **云机规模矩阵（20k/50k/100k 字符 × 1/2/3/6 规则）** | 本机与 fast 路径都不出证；见 §4 |
| **真实语义分类器 / ezkl 语义证明** | A11 判定 `demote`；见 [`semantic_feasibility.md`](../../bench/results/semantic_feasibility.md) |
| **SP1 的零知识性结论** | 本 artifact 不产生证明；结论见 [`docs/sp1-zk-audit.md`](../sp1-zk-audit.md) 与 [`docs/security-model.md`](../security-model.md) |

一句话：本目录复现的是**判定与证书/验证的正确性**，不是**证明成本**、**云机规模**
或**真实模型的隐私/合规结论**。

---

## 6. 常见失败

| 现象 | 原因 | 处理 |
|---|---|---|
| `No module named policydsl` | 不在仓库根，或 `PYTHONPATH` 未设 | `cd <repo>` 后重跑；容器里已是 `/app` |
| `ModuleNotFoundError: langchain_core` | 缺 demo 支路①的框架依赖 | `python3 -m pip install -r requirements-frameworks.txt` |
| `error: driver not built: …/pop-script` | 宿主驱动未构建 | 让脚本自动构建；或 `cd circuits && cargo build --release -p pop-script`（需要 Rust + SP1 工具链，不出证） |
| `semantic` / `anchor` 支路 **SKIP** | 缺 ezkl 工件 / foundry | SKIP 不是失败；需要该支路时按 [`docs/reproduce.md`](../reproduce.md) §8/§12 安装 |
| `docker: command not found` 或 WSL 提示未启用集成 | Docker Desktop 未启动/WSL 集成未开 | 启动 Docker Desktop 并启用该发行版的 WSL integration；本仓库当前 blocker 见 [`docs/blockers/M6.md`](../blockers/M6.md) |
| `SIGKILL: 9` / 进程被 OOM 杀 | 只有 `--prove` 真出证才会发生（~10.15 GiB 地板；groth16 ~30 GiB） | 本复现路径不带 `--prove`；真出证请腾空内存，见 [`docs/reproduce.md`](../reproduce.md) |
| 验证脚本退出码 0，但有证书 `passed=false` | 「证书为真」与「策略被满足」是两件事 | 属正常现象，见上文的读数提示 |

---

## 7. Zenodo / 数字口径

[`zenodo.json`](zenodo.json) 是**模板**，不是已发布记录：

- 所有 `<...>` 占位符（作者、ORCID、版本、日期、`LICENSE`、commit SHA、DOI）都必须
  替换；**不要填入任何虚构 DOI** —— DOI 由 Zenodo 在发布时分配，发布后再回填；
- 标题/描述里的数字必须能指回**本版本对应的 commit** 与**仓库内的结果文件**：
  - 证明成本/内存：`bench/results/scale-cloud.md`、`eu_ai_act_proof.md`、
    `scale-6x*.md`；
  - 隐私面：`bench/results/privacy_surface.md`、`privacy_surface_real.md`；
  - 猜测熵 `k`：`bench/results/k_entropy_largeN.md`、`k_entropy_crossmodel.md`；
  - 策略推断：`bench/results/policy_corpus_infer.md`；
  - 端到端：`bench/results/agent_e2e_deepseek.md`；
  - 语义可行性：`bench/results/semantic_feasibility.md`。
- 跨机数字必须同时注明硬件与 `proof_mode`（`core` / `groth16`），并说明
  `groth16` 是 wrapper-level、非后量子；**pre-NFA-fix 与 post-NFA-fix 不混表**。
- 本 artifact 自身可引用的验收证据是：Docker 冒烟的 42 项测试（等价宿主机运行）、
  宿主 `demo_all.sh` 的 `REPORT.md`、`verify_session.py` 的 `RESULT: PASS`（13 证书）、
  以及 `tests.test_doc_links` 的通过记录 —— 它们都不含 SP1 证明耗时。
- `zenodo.json` 的 `release_checksums` 是**占位清单**：发布时用
  `sha256sum` 对列出的结果文件生成真实值后回填，不要现在编造 checksum。

发布前建议在干净 checkout 上重跑：

```bash
python3 -m unittest tests.test_doc_links -v
bash scripts/ops/reproduce_artifact.sh
```

---

## 8. 验收状态（M6，基线 `1c1fc60`）

| 项 | 状态 |
|---|---|
| `Dockerfile` 语法、CMD 引用 | ✓ |
| `.dockerignore` 上下文（338 文件，敏感项 0） | ✓ |
| 默认 CMD（42 tests） | ✓（宿主机等价运行） |
| 宿主 `reproduce_artifact.sh` | ✓（`RESULT: PASS`，13 证书 / 17 tests） |
| `tests.test_doc_links` | ✓（4 tests OK） |
| `docker build` / `docker run` / 镜像大小 | ✗ **blocked**（engine 不可用） |
| 最新结果入口（X1c/X1d/X1e/X1f/E1/E2/E3/A11） | ✓（§4，仅仓库文件） |
