# Artifact 复现：纯 Python 层 + 证书/验证链路

> **范围一句话**：本目录让第三方用**一条命令**复现 PoP 的 Python 参考层、证书/账本
> 与第三方验证链路，**不需要 SP1 出证、不需要云机、不需要真实 LLM**。
>
> 对应代码基线：commit `28f0625`（`docs(plan): 列出不依赖 X1/X2 的可先跑任务`）。
> 换 commit 后，`policy_hash`、证书数量、测试条数都可能变化；引用数字时请连同
> **commit + 结果文件**一起引（见文末「Zenodo / 数字口径」）。

---

## 1. 两条复现路径

| 路径 | 需要什么 | 覆盖什么 | 耗时 |
|---|---|---|---|
| **A. Docker（纯 Python）** | Docker | 策略承诺、Ed25519 证书、序列化契约（42 项测试） | 首次构建取决于网络；运行约 1 s |
| **B. 宿主机（完整 demo fast）** | Python 3.10+、框架依赖、Rust + SP1 工具链（只构建宿主驱动 `pop-script`，**不出证**） | A 的全部 + 8 条 demo 支路的宿主校验 + 第三方 `verify_session` | 已构建驱动时约 10 s |

两条路径都**不应**被称为「复现了 SP1 证明」。fast 模式下的 `PASS` 表示宿主判定与
证书/账本链路自洽，证书的 `proof_mode` 是 `unproven`。真出证见
[`docs/reproduce.md`](../reproduce.md) §3–§7，需要约 10 GiB 内存。

---

## 2. 路径 A：Docker（纯 Python）

镜像定义在 [`Dockerfile`](../../Dockerfile)，构建上下文由
[`.dockerignore`](../../.dockerignore) 控制：`.git`、`circuits/target`、`bench/results`、
`scripts/examples/out`、`.pop-keys` 等不会进入镜像；`policydsl/`、`scripts/`、
`policy_packs/`、`tests/` 会保留。

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
> **镜像大小**：本文件的作者环境里 Docker 守护进程不可用，故**没有实测镜像大小**，
> 也没有执行过 `docker build`；blocker 与已做的替代检查见
> [`docs/blockers/A4.md`](../blockers/A4.md)。

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

1. `python3 -m policydsl compile policy_packs/eu_ai_act_v1.json`（打印 `policy_hash`）；
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

最后一步应看到：

```text
Ran 17 tests in ...s
OK
```

并在脚本末尾打印 `RESULT: PASS`。

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

## 4. 不覆盖什么（重要）

| 不覆盖 | 原因 / 去哪看 |
|---|---|
| **groth16 / compressed 真证明、链上验证合约** | 需要 ≥32–64 GB 云机与 foundry 工具链；见 [`docs/reproduce.md`](../reproduce.md) §4½ 与 [`docs/runbook-wave2.md`](../runbook-wave2.md) |
| **真实 LLM 的猜测熵 `k`、真实 provider 端到端** | 需要 API key/GPU 与采样预算；见 [`docs/runbook-wave2.md`](../runbook-wave2.md) 的 P0-09/P0-10 |
| **云机规模矩阵（20k/50k/100k 字符 × 1/2/3/6 规则）** | 本机与 fast 路径都不出证；见 [`docs/reproduce.md`](../reproduce.md) §4½ 与 [`docs/runbook-wave2.md`](../runbook-wave2.md) |
| **SP1 的零知识性结论** | 本 artifact 不产生证明；结论见 [`docs/sp1-zk-audit.md`](../sp1-zk-audit.md) 与 [`docs/security-model.md`](../security-model.md) |

一句话：本目录复现的是**判定与证书/验证的正确性**，不是**证明成本**或**云机规模**。

---

## 5. 常见失败

| 现象 | 原因 | 处理 |
|---|---|---|
| `No module named policydsl` | 不在仓库根，或 `PYTHONPATH` 未设 | `cd <repo>` 后重跑；容器里已是 `/app` |
| `ModuleNotFoundError: langchain_core` | 缺 demo 支路①的框架依赖 | `python3 -m pip install -r requirements-frameworks.txt` |
| `error: driver not built: …/pop-script` | 宿主驱动未构建 | 让脚本自动构建；或 `cd circuits && cargo build --release -p pop-script`（需要 Rust + SP1 工具链，不出证） |
| `semantic` / `anchor` 支路 **SKIP** | 缺 ezkl 工件 / foundry | SKIP 不是失败；需要该支路时按 [`docs/reproduce.md`](../reproduce.md) §8/§12 安装 |
| `docker: command not found` 或 WSL 提示未启用集成 | Docker Desktop 未启动/WSL 集成未开 | 启动 Docker Desktop 并启用该发行版的 WSL integration；本仓库作者环境的 blocker 见 [`docs/blockers/A4.md`](../blockers/A4.md) |
| `SIGKILL: 9` / 进程被 OOM 杀 | 只有 `--prove` 真出证才会发生（~10.15 GiB 地板） | 本复现路径不带 `--prove`；真出证请腾空内存，见 [`docs/reproduce.md`](../reproduce.md) |
| 验证脚本退出码 0，但有证书 `passed=false` | 「证书为真」与「策略被满足」是两件事 | 属正常现象，见上文的读数提示 |

---

## 6. Zenodo / 数字口径

[`zenodo.json`](zenodo.json) 是**模板**，不是已发布记录：

- 所有 `<...>` 占位符（作者、ORCID、版本、日期、`LICENSE`、commit SHA）都必须替换；
- **不要填入任何虚构 DOI** —— DOI 由 Zenodo 在发布时分配，发布后再回填；
- 标题/描述里的数字必须能指回**本版本对应的 commit** 与**仓库内的结果文件**：
  - 证明成本/内存：`bench/results/proofs.md`、`bench/results/compressed.md`；
  - 组合/会话/语义：`bench/results/compose.md`、`bench/results/semantic.md` 等；
  - 跨机数字必须同时注明硬件与 `proof_mode`（见 [`docs/reproduce.md`](../reproduce.md) §4½）。
- 本 artifact 自身可引用的验收证据是：Docker 冒烟的 42 项测试、宿主机
  `demo_all.sh` 的 `REPORT.md`、`verify_session.py` 的 `RESULT: PASS`，以及
  `tests.test_doc_links` 的通过记录 —— 它们都不含 SP1 证明耗时。

发布前建议在干净 checkout 上重跑：

```bash
python3 -m unittest tests.test_doc_links -v
bash scripts/ops/reproduce_artifact.sh
```
