# 开发与使用手册

> **这份文件回答什么**：怎么把仓库跑起来、改一处代码该跑哪几条验证、常见任务怎么做、
> 出错时先看哪里。**它不回答**：每个板块内部是怎么实现的（→ [`modules/`](modules/README.md)）、
> 论文里的每个数字怎么复现出来（→ [`reproduce.md`](reproduce.md)）、为什么这样设计是安全的
> （→ [`security-model.md`](security-model.md)）。
>
> **本文件里出现的每条命令都在本机实际执行过**（2026-09-17，本机 11.9 GiB / Python 3.10.12），
> 表里的耗时与内存都是**实测值**，不是估计。凡是我没能在这台机器上跑通的（真 groth16、
> 云机全矩阵），我会明确写「未在本机验证」并指向记录了它们的那份文件。

---

## 1. 我该从哪儿开始

| 我是谁 / 我想干什么 | 走这条线 |
|---|---|
| **我只想看看它是真的** | §3.1 全量测试 → §3.3 全链路 demo（13 秒）→ §3.5 第三方核验 |
| **我要改策略或规则** | §3 跑通 → §4.1 分层验证表 → §5.1 / §5.2 → [`modules/01`](modules/01-policy-dsl.md) / [`05`](modules/05-zk-circuits.md) |
| **我要接一个新框架** | §3 跑通 → §5.4 → [`modules/06`](modules/06-frameworks.md) §8（九条契约清单） |
| **我要动证明/电路** | §3 跑通 → §4.1 → §5.2 → [`modules/05`](modules/05-zk-circuits.md)（**先读 08 §3.3 的内存天花板**） |
| **我要把它部署起来** | [`runbook-proof-service.md`](runbook-proof-service.md) → §6 环境变量 → §3.6 |
| **我要复现论文里的数字** | [`reproduce.md`](reproduce.md)（按功能逐条）+ §5.6 重跑 bench |

**先读这一条，它能省掉你半天**：这个项目的失败大多是**静默**的 —— `unittest` 的 skip 是绿的、
`--no-prove` 的末行也是 `PASS`、脚本从错误的目录跑起来照样有输出。所以本手册反复讲同一件事：
**怎么把不响的失败弄响**（§4.3 汇总了四个）。

---

## 2. 环境

### 2.1 依赖分层：装到哪一层，就能跑到哪一层

| 层 | 需要什么 | 不装的后果 |
|---|---|---|
| **0 必装** | Python ≥ 3.10、标准库 | 什么都跑不了 |
| **1 参考层** | 无（`policydsl/` 只用标准库） | —— |
| **2 电路** | Rust 工具链 + SP1（`cargo prove`） | 只有 `--check` 路径；`pop-script` 都不存在时多数脚本以退出码 2 干净报错 |
| **3 出证** | 上面 + 足够内存（**~10.15 GiB 地板**） | `--no-prove` 仍全绿；真出证被 OOM 杀 |
| **4 链上** | foundry（`anvil` / `forge` / `cast`） | 锚定相关用例 skip；`anchor_e2e.sh` 直接告诉你装什么 |
| **5 语义规则** | `ezkl` + `torch` + 32 MiB `kzg.srs` | `test_semantic` 29/30 仍跑（**设计如此**，见 08 §1.1） |
| **6 框架** | `langchain` / `langgraph` / `mcp` | 真实框架用例 skip，鸭子类型 fake 顶上；套件仍全绿 |

**关键设计：每一层缺失都被显式处理。** 所以「装不全」不会让你什么都做不了，但也**不会**
告诉你某条路径没被跑到 —— 这正是 §4.3 第 1 条。

### 2.2 安装

```bash
# 2 电路（首次慢，之后增量）
cd circuits/program && cargo prove build            # 生成 guest ELF
cd ../script && cargo build --release -p pop-script # 宿主驱动（无改动时 8.9 s）
# ⚠️ 出证必须 SP1_PROVER=cpu；native 会 unreachable 崩溃，light 不能出证

# 4 链上
bash scripts/ops/retry_install_foundry.sh           # 网络受限时的重试版
# 5 语义规则
bash scripts/ops/install_ezkl.sh
# 6 框架
bash scripts/ops/install_frameworks.sh
```

三个安装脚本都放在 `scripts/ops/` 下，都带 `retry_` 变体（或本身就是重试版）—— 这台机器的
网络会限流，一次装不上是常态。**`POP_EZKL_WHEELHOUSE` 可以指向本地 wheel 目录**绕过网络。

### 2.3 这台机器（本机）的四条硬事实

1. **内存地板 ~10.15 GiB**，一份 core 证明 2–3 分钟、峰值实测 **10.85 GiB**（RSS，2026-09-17）。
   本机 11.9 GiB / 3 GiB swap —— **装得下，但没有余量**。出证期间**不要并行跑任何重活**，
   整轮测试也不行。失败的样子是 `SIGKILL: 9` 加一屏临时路径，核实用
   `dmesg | grep -i 'killed process'`。见 08 §3.3 与 §1.1。
2. **无 TeX 工具链** → `paper/*.tex` 改完**无法在本机编译**。`.tex` 是论文的权威源，
   `paper/proof-of-policy.md` 是它的镜像；两边都要改，且只能靠人眼对齐。
3. **网络受限**：GitHub / crates.io 会限流。git 的镜像配置是**仓库局部**的
   （`insteadOf` 写在仓库的 git config 里，**绝不设成全局**）；crates 侧靠
   `circuits/patches/` 里 vendored 的 `tempfile` 绕过上游缺的 `TempDir::keep()`。
4. **私钥绝不入 git**：`.pop-keys/`、`*.key`、`*.pub.hex` 都在 `.gitignore` 里。
   缺省密钥在 `.pop-keys/signing.key`；设 `POP_SIGNING_KEY_PASSPHRASE` 才会加密落盘。

---

## 3. 十五分钟跑通（每条都实测过）

| # | 命令 | 实测耗时 | 看到什么算对 |
|---|---|---:|---|
| 3.1 | `python3 -m unittest discover tests` | **33.4 s** | `Ran 675 tests … OK (skipped=15)` |
| 3.2 | `bash scripts/demo/demo_all.sh --list` | 秒 | 8 条支路的 key / 中文名 / 驱动脚本 |
| 3.3 | `bash scripts/demo/demo_all.sh` | **13.2 s** | 末尾 `汇总：没有 FAIL`；报告在 `scripts/examples/out/all/REPORT.md` |
| 3.4 | `python3 scripts/demo/demo_e2e.py --no-prove` | **1.16 s** | 会话摘要 + `llm model : fake (offline)` |
| 3.5 | `python3 scripts/verify/verify_session.py --session …/policy/session.json` | **0.081 s** | 10 项全 `[PASS]`，末行 `RESULT: PASS` |
| 3.6 | `python3 scripts/ops/proof_service.py --host-check` + 两条 curl | 秒 | `/v1/health` → `status: ok`；作业走到 `done` |
| 3.7 | 真出证 + 第三方核验（§3.7） | **2:07 + 21 s** | 13 项全 `[PASS]`，`RESULT: PASS` |

### 3.1 全量测试

```bash
python3 -m unittest discover tests                # 33.4 s
python3 -m unittest tests.test_dsl -v             # 单个模块
```

末行是 `OK (skipped=15)` —— **`OK` 只说「没失败」，不说「都跑了」**。那 15 个 skip 逐条列在
[`modules/08` §1.1](modules/08-tests-bench.md)，都是设计内的（真证明 / 真 ezkl / 真 provider
等等）。判断「某个性质到底被守住了没」时，那 15 条要单独看。

### 3.2 看全貌

```bash
bash scripts/demo/demo_all.sh --list
```

只列 8 条支路，不跑任何东西。这是**最快弄清这个项目有什么**的方式。

### 3.3 全链路（fast 模式，13 秒）

```bash
bash scripts/demo/demo_all.sh
```

8 条支路全跑一遍，但**不出真证明**（走宿主校验，证书如实标 `unproven`）。
实测 13.2 s，8 条支路全 PASS。退出码：`0` = 所有应有步骤 PASS，`1` = 有 FAIL；
**SKIP（缺依赖）单列，不算失败**。

> ⚠️ **`--no-prove` 下的 PASS 不是「已出证」。** 报告里 `zk proof` 那一行会写
> `(skipped: --no-prove)`，证书的 `proof_mode` 是 `unproven`。这是本项目最容易读错的一处 ——
> 见 [`demo/README.md` §4](demo/README.md)。

### 3.4 单条端到端（1.2 秒）

```bash
python3 scripts/demo/demo_e2e.py --no-prove
```

比 3.3 细：会打印会话摘要、每张证书的结论、`blocked tool calls`、`tool trace`、`ledger chain`。
终端会如实打出 `llm model : fake (offline)` —— **缺省是离线桩，不是真模型**；
`--model openai:gpt-4o-mini` 才走真客户端（但始终真实的是 **callback 管线**本身）。

### 3.5 第三方核验（0.08 秒）

`demo_all.sh` 跑完后产物在 `scripts/examples/out/all/<支路>/`（**已 gitignore**）：

```bash
python3 scripts/verify/verify_session.py --session scripts/examples/out/all/policy/session.json
```

实测 0.081 s、10 项全 PASS。**这是「第三方视角」的那条路** —— 它只用公开产物
（`session.json` + ledger + proof）复算全部结论，不碰出证方的任何东西。

> ⚠️ **两个读数陷阱，都在这条命令上：**
> 1. **`verify_session.py` 只打一行 `RESULT:`。** 单张证书那个脚本（`verify_cert.py`）
>    打**两行**：`RESULT` 说证书真不真，`合规` 说策略满足没满足 —— 两件事。
>    （`合规:` 那行只在策略含语义规则时才打印。）
> 2. **退出码 0 不等于「策略被满足了」。** 实测：这份会话 13 张证书里有 **6 张
>    `outcome.passed=false`**（如实记录违规），而它照样 `RESULT: PASS`、退出码 `0`。
>    **一张如实记录违规的证书是真的证书** —— 拿退出码当 CI 判据要当心，见
>    [`modules/07` §2.5](modules/07-cli-scripts.md)。

### 3.6 起证明服务

```bash
python3 scripts/ops/proof_service.py --host-check --port 8791 &   # 几秒一个作业
curl -s localhost:8791/v1/health
curl -s localhost:8791/v1/check -H 'Content-Type: application/json' \
  -d '{"policy_id":"agent-content-v1","response":"Leak sk-abcdefghijklmnopqrstuvwxyz now"}'
# → 200，passed=false，proof_mode="unproven"，含 nonce 与 verify_hint（可直接粘贴）
```

拿上一步的 `nonce` 提交作业，几秒后查状态：

```bash
curl -s -X POST localhost:8791/v1/attest -H 'Content-Type: application/json' \
  -d '{"policy_id":"agent-content-v1","response":"All clear.","nonce":"<上一步的 nonce>"}'
# → 202 {job_id, state:"queued", queue_position}
curl -s localhost:8791/v1/attest/<job_id>     # → state: done
```

**默认只绑 `127.0.0.1:8787`**，没配 token 就是**无鉴权**（`/v1/health` 的 `auth.mode` 会如实写
`none`）。`--host-check` 把出证换成宿主校验，用来验队列机制本身；去掉它才是真证明
（**~2.5 分钟/作业、峰值 ~10.2 GiB**）。生产形态、鉴权、链上后端见
[`runbook-proof-service.md`](runbook-proof-service.md)。

### 3.7 真出证 + 第三方核验（可选，重）

**一次只跑这一件事，其他进程全停。** 实测 2 分 07 秒、峰值 RSS 10.85 GiB：

```bash
SP1_PROVER=cpu python3 scripts/prove/issue_cert.py \
  --pack policy_packs/eu_ai_act_v1.json --response scripts/examples/eu_agent_reply.txt \
  --out-dir scripts/examples/out/cert_public
```

签名、锚定进账本、写出 `cert.json` / `payload.json` / `key.json` / `proof.bin`。
然后第三方核验（20.8 s）：

```bash
python3 scripts/verify/verify_cert.py \
  --cert scripts/examples/out/cert_public/cert.json --pack policy_packs/eu_ai_act_v1.json \
  --ledger scripts/examples/out/ledger.jsonl --proof scripts/examples/out/cert_public/proof.bin \
  --response scripts/examples/eu_agent_reply.txt
```

**13 项全 `[PASS]`、`RESULT: PASS`。** 三条值得注意的读数：

- `[PASS] response_binding … — 送达的 T′ 就是被证明的 T` —— 这一行**只有给了 `--response` 才有**
  （P0-2 的验收点）。换成另一条响应，它变 `[FAIL]`。
- `[PASS] trace_seal 证书未附 trace_seal —— 会话末端未被承诺，**截尾不可排除**` ——
  这行是**绿的**但语义是「这一项这次核不了」。**本项目里多处「绿」是「如实说没核」**，
  读报告要看括号里的字，不要只看 PASS。
- 三项**不给就 FAIL**：`--proof` 不给 → `proof` FAIL（证书声称有证明却没给）；`--receipts`
  不给 → `trace_binding` 只有 1 个来源、如实报 FAIL。**fail-closed 是设计，不是 bug。**

---

## 4. 日常开发循环

### 4.1 改了什么 → 跑什么

从便宜到贵，**先在便宜的档位过，再往上走**：

| 我改了什么 | 第一档（秒级） | 第二档（分钟） | 第三档（贵） |
|---|---|---|---|
| 文档 / 注释 | 本文件与相关模块文档互查 | —— | —— |
| `policydsl/` 的一个模块 | `python3 -m unittest tests.test_<板块>` | `python3 -m unittest discover tests` | `--no-prove` 全链路 |
| `scripts/` 结构 | `python3 -m unittest tests.test_scripts_layout` | 同上 | `bash scripts/demo/demo_all.sh` |
| **策略规则（两侧）** | `python3 scripts/prove/cross_validate.py --no-prove`（**0.048 s**，19 向量对拍） | 全量测试 | `cross_validate` 真出证（**≈45 min**） |
| **任何「不该改变行为」的重构** | `python3 scripts/verify/acceptance.py --verify tests/acceptance_baseline.json`（**1.4 s**，七面逐路径对拍；`unittest` 里也有一份，随全量测试跑） | 全量测试 | 同上 |
| **电路 / Rust** | `cargo build --release -p pop-script`（8.9 s） | `cross_validate --no-prove` | `POP_TEST_PROOF=1` / `cross_validate` 真出证 |
| 证书 / 信封结构 | `python3 -m unittest tests.test_cert tests.test_policy_binding` | 全量测试 | §3.7 真出证 + 核验 |
| 框架适配器 | `python3 -m unittest tests.test_<框架>` | 全量测试 | §3.4 带 `--model` 跑真模型 |
| 服务 / 鉴权 | `python3 -m unittest tests.test_proof_service` | 全量测试 | §3.6 起服务打一遍 |

**`cross_validate.py --no-prove` 是本仓库性价比最高的一条命令**：19 条向量、Python golden
与 Rust 判定逐点对拍，**0.048 秒**（`pop-script --check` 是原生执行，不进 zkVM）。

> ⚠️ **`cross_validate.py` 没有 `--help`，也不认 `--help`。** 它用裸 `sys.argv` 解析：
> 敲 `--help` 会**被当成普通参数忽略，然后直接开跑 19 条真证明**（≈45 min）。
> 唯一的开关是 `--no-prove` 与 `--work-dir`。同类「没有 argparse」的脚本还有
> `demo_all.sh` 之外的几个老脚本 —— 敲之前先 `grep add_argument`。

### 4.2 提交前清单

1. `python3 -m unittest discover tests` → **710 / 15**，工作树里没有计划外的文件。
2. 改了 `scripts/` 结构 → `tests.test_scripts_layout` 过。
3. 改了会产生数字的东西 → 数字**四处同步**（见 [`modules/08`](modules/08-tests-bench.md)）。
4. 改了文档 → 相对链接不悬空。
5. `git status` 干净，产物（`scripts/.work/`、`scripts/examples/out/`、`bench/work/`）没被误加。

### 4.3 ⚠️ 四个「不响的失败」

这四条都是**本项目真踩过的**，共同点是：**出错了但看起来是绿的**。

1. **`unittest` 的 skip 是静默的绿。** 一次变异改动**等价**、其余 17 例全绿，直到补了断言
   才杀掉（[`modules/08`](modules/08-tests-bench.md) §1.1 与「三个坑」）。
2. **`--no-prove` 的末行也是 `PASS`。** 它说的是「宿主判定这条路对了」，**不是**「出证成功了」。
   `regression_prove.py` 曾把 `time` 的样板取进 `log_tail` 而挤掉 traceback ——
   **最需要证据的那种失败反而最看不见**。
3. **「恰好对」的测量比明显错的更危险。** 一个只差 `kind` 字段的变异能全绿通过；
   写断言时问自己：**把它改坏，哪个字段会变？** 答案是「没有」的断言不咬人。
4. **脚本从一个「错的 cwd」跑起来照样有输出。** `scripts/` 下所有脚本**按标记搜仓库根**，
   在哪儿敲都一样（这是特性）；但 **`python3 -m policydsl` 只在仓库根能用** ——
   换个目录会 `No module named policydsl`。要跨目录用，得 `PYTHONPATH=<repo>`：

   ```bash
   cd /tmp
   python3 -m policydsl compile …          # ✗ No module named policydsl
   PYTHONPATH=/path/to/zk-policy python3 -m policydsl compile …   # ✓
   python3 /path/to/zk-policy/scripts/prove/prove_policy.py --help # ✓ 不受 cwd 影响
   ```

---

## 5. 配方：常见任务

### 5.1 改策略（不动代码）

策略包是 JSON，在 `policy_packs/`。改完：

```bash
python3 -m policydsl compile policy_packs/<你的包>.json    # 看新 sha256（0.011 s）
python3 -m policydsl check --policy policy_packs/<你的包>.json <响应.txt>   # 0.043 s
```

`compile` 输出的 `sha256` **就是证书里的 `policy_hash`** —— 改一个字符，它变，此前所有
引用旧策略的证书全部对不上。这是**特性**（策略绑定），不是麻烦。详细规则写法见
[`modules/01`](modules/01-policy-dsl.md)。

### 5.2 加一个规则 kind（**跨两层**，最容易只改一半）

一个 kind 要在**四个地方**同时存在，少一处就是「Python 认、电路不认」或反过来：

| 层 | 文件 | 干什么 |
|---|---|---|
| 模型 / 校验 | `policydsl/core/model.py` | `Rule` 的 kind 分派与参数校验（含 `PolicyError`） |
| 编译 | `policydsl/core/compile.py` | 编进 `ConstraintSpec` |
| 参考判定 | `policydsl/core/evaluate.py` | golden 判定（对拍基准） |
| 电路 | `circuits/types/src/lib.rs`（`SpecConstraint` 分派） | zkVM 内的判定，**必须与 golden 逐点一致** |

加完**必跑**：

```bash
python3 scripts/prove/cross_validate.py --no-prove    # 0.048 s，先在这里对拍
python3 -m unittest tests.test_rules_incircuit tests.test_dsl
python3 -m unittest tests.test_rule_kinds             # 机械核对下面几张表是否同步
```

`tests/test_rule_kinds.py` 会**逐字面量**核对 `model.py` / `compile.py` / `evaluate.py` /
`privacy/commit.py` 四处分派与 `multiparty.KIND_OWNER` 是否覆盖同一组 kind ——
漏改其中任何一处都会当场红，不必等你自己想起来。

**未入电路的 kind 是 fail-closed 的**（`test_policy_binding` 守着这条）—— 忘了改 Rust 侧
不会静默放行，会当场判 FAIL。但**前提是你跑了那条测试**。

### 5.3 加一个脚本

放进 `scripts/` 的 5 个组之一，开头三行照抄 `scripts/_bootstrap.py` 的用法代码块。
三条红线（都有测试锁着）：不给 `scripts/` 加 `__init__.py`、组间不重名、
`scripts/` 根上只放 `_bootstrap.py` + 5 组 + `examples/`。详见
[`modules/07`](modules/07-cli-scripts.md) 的「怎么改它」。

### 5.4 接一个新框架

按 [`modules/06`](modules/06-frameworks.md) §8 的九条契约清单走。**先分清「提取事件」与
「出证」两件事**，参考实现是 `policydsl/adapters/generic_adapter.py`（框架无关、可跑）。
新写的适配器**必须做一遍变异测试** —— 这条线的测试极易「看着绿、其实没咬住」。

### 5.5 改证书 / 信封结构

改 `policydsl/evidence/cert.py` 的 `build_payload`。**注意谁算哪些哈希**：
`policy_hash` 是它自己从 `spec["sha256"]` 取的；而 `vkey_hash` / `proof_sha256` /
`public_values_sha256` **必须由调用方给** —— 它不算、也不核。加字段要考虑**旧证书**
（缺字段时如实跳过，不是默认通过）。必跑 `tests.test_cert` + `tests.test_policy_binding`。

### 5.6 重跑 bench 与数字同步

```bash
python3 bench/bench_cycles.py                    # 每点数秒
python3 bench/bench_compose.py --render-only     # 0.043 s：只由已有 JSON 重渲染 .md
SP1_PROVER=cpu python3 bench/bench_proofs.py     # 每点 119–173 s + ~10 GB
```

`bench/work/` 是中间产物，入库的只有 `bench/results/`。**跑完数字要四处同步**
（`README.md` / `paper/proof-of-policy.md` §7 / `docs/reproduce.md` / `modules/08`）——
**这四处没有自动化检查**。唯一有留痕的是 `regression_prove.py` 追加进
`bench/results/regression-prove.jsonl` 的那条（含 git sha / 硬件 / 二进制摘要）。

---

## 6. 环境变量速查

| 变量 | 作用 | 缺省 / 注意 |
|---|---|---|
| `SP1_PROVER` | SP1 的证明后端。**出证必须 `cpu`** | `native` 会 `unreachable` 崩溃；`light` 不能出证 |
| `POP_SIGNING_KEY` | Ed25519 私钥路径 | 缺省 `.pop-keys/signing.key`（首次自动生成，**已 gitignore**） |
| `POP_SIGNING_KEY_PASSPHRASE` | 设了则以加密形式落盘 | 不设 = 明文 PKCS#8，靠文件权限（0600） |
| `POP_SERVICE_TOKEN` | 证明服务的 token，**逗号分隔 `label:secret`**（secret 里不能有逗号） | 与 `--auth-token` / `--auth-file` **合起来**生效，不是覆盖 |
| `POP_ANCHOR_RPC` | EVM RPC 端点 | 与 `POP_ANCHOR_CONTRACT` **必须同时给**，只给一个拒绝启动 |
| `POP_ANCHOR_CONTRACT` | 已部署的 `Anchor` 合约地址 | 同上 |
| `POP_ANCHOR_KEY` | 上链提交私钥 | 缺省用 Anvil 测试键 |
| `POP_EZKL_WHEELHOUSE` | ezkl 的本地 wheel 目录 | 网络受限时用（`install_ezkl.sh`） |

**测试门控**（默认全关，开了才跑真东西；**开之前先腾空内存**）：

| 变量 | 打开什么 | 大概要多久 / 多少内存 |
|---|---|---|
| `POP_TEST_PROOF=1` | 真 vkey 出证 | ~2.5 min / ~10.2 GiB |
| `POP_TEST_COMPOSE=1` | 组合证明真端到端（两份证明） | 563.5 s / ~10.5 GiB |
| `POP_TEST_SESSION=1` | 会话聚合真端到端 | 152.5 s / ~10 GiB |
| `POP_TEST_MULTIPARTY=1` | 多证明者真端到端（两段切片） | ~4 min / ~10 GiB |
| `POP_TEST_EZKL=1` | 语义规则真 ezkl 证明 | ~61 s / ~9 GiB |
| `POP_TEST_LLM=1` + `POP_TEST_MODEL=` | 真 provider（**要网络与真 key**） | 秒级 |
| `POP_TEST_ANVIL_PORT` | 锚定 e2e 用的 anvil 端口 | 缺省 8545 |
| `POP_FAKE_FAIL` / `POP_FAKE_EXPECTED` | **只给** `tests/test_regression_prove.py` 的替身驱动用（模拟 OOM / 指定行为） | —— |

> 逐条的耗时/内存与「为什么这些逃逸路线需要单独的变量」见
> [`modules/08` §1.1](modules/08-tests-bench.md)。

---

## 7. 产物地图

| 命令 | 写在哪 | 入 git？ |
|---|---|---|
| `demo_all.sh` | `scripts/examples/out/all/`（每条支路一个子目录 + `REPORT.md`） | 否 |
| `demo_e2e.py --out-dir D` | `D`（缺省 `scripts/examples/out/e2e/`） | 否 |
| `issue_cert.py --out-dir D` | `D`：`cert.json` / `payload.json` / `key.json` / `proof.bin` / `results.json` | 否 |
| `cross_validate.py` | `scripts/.work/`（草稿；`--work-dir` 可改） | 否 |
| `proof_service.py --out-dir D` | `D`（缺省 `scripts/examples/out/service/`）：`jobs/<job_id>/`、`checks/`、`ledger.jsonl` | 否 |
| `anchor_e2e.sh` | `scripts/examples/out/chain/`（`OUT_DIR=` 可改） | 否 |
| `bench_*.py` | `bench/results/<name>.{json,md}`；中间产物在 `bench/work/` | **是**（`results/`） |
| 证明边车 | 与证明同目录：`<proof>.verify.json`、`.bytes` / `.pv` / `.vkh` | 否 |

**别把产物提交进 git。** 上面的「否」都在 `.gitignore` 里；`git status` 里看到它们才是异常。

---

## 8. 故障排查

| 症状 | 多半是 | 怎么办 |
|---|---|---|
| `SIGKILL: 9` / 一屏临时路径 / 没有末行 | **内存不足**（~10.15 GiB 地板） | 停掉其它进程重跑；`dmesg \| grep -i 'killed process'` 核实。服务会把这种失败翻成一句人话 |
| `pc_start != vk.pc_start` | 磁盘上的**证明工件比当前 guest ELF 旧**（改过 Rust 就得重新出证） | 重新跑 `issue_cert.py` / `demo_all.sh --prove`。**`scripts/examples/out/` 下的旧产物都可能是这种情况** |
| `No module named policydsl` | cwd 不在仓库根 | 回仓库根，或 `PYTHONPATH=<repo>` |
| `error: driver not built` | `pop-script` 没编译 | `cd circuits && cargo build --release -p pop-script` |
| 命令「跑了很久没停」 | 你可能敲了 `cross_validate.py --help`（它当普通参数忽略，**直接开跑真证明**） | Ctrl-C；加 `--no-prove` |
| `proof is not verifier-only verifiable` | core 模式的证明走不了 `pop-verify` 快路径 | 用 `pop-script --verify`；想要快路径就 `--proof-mode compressed` 重新出证 |
| anvil 起不来 | 端口被占 | `POP_TEST_ANVIL_PORT` / `PORT=` 换端口；`--keep` 的上一轮可能还占着 |
| 网装不上（crates / pip） | 本机限流 | 用 `retry_install_*.sh`；ezkl 用 `POP_EZKL_WHEELHOUSE` |
| 测试「全绿」但功能没好 | skip 顶掉了 | 看末行的 `skipped=`，对照 [`08` §1.1](modules/08-tests-bench.md) |

---

## 9. 相关文档

- 全部文档的索引与状态标注 → [`README.md`](README.md)
- **按功能**复现每个特性（含云机 runbook） → [`reproduce.md`](reproduce.md)
- 每个板块怎么实现 / 怎么用 / 怎么改 → [`modules/`](modules/README.md)（01–08）
- 为什么这样设计是安全的（威胁模型与反例） → [`security-model.md`](security-model.md)
- 分层与契约（一页纸） → [`architecture.md`](architecture.md)
- 证明服务的运维细节与排查表 → [`runbook-proof-service.md`](runbook-proof-service.md)
- 开发计划、待办与已登记的边界 → [`dev-plan.md`](dev-plan.md)
- 8 条 demo 支路逐条说明 → [`demo/README.md`](demo/README.md)
