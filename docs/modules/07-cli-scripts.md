# 07 · CLI 与脚本

> 覆盖 `policydsl/__main__.py` 与 `scripts/` 下的全部脚本（9 个 Python + 4 个 shell）。
> 这一板块回答：**每个脚本负责哪一段，什么时候该用哪个。**
> 完整的复现顺序见 [`../reproduce.md`](../reproduce.md)；这里讲的是**脚本内部在做什么**。

---

## 1. 脚本地图

| 脚本 | 一句话 | 需要 Rust 二进制？ | 需要 SP1 证明？ | 典型耗时 |
|---|---|---|---|---|
| `policydsl/__main__.py` | 编译策略 / 参考判定 | 否 | 否 | 毫秒 |
| `prove_policy.py` | 单条响应 → 真实证明 + golden 比对 | `pop-script` | 是（可 `--no-prove`） | ~70 s |
| `cross_validate.py` | 14 条向量 × (host + prove) 与 golden 对拍 | `pop-script` | 是（可 `--no-prove`） | 数分钟 |
| `private_demo.py` | 私有模式全链路实验（Leak/Binding/Evidence/证明） | `pop-script` | 是（可 `--no-prove`） | ~70 s |
| `issue_cert.py` | 签发证书 + 锚定（可选上链） | `pop-script` | 是（可 `--no-prove`） | ~70 s |
| `verify_cert.py` | **第三方**独立验证单张证书 | `pop-script` / `pop-verify` | 验证已有证明 | ~20 s |
| `demo_e2e.py` | 一键真实会话（LangChain + MCP + zk + 锚定） | `pop-script` | 可 `--no-prove` | 秒级 / ~70 s |
| `verify_session.py` | **第三方**独立验证整个会话包 | 同上 | 验证已有证明 | 秒级 |
| `deploy_anchor.py` | 部署 `Anchor.sol`（字节码来自入库 artifact） | 否 | 否 | 秒级 |
| `make_shots.py` | 从会话产物生成截图/HTML/SVG | 否 | 否 | 秒级 |
| `anchor_e2e.sh` | 起 anvil → 部署 → demo → `--rpc` 核对 + 反例 | 可选 | 可 `--prove` | ~10 s / ~70 s |
| `make_audit_proof.sh` | 生成 compressed 审计 fixture | `pop-script` | 是（需 ≥16 GB） | 若干分钟 |
| `install_frameworks.sh` | 装 langchain/langgraph/mcp 到独立 venv | 否 | 否 | 取决于网络 |
| `retry_install_frameworks.sh` | 上述网络的镜像回退版 | 否 | 否 | 同上 |
| `retry_install_foundry.sh` | 装 foundry（anvil/cast/forge） | 否 | 否 | 取决于网络 |

补充：`scripts/vectors.json`、`results.json`、`results_check.json`、`results_prove.json`、
`scripts/examples/out/` 都是**运行产物**（部分入库、部分 gitignored）。

---

## 2. 各脚本的输入 / 输出 / 判定标准

### 2.1 `prove_policy.py` —— 最小的一件事

```bash
SP1_PROVER=cpu python3 scripts/prove_policy.py \
  --pack policy_packs/eu_ai_act_v1.json \
  --response scripts/examples/eu_agent_reply.txt \
  [--out-dir DIR] [--no-prove] [--expect pass|violate]
```

流程：`load_policy` → `check`（golden）→ `compile_policy` → `spec_canonical_text` →
写 `vectors.json`（`spec_canonical` 字段）→ `pop-script --check`（host）→ `pop-script`（prove）
→ 逐项与 golden 比 `passed` + 违规规则集合。

- `--expect pass|violate` 是**健全性护栏**：先验 golden 是否符合预期，不符合直接退出码 2
  （防止「测试通过」其实是因为响应早就变了）。
- 退出码：`0` PASS；`1` 比对失败；`2` 前置条件/环境错误。

### 2.2 `cross_validate.py` —— I1 的总闸门

14 条向量，覆盖六类规则各至少一条 pass + 一条 violate：

| 向量 | 规则类型 |
|---|---|
| `clean_pass` / `keyword_hit` / `length_too_long` | keyword / length |
| `email_hit` / `email_clean` / `secret_hit` / `secret_clean` | pattern（PII） |
| `format_ok` / `format_bad` | format_check |
| `tool_arg_hit` / `tool_arg_clean` | tool_arg_guard |
| `budget_over` / `budget_ok` / `token_over` | budget_bound（calls / tokens） |

比对方式：Python 的 `(rule.name, kind)` 集合 vs Rust 输出的 `(rule, kind)` 集合，加上 `passed`。
期望输出 `RESULT: host 14/14  prove 14/14  PASS`。

> 这个脚本是**改判定逻辑后必须跑的第一件事**。它把「两侧不一致」变成一次红灯，而不是等到
> 复现论文数字时才发现。

### 2.3 `private_demo.py` —— 私有模式的六个实验

构造一个含 keyword + length + email 正则三条规则的用例，并**故意**让响应同时命中关键词与邮箱。
它跑六个实验，每个都有独立的 PASS/FAIL 行：

| 实验 | 检查什么 |
|---|---|
| `check` | 电路内 `--check` 的私有输出与 golden **逐字段**一致（响应承诺 / 证据承诺 / 脱敏） |
| `negative` | 伪造见证区间 → `mask_covered=false`（证明这个性质不是恒真） |
| `leak` | 公开输出里**没有**响应/证据明文；承诺是 64 位十六进制且 ≠ 原响应 |
| `binding` | 承诺确定性、不同输入不同承诺、伪造脱敏被拒 |
| `opening` | 证据开示自洽 + 承诺与证明输出一致 + 篡改被拒 |
| `prove` | 同一任务真实证明后复查（`--no-prove` 跳过） |

### 2.4 `issue_cert.py` —— 签发 + 锚定

```bash
python3 scripts/issue_cert.py --pack P --response R --out-dir D \
    [--mode public|private] [--proof-mode core|compressed|groth16|plonk] \
    [--no-prove] [--ledger L] [--rpc URL --contract 0x…] [--private-key KEY]
```

产物：`vectors.json`、`results.json`、`proof.bin`（+ `.meta.json`/边车）、
`cert.json`（信封）、`payload.json`（明文载荷，便于阅读）、`anchor.json`（锚定条目）。

关键实现点：

- 私有模式下自动计算 `mask` / `redacted` / `spans` 并塞进向量（`--mode private`）。
- `run_pop` **强制 `SP1_PROVER=cpu`**（避免继承环境里非法的 `native`）。
- `outcome` 直接从 `results.json` 剥掉 `name`/`mode` 得到（**不重算**），保证证书里的结论 ==
  电路承诺的结论。
- 锚定走 `anchor.backend_from_env(...)`：没给 `--rpc/--contract` 就写文件账本。

### 2.5 `verify_cert.py` —— 第三方验证单张证书

```bash
python3 scripts/verify_cert.py --cert C --pack P --ledger L [--proof proof.bin] [--rpc URL --contract 0x…]
```

检查项（逐行 PASS/FAIL）：

| 检查 | 内容 |
|---|---|
| `signature` | DSSE 信封签名 |
| `policy_hash` | **重新编译**策略包并比对（不是从证书里读） |
| `anchor` | 账本链完整 + 摘要存在于账本 |
| `anchor_on_chain`（可选） | 链上 `anchoredAt` 读回，且与本地 meta 的 `chain_ts` 一致 |
| `proof_verify` / `proof_outcome` / `proof_vkey` / `proof_sha256` | 证明有效 + 承诺的 outcome/vkey/工件哈希都匹配 |
| `verify_only` / `public_values` / `vkey_hash` | 走快路径时的对应三项 |

签名失败会**提前返回**（`print_fail`），因为后面所有检查都建立在「载荷可信」之上。

### 2.6 `demo_e2e.py` —— 一键真实会话

四段，全部用**真实**组件（`--no-prove` 只跳过 SP1 证明）：

1. **LLM 流式路径**：LangChain `GenericFakeChatModel` 流式两次 —— 一次干净、一次
   中途泄露 `sk-…` 触发**早停**与链式证书；
2. **MCP 工具路径**：真实 `stdio_client` 起 `tests/mcp_echo_server.py`，
   调用 `search_kb`（干净）、`dump_config`（秘密结果）、带 `token` 参数的调用（**飞行前拦截**）；
3. **zk 路径**：对一条响应真实出证（`zk_path`），vkey 哈希与证明哈希绑进证书；
4. **锚定**：每张证书的 `cert_digest` 入账本；给了 `--rpc/--contract` 就**同时上链**
   （成功后回写 `meta.on_chain`）。

产出 `session.json`（含 `certificates` 列表、`summary`、以及有链时的 `chain` 坐标），
末尾提示用 `verify_session.py` 验证。**这是「12 张证书」的来源**。

### 2.7 `verify_session.py` —— 第三方验证整个会话

```bash
python3 scripts/verify_session.py --session S [--rpc URL --contract 0x…] [--no-chain]
```

五类检查：`ledger_chain` / `certificates_signature` / `certificates_policy_hash` /
`certificates_anchored` / `stream_chains` / `zk_proof`（+ 可选 `chain_anchored`）。

细节：

- `policy_hash` 用 `spec_cache` 缓存，同一策略包只编译一次。
- 流式链按 `chain.index == 0` **切分成多个 run**（一次会话可能有多次流式生成），逐个 `verify_chain`。
- zk 证明：有边车且模式允许 → `pop-verify` 快路径；否则 → `pop-script --verify`（core）。
- **`chain_anchored` 的交叉核对**是本脚本最有价值的一段（见 [`04`](04-anchoring-audit.md) §4）：
  逐证书读链上 `anchoredAt`，并与本地账本 `meta.on_chain` 的 `chain_ts`/`block` 三方对上。
- 未附证明的证书（`proof_sha256 is None`）会被正确地判为 `unproven (host-check only)`，不算失败。

### 2.8 `deploy_anchor.py` / `make_shots.py`

- `deploy_anchor.py`：`--rpc`（默认 `http://127.0.0.1:8545`）、`--private-key`（默认 `anchor.ANVIL_KEY`）、
  `--out`（默认 `.anchor_deploy.json`，gitignored）。**不需要 solc/forge**，字节码来自
  `contracts/Anchor.json`。末尾打印 `export POP_ANCHOR_RPC=… / POP_ANCHOR_CONTRACT=…`。
- `make_shots.py`：`--run-demo` 会先跑 demo 再生成 `docs/demo/session_report.html`、
  `session_report.svg`、`session_summary.png`、`verify_result.png`。

---

## 3. Shell 脚本

### `anchor_e2e.sh` —— 端到端链上锚定（推荐入口）

```bash
bash scripts/anchor_e2e.sh                 # 不生成证明，~10s
SP1_PROVER=cpu bash scripts/anchor_e2e.sh --prove    # 附真实 Core 证明，~66s / ~10GB
RPC=http://… bash scripts/anchor_e2e.sh    # 复用已有节点
bash scripts/anchor_e2e.sh --keep          # 结束后不关 anvil
```

步骤：① 找 foundry → ② 没节点就起 anvil（端口 `PORT`，默认 8545）→ ③ `deploy_anchor.py`
→ ④ `demo_e2e.py`（每张证书上链）→ ⑤ `verify_session.py --rpc` 独立核对
→ ⑥ **反例对照**：一个未登记的摘要必须读回 `0`。

结束后 `trap cleanup EXIT` 负责关掉自己起的 anvil（`--keep` 则保留）。
退出码：`0` 全 PASS，`1` 任一步失败。

### `make_audit_proof.sh` —— compressed 审计 fixture

生成一份**极小**策略（2 条规则 + 一句无命中的短响应）的 **compressed** 证明，
连同 `.bytes`/`.pv`/`.vkh`/`.meta.json`/`.verify.json` 一起放进 `circuits/testdata/audit_proof/`，
并把边车里的路径**重写成相对名**（避免把本机绝对路径带进仓库）。

有了 fixture，`tests/test_verifier_only.py` 的 2 个用例会自动启用（否则 skip）。
**本机 12 GB 内存下 compressed 会 OOM**，需 ≥16 GB 机器。

### 三个安装脚本

| 脚本 | 说明 |
|---|---|
| `install_frameworks.sh` | 创建独立 venv 装 langchain / langgraph / mcp；索引按镜像顺序尝试，失败不致命 |
| `retry_install_frameworks.sh` | 网络受限版：按字节数探测镜像可用性后重试，带 `--trusted-host` |
| `retry_install_foundry.sh` | 装 foundry；官方 `foundryup` 常超时，实际走 `gh-proxy.com` 拉发行包 |

> 本机网络约束（github/crates.io 直连被限流）与具体镜像配置见
> [`../reproduce.md`](../reproduce.md) §0。**git 的镜像 `insteadOf` 必须保持仓库局部，不要设成全局。**

---

## 4. 常见组合

| 想做什么 | 命令 |
|---|---|
| 快速验证一套改动没破坏一致性 | `python3 -m unittest discover tests` + `cross_validate.py --no-prove` |
| 只看结论、不出证 | 给任意脚本加 `--no-prove`（走 `pop-script --check`） |
| 第三方复核一张证书 | `verify_cert.py --cert … --pack … --ledger … [--proof …]` |
| 全链路最小复现 | `bash scripts/anchor_e2e.sh` |
| 生成论文/文档用的截图 | `python3 scripts/make_shots.py --run-demo` |

---

## 5. 约定与注意

1. **路径解析统一用 `REPO = Path(__file__).resolve().parent.parent`**，因此仓库改名/搬家不影响脚本
   （仓库曾从 `方向二` 改名为 `Proof-of-Policy`）。
2. **二进制路径固定**：`circuits/target/release/pop-script` 与 `pop-verify` —— 没构建时脚本会给出
   `cd circuits && cargo build --release -p pop-script` 的提示。
3. **`SP1_PROVER=cpu` 是硬要求**；`issue_cert.run_pop` 直接 `env=dict(os.environ, SP1_PROVER="cpu")`
   覆盖，`anchor_e2e.sh` 在调用处显式带上。
4. **退出码语义**：`0` PASS / `1` 比对或验证失败 / `2` 前置条件不满足（缺二进制、`--expect` 不符等）。
5. **产物目录约定**：`scripts/examples/out/<场景>/`；账本默认
   `scripts/examples/out/ledger.jsonl`。
6. **CI 只跑不需要 Rust 与网络的部分**（见 `.github/workflows/ci.yml`）：
   Python 测试套件 + 锚定测试（离线 fake-RPC）+ 一条「文档里没有陈旧绝对路径」的检查。

---

## 6. 测试对应

| 测试 | 覆盖的脚本 |
|---|---|
| `tests/test_verifier_only.py` | `verify_cert.py` / `verify_session.py` 的快路径判定 |
| `tests/test_demo_e2e.py` | `demo_e2e.py` 的会话产物结构 |
| `tests/test_anchor_chain.py::TestAnvilEndToEnd` | `deploy_anchor.py` 的部署与读回 |
| （间接）`tests/test_rules_incircuit.py` | `cross_validate.py` 所用路径的单元版 |

---

## 7. 扩展指引

- **加一个新的验证维度**（如「策略包是否被多张证书一致引用」）：在 `verify_session.py` 的
  `results` 列表里追加一项 `(name, ok, detail)` 即可 —— 打印与退出码会自动跟上。
- **加一个新后端**：`anchor.backend_from_env` 认识新配置项后，`issue_cert.py` / `demo_e2e.py`
  **无需改动**（它们只调 `backend.anchor(...)`）。
- **把脚本接到 CI**：优先选 `--no-prove` 路径 + 离线 fake，避免在 CI 里跑证明或依赖网络。

---

**相关**：一键锚定的原理 → [`04-anchoring-audit.md`](04-anchoring-audit.md)；
完整复现步骤与环境要求 → [`../reproduce.md`](../reproduce.md)。
