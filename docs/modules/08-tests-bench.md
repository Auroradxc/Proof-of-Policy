# 08 · 测试与评测

> 覆盖 `tests/`（17 个模块，184 个用例）与 `bench/`（3 个脚本，结果入库在 `bench/results/`）。
> 这一板块回答：**哪些性质被自动化守住了，论文里的数字是怎么测出来的。**

---

## 1. 测试套件总览

```bash
python3 -m unittest discover tests -v      # 期望 184 passed, 5 skipped
```

| 模块 | 用例数 | 守护的性质 |
|---|---:|---|
| `test_dsl` | 23 | 领域模型、六类规则的通过/违规矩阵、`PolicyError` 路径 |
| `test_nfa` | 7 | 正则子集解析、NFA 构造、`match_search` 与 `re` 的行为对照、fail-fast |
| `test_pii` | 8 | 四个 PII 模式的命中/漏报、IBAN MOD-97 校验位 |
| `test_serialize` | 9 | serde 外部标签枚举形状、未知 kind 抛 `NotImplementedError`、`spec_canonical` 字节稳定 |
| `test_commit` | 12 | 承诺、私有输出、掩码覆盖、脱敏、证据开示 |
| `test_policy_binding` | 16 | **P0-1**：策略绑定三方比对；「空策略证明 + 真策略哈希」攻击回归；未入电路的 kind **fail-closed** |
| `test_binding` | 19 | **P0-2**：挑战-响应绑定（①正确对通过 ②换 T 拒 ③换 nonce 拒 ④空 nonce 独立域）、`NonceStore` 重放、Python↔Rust 逐字节对齐、带挑战证书端到端 |
| `test_cert` | 4 | 证书载荷、`cert_digest` 稳定性、签名与篡改拒绝 |
| `test_agent` | 5 | `AgentMonitor` 两条路径、`mock_agent` 确定性、LangGraph 适配 |
| `test_frameworks` | 26 | LangChain 回调（流式链/篡改/早停）、`guard_node`、`astream_events` |
| `test_mcp` | 9 | 参数侧飞行前拦截、结果侧判定、文本提取 |
| `test_anchor` | 4 | 账本读写、`verify_ledger`、篡改检出 |
| `test_anchor_chain` | 22 | 合约 artifact、摘要编码、后端选择、RPC 后端离线（幂等/竞态）、cast 命令行、anvil 端到端 |
| `test_rules_incircuit` | 8 | 六类规则在 `--check` 下与 Python golden 逐点对齐 |
| `test_ablation` | 5 | pike ≡ naive（Python 与 Rust 两侧） |
| `test_verifier_only` | 5 | `prefer_verifier_only` 三条件、core 不走近路 |
| `test_demo_e2e` | 2 | 端到端会话产物结构 |
| **合计** | **184** | |

### 5 个 skip（都是设计内的）

| skip | 原因 | 怎么启用 |
|---|---|---|
| `test_verifier_only` 中 2 例 | `circuits/testdata/audit_proof/` 没有 compressed fixture | 在 ≥16 GB 机器上跑 `SP1_PROVER=cpu bash scripts/make_audit_proof.sh` |
| `test_frameworks`（或 `test_mcp`）中 1 例 | 依赖已安装而用例本身是「缺依赖时的行为」 | 设计如此，装了框架就会 skip |
| `test_policy_binding` 中 2 例 | 「证明层」用例默认关闭（每例真出一次 core 证明，~2 分钟） | `POP_TEST_PROOF=1 python3 -m unittest tests.test_policy_binding` |

> `test_binding` 的 19 例**全部实际执行**：它靠 `pop-script --check`（秒级、不出证明）做
> Python↔Rust 逐字节比对，不需要真证明，因此不受 `POP_TEST_PROOF` 门控。

> 这是当前环境下的计数（`langchain`/`langgraph`/`mcp` 与 `pop-script`/`pop-verify` 均已安装，
> 因此真实框架用例与 Rust 路径用例**实际执行**了，而不是跳过）。

### 分层设计：为什么没装框架也能跑

所有框架适配器都遵循「**导入回退 + 离线 fake**」：

| 层次 | 手段 | 例子 |
|---|---|---|
| 真依赖存在 | 跑真实端到端 | `test_mcp.py` 起真 `stdio_client` 子进程；`test_frameworks.py` 用真 LangChain/LangGraph |
| 真依赖缺失 | 鸭子类型 fake | `test_mcp.py::FakeSession`（记录 `calls` 以证明「拦截发生在执行前」） |
| Rust 二进制缺失 | 用 `skipUnless` 跳过 | `test_rules_incircuit.py`、`test_ablation.py::TestRustNaivePath` |
| foundry 缺失 | 跳过 anvil e2e | `test_anchor_chain.py::TestAnvilEndToEnd` |

CI（`.github/workflows/ci.yml`）跑的是**最轻的一档**：Python 套件 + 锚定测试（离线 fake-RPC）
+ 一条文档卫生检查（禁止出现陈旧的绝对路径 `/home/*/方向二`）。**不跑证明、不依赖网络。**

---

## 2. 测试 ↔ 性质对照（安全模型）

把 `../security-model.md` 的定义映射到具体用例：

| 定义 | 对应用例/脚本 |
|---|---|
| Completeness | `scripts/prove_policy.py`（eu pass）、`cross_validate.py` 14/14 |
| Soundness（入电路规则） | `cross_validate` 的 violate 向量、`private_demo` 的违规用例 |
| Content privacy | `test_commit.py::TestPrivateOutput`（无明文泄露）、`private_demo` 的 `leak` 实验 |
| Redaction soundness | `test_commit.py::TestMaskCoverage`（伪造 span → `mask_covered=false`） |
| Evidence unforgeability | `test_commit.py::TestEvidenceOpening`（篡改开示 → 失败） |
| Provenance | `scripts/verify_cert.py` 的 `policy_hash`/`vkey`/`proof_sha256` 卡；`test_cert.py`；`test_policy_binding.py`（P0-1 攻击回归） |
| Response binding (A6) | `scripts/verify_cert.py --response` 卡；`test_binding.py`（换 T′/换 nonce/域分离）；`demo_e2e` 的 challenge 实验 |
| Ledger integrity | `test_anchor.py`（链篡改检出）、`verify_session.py::ledger_chain` |
| Stream chain | `test_frameworks.py`（链路验证/篡改/早停） |
| 链上锚定 | `test_anchor_chain.py`（离线 fake + anvil e2e）、`anchor_e2e.sh` 的 `chain_anchored` 与反例 |
| End-to-end | `scripts/verify_session.py` 全 PASS（含真实 SP1 证明） |

**关键的一类测试是「负例/反例」**：伪造 span、篡改开示、篡改账本条目、未登记摘要读回 0、
core 边车不得走快路径 —— 这些保证正向检查**不是恒真**的。

---

## 3. 评测（`bench/`）

三个脚本，覆盖三种成本：

| 脚本 | 测什么 | 用时不出证？ | 输出 |
|---|---|---|---|
| `bench_cycles.py` | **zkVM 周期数**（`pop-script --execute`） | 每点数秒 | `bench/results/cycles.{json,md}` |
| `bench_proofs.py` | **证明墙钟时间 + 工件大小 + 峰值内存** | 每点 ~100–150 s | `bench/results/proofs.{json,md}` |
| `bench_verify.py` | **验证成本**（冷启动 CLI / vkey setup / 纯验证） | 每次 ~20 s | `bench/results/verify.{json,md}` |

```bash
python3 bench/bench_cycles.py
SP1_PROVER=cpu python3 bench/bench_proofs.py
SP1_PROVER=cpu python3 bench/bench_verify.py --proof <proof.bin>
```

**设计要点**（都写在 `bench/README.md`，改评测前先读）：

- 变长响应由 `bench_cycles.response(prefix, length)` 生成，**保证不含任何命中词** ——
  这样每条约束都被扫描到底，测的是**最坏情况扫描成本**，而不是命中即停的短路成本。
- 规则数 1/3/6：1 = 仅长度（基线）；3 = +keyword+pattern；6 = +更多 keyword/pattern。
  第一条固定为 `length_bound`，使不同规则数之间只差「扫描量」。
- **消融**：`match_mode="naive"`（每个起点重跑 NFA，O(n²)）对照默认 `pike`。
  naive 只在 `length ≤ 2000` 上跑（>2000 在 zkVM 内过慢）。
- `bench_cycles` 走**子进程**调 `pop-script`（而不是 import），以测真实 CLI 路径的开销。
- `bench_proofs` 用 `/usr/bin/time` 抓峰值 RSS；每个点跑完顺手 `--verify` 确认证明有效。

### 3.1 周期数矩阵（`bench/results/cycles.md`）

| length | rules | mode | cycles |
|---:|---:|:--|---:|
| 200 | 1 | pike | 8,333 |
| 200 | 3 | pike | 879,595 |
| 200 | 3 | naive | 1,623,555 |
| 200 | 6 | pike | 1,224,009 |
| 2000 | 1 | pike | 12,454 |
| 2000 | 3 | pike | 8,392,873 |
| 2000 | 3 | naive | 15,855,095 |
| 2000 | 6 | pike | 11,266,423 |
| 2000 | 6 | naive | 20,542,001 |
| 20000 | 1 | pike | 54,374 |
| 20000 | 3 | pike | 83,514,326 |
| 20000 | 6 | pike | 111,684,879 |

读法：基线（仅长度）近线性（20k 字 5.4e4 周期）；字符串规则约 **~4.2k 周期/字符**
（20k×3 = 83.5M；20k×6 = 111.7M）。`naive` 在同样输入下约 1.85× / 1.89× pike —— 这只是
**非对抗输入**下的差距，见 §3.2。

### 3.2 消融：对抗输入下的二次退化

用对抗输入（一串 `a` 后跟一个 `b`）压朴素匹配器，比值随 n 翻倍：

| n | pike | naive | 比值 |
|---:|---:|---:|---:|
| 100 | 519,955 | 12,748,918 | 24.5× |
| 200 | 1,021,653 | 50,441,932 | 49.4× |
| 400 | 2,024,955 | 200,722,858 | 99.1× |

比值近似随 n **线性增长** ⇒ naive 的绝对代价是 **O(n²)**，pike 保持线性。
这是「策略合规匹配」这一场景下的首个消融证据（论文 §7.2）。
两个匹配器的**语义等价**由 `tests/test_ablation.py` 保证 —— 否则这个对比没有意义。

### 3.3 真实证明成本（`bench/results/proofs.md`）

| length | rules | time (s) | proof (KiB) | peak RSS (MiB) | verified |
|---:|---:|---:|---:|---:|:--|
| 200 | 3 | 127.44 | 2723.2 | 10764.8 | yes |
| 200 | 6 | 140.47 | 2726.7 | 10862.4 | yes |
| 1000 | 1 | 98.5 | 2713.3 | 9826.3 | yes |

结论：证明时间由**证明器固定开销主导**（~100 s 量级），长度/规则数的边际影响体现在 zkVM 周期数上；
证明工件稳定在 ~2.7 MiB；峰值内存 ~10 GB —— 这就是「复现需要 ≥12 GB 内存」的来源。

### 3.4 验证成本（`bench/results/verify.md`）

| proof | cold CLI (s) | vkey setup (s) | pure verify (ms) |
|---|---:|---:|---:|
| `bench/work/proof.bin` | 22.799 | 1.616 | 89.84 |

- **cold CLI** 包含构造 SP1 证明器客户端（重）—— 这是实现细节造成的，不是密码学成本；
- **pure verify** 是「vkey setup 一次 + N 次验证」，即 ~90 ms。

`pop-verify`（`05` §5）正是为了消掉 cold CLI 里的证明器构造而存在的：它只依赖 `sp1-verifier`。
`bench/results/verify.md` 里那句 “A verifier-only path … is future work” 是**写入时的状态**，
现已实现（`circuits/verifier`、`policydsl/verifier.py`）；重跑该 benchmark 可更新这一行。

### 3.5 对标 zkAgent

详见 [`bench/comparison_zkagent.md`](../../bench/comparison_zkagent.md) 与论文 §7.4。
一句结论：二者**证明义务不同**（推理完整性 vs 策略合规），**不可宣称「PoP 更快」**；
正确表述是「在不涉模型的前提下，以同量级证明时间、低一个数量级的硬件、与 LogUp 相当的证明规模
完成，并补上没有的内容隐私」。

---

## 4. 不变量与边界

1. **结果文件入库**：`bench/results/*.{json,md}` 是**提交进仓库**的（供论文/文档引用），
   中间产物 `bench/work/` 被 gitignore。
2. **重跑要声明环境**：内存、CPU 核数、`SP1_PROVER` 取值都会显著影响数字；
   对比时务必确认是同一档配置（本机：24 核 / 12 GB）。
3. **naive 只在小长度上测**：这不是遗漏，是刻意的（zkVM 内 O(n²) 会失控）。
4. **测试不得依赖网络**：所有网络相关行为都要有离线回退，否则 CI 会红。
5. **测试不得依赖 SP1 证明**（除非显式声明）：默认路径是 `--check`；真实证明用例要
   `skipUnless` 二进制存在。
6. **`tests/mcp_echo_server.py` 的 `@tool` docstring 不翻译**：它会被发给模型，属于功能字符串。

---

## 5. 扩展指引

- **加测试**：优先补「负例」——正向检查容易写成恒真，反例才有价值（参考 `TestMaskCoverage`、
  `TestAnvilEndToEnd` 的反例对照）。
- **加评测点**：改 `bench_cycles.py` 的 `lengths` / `rule_counts`；`bench_proofs.py` 的采样点
  要克制（每点 ~2 分钟 + 10 GB 内存）。
- **更新论文数字**：跑完 `bench_*.py` 后，`README.md`、`paper/proof-of-policy.md` §7、
  `docs/reproduce.md` 的验收判据里都有硬编码的数字，需要一并核对。
  当前验收判据是 **184 passed / 5 skip**、`cross_validate` host 14/14 + prove 14/14。

---

**相关**：各板块覆盖了什么 → [`01`](01-policy-dsl.md)～[`07`](07-cli-scripts.md) 各文档的「测试对应」小节；
跑起来 → [`../reproduce.md`](../reproduce.md)。
