# P7 实施计划：verifier-only / 规则入电路 / 链上锚定

> 决策（用户 2026-09-10）：**保留 Core 为默认证明模式**；另设 `--proof-mode compressed` 供审计（verifier-only）路径。
> **真跑本地 Anvil**（不满足于假 RPC）。
> 网络现状（2026-09-10 实测）：`rsproxy` / `pypi.tuna` / `github` / `gh-proxy` **全部超时** → 外部下载暂不可用；
> 但 A 所需 Rust crate（`sp1-verifier` / `bincode` …）**已在本地 cargo 缓存**，可离线构建。Anvil/foundry 与 solc **当前无法下载**。

---

## A. verifier-only 二进制（免构造证明器）—— 已实现（fixture 待更大内存）

**已交付**
1. `circuits/verifier`（bin `pop-verify`，只依赖 `sp1-verifier`，**不依赖 sp1-sdk/prover**）：
   `pop-verify --meta <proof>.verify.json` → 支持 `compressed`（`SP1CompressedVerifierRaw::verify_with_public_values`）
   与 `groth16`/`plonk`（`Groth16Verifier`/`PlonkVerifier` + 内置 VK 常量）；`core` 明确拒绝并给出提示（exit 3）。
2. `circuits/script`：`--proof-mode core|compressed|groth16|plonk`（**默认 core 不变**）；`--proof-out` 额外写验证边车
   `<proof>.bytes` / `.pv` / `.vkh` / `.verify.json`（含 `proof_mode`/`vkey_hash_str`）。
3. Python：`verify_cert.py` / `verify_session.py` 在**存在边车且 `pop-verify` 已构建**时走快路径（纯函数 `prefer_verifier_only()` 已单测）；
   证书 `binding` 新增 **`public_values_sha256`**（`issue_cert.py`/`demo_e2e.py` 写入，二者绑定公开值）。
4. 测试 `tests/test_verifier_only.py`（4 例：模式校验/选择逻辑/无需 SP1 环境；fixture 用例在缺 fixture 时跳过）。

**实测阻塞（重要）**：本机 12 GB WSL 下 **compressed 证明 OOM**（1:51 时被 OOM killer 终止，峰值 anon-RSS **11.0 GB**；
`SHARD_SIZE`/`MEMORY_LIMIT` 调参对**固定递归开销**无效）。Core 证明仍正常（~10 GB，回归 PASS）。
→ **审计路径产物需 ≥16 GB 内存**（或换机/Windows 侧）生成；已提供 `scripts/make_audit_proof.sh` 一键生成 fixture
（生成后 `tests/test_verifier_only.py` 的 fixture 用例自动启用）。

**验收（部分达成）**：`pop-verify` 构建/模式处理/快路径选择已测；**端到端（真实 compressed 证明 + pop-verify 验证）待 ≥16 GB 环境**。

**跟进选项**：把 WSL 上调到 15–16 GB 重试（宿主 15.7 GB，需权衡）；或在更大内存机器/CI 上跑 `make_audit_proof.sh`。

## B. format / budget / tool 规则入电路 —— 已实现

**已交付**
1. `pop-types`：请求扩展为「响应 + 工具轨迹」（`ProofRequest.tool_calls/token_count`，`PrivateRequest` 同）；
   新增 `Constraint::{FormatCheck, ToolArgGuard, BudgetBound}` 变体与 `ToolCall`/`FormatKind`/`BudgetUnit`。
2. `evaluate`（guest 与宿主共用）：JSON 用 `serde_json`（no_std+alloc）；`int`/`float` 采用**规范子集**
   （int：可选符号 + 1..=19 ASCII 数字；float：拒绝 `_`/`nan`/`inf`）——与 Python golden **逐点对齐**；
   `tool_arg_guard` 支持 `tools` 限定；`budget_bound` 的 `calls` 用 `tool_calls.len()`，`tokens` 用声明的 `token_count`。
3. 跨层：`serialize.py` 增三 kind 映射；`commit.canonical_violations` 证据串与 Rust **逐字一致**
   （`format`、`tool:field`、`unit=total/budget`），私有模式证据承诺因此可比对；`AgentMonitor` 工具路径 `zk:true`。
4. 测试：`tests/test_rules_incircuit.py`（8 例：三类规则 host 对齐 + 规范子集边界 + **私有证据承诺逐字一致**）；
   `cross_validate` 扩到 **14 向量**（含 format/tool/budget/token）。

**验收**：host 交叉验证 **14/14 PASS**；**真实证明交叉验证 14/14 PASS**（含 format/tool/budget/token 全部四类新向量）。
**边界（保留）**：`token_count` 为声明值（非电路内分词）；`int/float` 仅规范子集（超集输入按子集规则拒绝，已文档化）。

## C. 链上锚定 RPC 后端（真跑本地 Anvil）

**问题**：`anchor_on_chain` 仅为桩；账本只有本地文件。

**方案（三层）**
1. **合约**：`contracts/Anchor.sol`（`anchor(bytes32)` → event `Anchored(digest,ts)` + `mapping anchoredAt`）；
   另附 `contracts/Anchor.json`（abi+bytecode）**入库**，使运行期**不需 solc/forge**。
2. **后端抽象**（`policydsl/anchor.py`）：`FileLedgerBackend`（现有，默认）/ `RpcAnchorBackend(rpc_url, contract, key)`
   （`web3.py`：`anchor()` 发交易并回写 `tx_hash` 到本地条目；`get()` 用 `eth_call` 读回时间戳）；`verify_session --rpc` 可选核对。
3. **真链**：本地 **Anvil**：
   - 首选 foundry（`foundryup` / 发行包）——**当前 github/gh-proxy 不可达，暂不可装**；
   - 备选：Windows 侧 Docker Desktop 起 `foundry` 容器（需 Docker 拉镜像，同样依赖网络）；
   - 退路（无网也可跑）：用 `web3.py` + **已入库 bytecode** 部署到任何本地 EVM（如用户自备节点/测试网）。

**实施顺序**：先落地「合约源码 + 入库 bytecode + RPC 后端 + 假 RPC 单测」，等网络恢复后再补 **Anvil 端到端**
（`deploy → anchor → eth_call 读回 → verify_session --rpc` PASS）。可加**定时重试**（网络恢复自动安装并跑通）。

**验收**：Anvil 上端到端 PASS；无 RPC 时默认文件后端不受影响；`--rpc` 缺失时给出明确提示。
**工作量**：2–3 天（含环境）；离线部分 1 天。

---

## 顺序、依赖与验收基线

```
A (离线可做, 立取收益) ─► 论文 verifier 数字更新
B (离线可做)            ─► 安全模型边界收缩
C (代码离线可做; Anvil 待网络) ─► 依赖 A 的 compressed/groth16 产物做链上验证
```
每项完成的**统一门槛**：`python3 -m unittest discover tests` 全绿（skip 为设计内）→ `cross_validate`（host+prove）→ 需要时 `verify_session` PASS →
刷新 `bench/results/*` 与论文数字 → git 提交（含 Co-Authored-By）。
