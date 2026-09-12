# P7 实施计划：verifier-only / 规则入电路 / 链上锚定

> 决策（用户 2026-09-10）：**保留 Core 为默认证明模式**；另设 `--proof-mode compressed` 供审计（verifier-only）路径。
> **真跑本地 Anvil**（不满足于假 RPC）。
> 网络现状（2026-09-10 实测）：`rsproxy` / `pypi.tuna` / `github` / `gh-proxy` **全部超时** → 外部下载暂不可用；
> 但 A 所需 Rust crate（`sp1-verifier` / `bincode` …）**已在本地 cargo 缓存**，可离线构建。
> **2026-09-10 更新**：网络恢复，foundry **1.8.1 已装**（anvil/forge/cast，见 `scripts/retry_install_foundry.sh`）→ C 的端到端已真跑通过。

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

**实测阻塞（已按选项 C→B 处理）**：本机 12 GB WSL 下 **compressed 证明 OOM**（1:51 被 OOM killer 终止，峰值 **11.0 GB**）；
随后按**选项 C** 实测 **groth16** —— 同样 **OOM**（exit 137，1:36，峰值 **11.07 GB**，**内存占用与 compressed 相同**，无改善）；
`SHARD_SIZE`/`MEMORY_LIMIT` 对**固定递归开销**无效（`drop_ldes` 未在 sdk 暴露）。
→ **采用选项 B**：审计 fixture 交**≥16 GB** 机器/CI 生成；本仓库保留 `scripts/make_audit_proof.sh` 与自动跳过的 fixture 用例；
Core 证明路径不受影响（~10 GB，回归 PASS）。

**验收（当前状态）**：`pop-verify` 构建/模式处理/快路径选择已测；**端到端（真实 compressed 证明 + pop-verify 验证）待 ≥16 GB 环境**。

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

> ⚠️ **本节记述的是 P7 当时的状态，其中两处已被 P1-5 取代**（2026-09-11）：
> ① `ProofRequest.tool_calls` / `token_count` 与 `ToolCall` **已删除**，代之以网关签发的
> `receipts` 回执链；② `budget_bound(tokens)` 不再是"声明的 `token_count`"，而是**电路内自算**。
> 现状见 `docs/plan-p0p1p2.md` §P1-5 与 `docs/modules/05-zk-circuits.md` §2.3a。本节保留作对照，
> 不复写历史。
>
> ③ 向量数：P7-b 交付时是 **14 向量**，后续叠加 P1-5（回执链）、P2-9b（同形折叠）后
> 现为 **19 向量** —— 上文的「14/14」只在当时的向量集上成立，当前口径见
> `docs/reproduce.md` §验收判据（`host 19/19 · prove 19/19`）。

## C. 链上锚定 RPC 后端（真跑本地 Anvil）—— 已实现并端到端 PASS

**问题**：`anchor_on_chain` 仅为桩；账本只有本地文件。

**已交付**
1. **合约** `contracts/Anchor.sol`：`anchor(bytes32)`（**首次即最终**，重复登记 revert）
   → `anchoredAt/anchoredBy/isAnchored/count` + `Anchored(digest, ts, by, seq)` 事件；
   链上**只存 32 字节摘要**。`contracts/Anchor.json`（abi+bytecode）**入库**，
   运行期部署/锚定**不需要 solc/forge**（只需 `cast` + RPC）；`contracts/README.md` 记录重新生成方式。
2. **后端抽象** `policydsl/anchor.py`：`AnchorBackend` 接口 + `FileLedgerBackend`（默认，离线可验）
   / `RpcAnchorBackend(rpc_url, contract, key, ledger_path)`；`backend_from_env()` 统一选择；
   `anchor_on_chain()` 由桩变可用（只读工具 `verify_digest_on_chain()` 供验证方使用）。
   - 底层 RPC 客户端 = **foundry `cast`**（`CastRpc`，可注入以便离线单测），**不引入 web3.py/eth-account 依赖**
     （偏离原计划的自研方向；理由：Anvil 端到端本就需要 foundry，`cast` 已是既有依赖，少一层 Python 依赖）。
   - `anchor()` **幂等**：先 `anchoredAt` 查询；并发下遇到 `already anchored` revert 也按幂等处理。
   - 链上成功后才把 `tx_hash`/区块/链上时间戳写进本地账本 `meta.on_chain`（哈希链保持自洽）。
3. **工具链**：`scripts/deploy_anchor.py`（部署，打印 `POP_ANCHOR_RPC/CONTRACT`）；
   `issue_cert.py` / `demo_e2e.py` 支持 `--rpc/--contract`；
   `verify_session.py` / `verify_cert.py` 支持 `--rpc/--contract` 链上核对；
   `scripts/anchor_e2e.sh` 一键：起 anvil → 部署 → 会话 demo（13 张证书全部上链）→ 第三方核对 → **反例对照**。

**顺带修掉的真 bug**：`pop-script --proof-out` 会给**所有**模式（含 core）写 `<proof>.verify.json` 边车，
而「走 verifier-only 快路径」的判定原先只看边车是否存在 → **core 证明被误判为快路径**，`pop-verify` 以 exit 3 拒绝
（真跑带证明的链上 e2e 才暴露）。已抽出 `policydsl/verifier.py::prefer_verifier_only`（二进制 + 边车 + 模式 ∈
{compressed,groth16,plonk}），`verify_session`/`verify_cert` 共用，并补单测（core 边车必须回落 `pop-script --verify`）。

**实测（2026-09-10，本机 WSL 12 GB，foundry 1.8.1）**
- `bash scripts/anchor_e2e.sh`（无证明，冷启动自建 anvil）→ **ALL PASS**：
  `chain_anchored 14/14 digests on chain … (14 cross-checked)` + 反例 `unknown digest anchoredAt = 0`。
- `SP1_PROVER=cpu bash scripts/anchor_e2e.sh --prove` → 真实 Core 证明（2.78 MB）生成并**上链锚定 14/14**；
  第三方验证走 `pop-script --verify` 回落路径 PASS。
- `tests/test_anchor_chain.py` **22 例全绿**（含真链 `deploy→anchor→读回→幂等→账本回写`，无 anvil 时自动 skip）。

**验收**：Anvil 上端到端 PASS ✅；无 RPC 时默认文件后端不受影响 ✅；`--rpc` 缺失时给出明确提示 ✅。
**边界（保留）**：仍在本地 Anvil / 自备 RPC；未接公共测试网；上链交易用明文私钥参数（demo 用 Anvil 公开测试键，
生产应换 keystore/HSM）。

---

## 顺序、依赖与验收基线

```
A (离线可做, 立取收益) ─► 论文 verifier 数字更新
B (离线可做)            ─► 安全模型边界收缩
C (代码离线可做; Anvil 待网络) ─► 依赖 A 的 compressed/groth16 产物做链上验证
```
每项完成的**统一门槛**：`python3 -m unittest discover tests` 全绿（skip 为设计内）→ `cross_validate`（host+prove）→ 需要时 `verify_session` PASS →
刷新 `bench/results/*` 与论文数字 → git 提交（含 Co-Authored-By）。
