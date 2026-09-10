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

## B. format / budget / tool 规则入电路

**问题**：三类规则目前仅链下参考判定，证书标 `zk:false`（安全模型的不承诺项）。

**方案**：把**输入扩展为「响应 + 工具轨迹」**，判定下沉到 `pop-types::evaluate`。
1. 请求结构（serde 默认值，向后兼容）：
   `ProofRequest { response, constraints, #[serde(default)] tool_calls: Vec<ToolCall>, #[serde(default)] token_count: Option<u32> }`，
   `ToolCall { name: String, args: BTreeMap<String,String> }`。
2. 新约束变体：
   - `FormatCheck{format: Json|Int|Float}`：guest 用 `serde_json`（no_std+alloc）；与 Python `json.loads` 的接受域差异用测试钉死子集；
   - `ToolArgGuard{tools?: [str], forbidden_fields: [str]}`：遍历 `tool_calls`，命中即违规（证据＝工具名+字段）；
   - `BudgetBound{budget, unit: Calls|Tokens}`：`calls = tool_calls.len()`；`tokens` 用请求携带的 `token_count`（文档写明是**声明值**）。
3. 跨层对齐：`policydsl/serialize.py` 增三 kind 映射；`commit.canonical_violations` 与 Rust 证据串**逐字一致**（私有承诺）；
   `AgentMonitor` 工具路径证书 `zk:false → true`；安全模型 §5 边界条目收缩。
4. 测试：`cross_validate.py` 增三组向量（host + 真证）；`tests/test_rules_incircuit.py`；私有模式证据承诺对齐。

**验收**：三规则 host 与真证均与 Python golden 逐字段一致；安全模型/论文“未入电路”表述更新。
**风险**：guest 内 serde_json 周期开销（用 `--execute` 量化）；`token_count` 语义为声明值（文档标注）。
**工作量**：2–3 天（离线可完成）。

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
