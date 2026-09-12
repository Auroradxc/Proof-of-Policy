# 04 · 锚定与审计

> 覆盖 `policydsl/anchor.py`、`contracts/`、`policydsl/verifier.py`。
> 这一板块回答：**怎么让「某张证书在某时刻已存在」这件事变得不可否认、可被任何第三方核对。**

---

## 1. 职责

锚定的对象是 **`cert_digest`**（证书载荷的 SHA-256，见 `03`）—— 不是证书本身，更不是响应内容。
链上/账本里只有 32 字节摘要。

两种后端，**同一个 `anchor()` 接口**，上层（`demo_e2e.py` / `issue_cert.py`）只换后端不改逻辑：

| 后端 | 类别 | 可验证性 | 依赖 |
|---|---|---|---|
| `FileLedgerBackend` | **默认** | 离线可验（哈希链自证） | 无 |
| `RpcAnchorBackend` | 可选 | 公共时间戳 + 链的不可篡改性 | foundry `cast` + EVM RPC |

后端选择逻辑在 `backend_from_env(ledger_path, rpc_url, contract, private_key, require=False)`：
**给了 RPC 与合约地址 → 上链；否则 → 文件账本**。`require=True` 时配置不全直接报错
（供 `--rpc` 这类显式请求使用，避免调用方误以为「已经上链」其实只写了本地文件）。

---

## 2. 文件哈希链账本（默认后端）

每行一条 JSON，记录彼此链接：

```jsonc
{"seq": 12,
 "prev": "<上一条记录的 hash>",          // 首条为 "genesis"
 "digest": "<cert_digest>",
 "ts": "2026-09-10T12:00:00Z",
 "meta": {"kind": "zk", "policy": "agent-content-v1",
          "on_chain": {"contract": "0x…", "tx_hash": "0x…", "block": 42,
                       "chain_ts": 1789041583, "chain_ts_iso": "…"}},
 "hash": "<SHA256(canonical(去掉 hash 字段后的本条记录))>"}
```

**自引用规避**：`_entry_hash` 先剔除 `hash` 字段再求哈希，否则无法自洽。

`verify_ledger(path) -> (ok, reason)` 重新计算整条链，依次校验三件事：

1. `seq` 从 0 连续递增；
2. `prev` 等于上一条的 `hash`；
3. `hash` 等于按内容重算的值（**能检出篡改**）。

任一编辑/重排/删除都会被定位到具体条目（`entry N: hash mismatch (tampered)`）。

---

## 3. 链上锚定（`RpcAnchorBackend` + `contracts/Anchor.sol`）

### 合约语义（`contracts/Anchor.sol`）

```solidity
contract Anchor {
    mapping(bytes32 => uint256) private _ts;      // 登记时间戳（0 = 未登记）
    mapping(bytes32 => address) private _by;
    uint256 public count;

    event Anchored(bytes32 indexed digest, uint256 ts, address indexed by, uint256 seq);

    function anchor(bytes32 digest) external {
        require(_ts[digest] == 0, "Anchor: already anchored");   // 首次即最终
        ...
    }
    function anchoredAt(bytes32) external view returns (uint256);
    function anchoredBy(bytes32) external view returns (address);
    function isAnchored(bytes32) external view returns (bool);
}
```

三个设计选择：

- **首次即最终**：重复登记直接 revert，链上时间戳不可被后来者覆盖。
- **只存摘要**：`bytes32` 而非字符串/JSON —— 链上不泄露响应、策略或任何内容。
- **`anchoredAt == 0` 表示「未登记」**（区块时间戳本身永远不为 0），因此 `get()` 可以无歧义地判空。

### 部署不需要 solc/forge

`contracts/Anchor.json` 是**入库的 artifact**（`{_comment, contractName, solc, abi, bytecode}`，653 字节字节码），
`deploy_anchor_contract` 直接读它发 `--create` 交易。运行期只需要 `cast` + 一个 RPC 端点。
重新生成方式见 `contracts/README.md`（`cd contracts && forge build`，solc 0.8.24 已在 `~/.svm` 缓存）。

### `CastRpc`：用 foundry `cast` 当客户端

选择子进程 `cast` 而非 `web3.py`，是为了**不引入 Python 依赖**（anvil 端到端本来就需要 foundry）。

| 方法 | 说明 |
|---|---|
| `chain_id()` / `block_number()` | 链状态 |
| `deploy(bytecode, pk)` | 部署，返回 `{address, tx_hash, block}` |
| `send_anchor(contract, digest_b32, pk)` | 调 `anchor(bytes32)`，返回 `{tx_hash, block}` |
| `call_uint / call_address / call_bool` | `eth_call` view 函数 |
| `timestamp_of_block(block)` | 读区块时间戳（交叉核对用） |
| `address_of_key(pk)` | 由私钥推导地址（写进本地 meta 供审计） |

> **参数顺序陷阱（踩过的坑）**：`cast` 的 `--rpc-url` 必须**紧跟子命令**，且 `--create` 的字节码必须是
> **最后一个位置参数**。所以 `_run(*args, tail=(), with_rpc=True)` 专门区分了「子命令之后的参数」
> 与「必须排在最后的 tail」。另外 `cast wallet` 是**本地**子命令，不接受 `--rpc-url`（用 `with_rpc=False`）。
> `pop-script`/测试里有对应的断言（`tests/test_anchor_chain.py::TestCastCommandLines`）。

### `RpcAnchorBackend.anchor()` 的两条性质

1. **幂等**：先 `anchoredAt(d)` 查询；已登记 → 直接返回 `{"status": "already_anchored", ...}`。
   并发/竞态下如果 `cast` 报 `already anchored` revert，也按幂等处理（再查一次）。
2. **先有事实，后有记录**：**链上成功后**才把 `tx_hash`/区块号/链上时间戳写进本地账本条目
   的 `meta.on_chain`。哈希链因此始终自洽（全局不变量 I5）。

返回记录形状：

```jsonc
{"backend": "rpc", "status": "anchored",
 "digest": "<64hex>", "contract": "0x…",
 "chain_ts": 1789041583, "chain_ts_iso": "…", "anchored_by": "0x…",
 "tx_hash": "0x…", "block": 42,
 "ledger": {"seq": 12, "hash": "<64hex>"}}     // 给了 ledger_path 时才有
```

### 环境变量与配置

| 变量 | 用途 |
|---|---|
| `POP_ANCHOR_RPC` | RPC 端点，如 `http://127.0.0.1:8545` |
| `POP_ANCHOR_CONTRACT` | 已部署的 Anchor 合约地址 |
| `POP_ANCHOR_KEY` | 提交交易的私钥（缺省用 `ANVIL_KEY`） |

> **`ANVIL_KEY` 是 Anvil 默认账户 #0 的公开测试私钥**（`0xac09…ff80`，地址 `0xf39F…2266`），
> 仅用于本地 demo。私钥以命令行参数传给 `cast` —— 生产必须换 keystore/HSM（见 `../plan-p7.md`）。

---

## 4. 交叉核对：为什么这个 PASS 不是恒真

锚定的价值在于**两个独立记录源互相印证**：

```
本地账本 meta.on_chain.chain_ts  ==  链上 anchoredAt(digest)
本地账本 meta.on_chain.block    →   timestamp_of_block(block) == 链上 chain_ts
```

`verify_session.py --rpc` 对**每一张**证书执行上述核对，并统计
`chain_anchored 14/14 digests on chain 0x5fbd… (14 cross-checked)`。

**反例对照**（`scripts/anchor_e2e.sh` 第 5 步）：一个从未登记的摘要读回 `anchoredAt = 0`。
如果脚本改坏了、检查退化成恒真，这一步会把它抓出来。

链上锚定能证明什么、不能证明什么：

- ✅ 「该摘要**在某时刻已存在**」—— 且时间戳由链给出，不依赖证明者自述；
- ❌ **不**证明「证书内容为真」—— 那由签名 + `policy_hash` + SP1 证明承担（`03`/`05`）。

---

## 5. `verifier.py`：verifier-only 快路径判定

**背景（真实 bug）**：`pop-script --proof-out` 会为**所有**证明模式（含 `core`）写出
`<proof>.verify.json` 边车。如果快路径只看「边车存在」，就会对 core 证明也调 `pop-verify`，
结果以退出码 3 失败：`proof mode 'core' is not verifier-only verifiable`。

修复方式是把模式纳入判定：

```python
VERIFIER_ONLY_MODES = ("compressed", "groth16", "plonk")

def sidecar_path(proof) -> Path:              # <proof>.verify.json
def sidecar_proof_mode(sidecar) -> str | None # 读边车里的 proof_mode

def prefer_verifier_only(proof, pop_verify) -> bool:
    # 三个条件同时满足才走快路径：
    #   ① pop-verify 二进制存在
    #   ② <proof>.verify.json 边车存在
    #   ③ 边车里的 proof_mode ∈ {compressed, groth16, plonk}
```

**core 证明必须回落到 `pop-script --verify`**（它会从 ELF 重新 setup 推导 vkey，代价是构造
SP1 证明器状态 ~10 GB；这正是 `verifier-only` 想避免的）。`tests/test_verifier_only.py`
里有一条专门的反向用例 `test_core_sidecar_does_not_take_the_fast_path`。

### 5b. 绑定比对内核（`check_agreement`）

`verifier.py` 的另一半职责是给「多方比对」提供一个**防空洞**的公共内核：

```python
def _committed_field(proof_result, field) -> str | None   # outcome[field] 是 str 才返回
def committed_policy_hash(proof_result)      -> str | None
def committed_response_binding(proof_result) -> str | None

def check_agreement(sources, what) -> (bool, str)
def check_policy_binding(sources)   == check_agreement(sources, "policy_hash")
def check_response_binding(sources) == check_agreement(sources, "response_binding")
```

`sources` 是 `[(标签, 值或 None), …]` 的列表。判定规则是
**「至少两个来源非 None，且它们两两相等」**：

| 情况 | 结果 | 理由 |
|---|---|---|
| 只有 1 个来源 | **False**（`binding uncheckable`） | 单一来源是自己跟自己比，恒真 —— 这就是「空洞通过」 |
| 0 个来源 | **False** | 无从比对 |
| ≥2 个且全相等 | True | 独立性来自「来源互不派生」 |
| ≥2 个但有分歧 | False（`MISMATCH: …`） | 有一方在说谎/被篡改 |

缺失的来源会在详情里列为 `(absent: …)`，所以报告读起来能区分「比过了」和「没得比」。
`verify_cert.py` 的 `policy_hash` / `response_binding` 两张卡、`verify_session.py` 的
会话级与 zk 级绑定都走这个内核。来源标签见 `_SOURCE_LABELS`
（含 `"cert.challenge"` 与 `"response"`）。

---

## 6. 函数级 API（`anchor.py`）

| 函数/类 | 说明 |
|---|---|
| `digest_to_bytes32(digest)` / `bytes32_to_digest(word)` | 64-hex ⇄ 链上 `bytes32` 字面量（严格校验长度与字符） |
| `_entry_hash(entry)` | 剔除 `hash` 字段后的规范哈希 |
| `read_ledger(path)` / `append_anchor(path, digest, meta, ts)` | 逐行读写；`prev` 取上一条 `hash`，首条 `genesis` |
| `verify_ledger(path) -> (bool, str)` | 重算整条链 |
| `find_anchor(path, digest) -> dict?` | 查第一条匹配记录 |
| `AnchorBackend` | 抽象接口：`anchor(digest, meta)` / `get(digest)` |
| `FileLedgerBackend(path)` | 文件账本（`name="file"`，`status="appended"`） |
| `CastRpc(rpc_url, cast_bin=None, timeout=120)` | 上面 §3 的 cast 客户端 |
| `RpcAnchorBackend(rpc_url, contract, private_key=None, ledger_path=None, client=None, from_address=None)` | 链上后端（`client` 可注入，便于离线单测） |
| `load_artifact(path=None)` | 读 `contracts/Anchor.json` |
| `deploy_anchor_contract(rpc_url, private_key=None, client=None, artifact_path=None, from_address=None)` | 部署并返回部署信息 |
| `backend_from_env(ledger_path=None, rpc_url=None, contract=None, private_key=None, require=False)` | 后端选择 |
| `anchor_on_chain(digest, rpc_url=None, contract=None, private_key=None, ledger_path=None)` | 便捷入口；未配置抛 `NotImplementedError` |
| `verify_digest_on_chain(digest, rpc_url, contract, client=None)` | **只读**核对（`verify_session --rpc` 用） |
| `AnchorError` | 后端调用失败（cast 报错/超时/配置缺失） |
| 常量 | `GENESIS="genesis"`、`REPO`、`ARTIFACT`、`ANVIL_KEY`、`ENV_RPC/CONTRACT/KEY` |

---

## 7. 不变量与边界

1. **摘要格式**：`digest_to_bytes32` 要求恰好 64 个十六进制字符（可带 `0x`），否则 `ValueError`。
2. **账本是仅追加的**：`append_anchor` 只写不读改；任何「修改历史条目」的行为都会被 `verify_ledger` 检出。
3. **`get()` 的判空语义**：`chain_ts == 0` ⇒ 未登记（合约保证已登记条目的时间戳非 0）。
4. **上链失败不写本地**：`send_anchor` 抛错时 `anchor()` 直接向上抛，不会留下「本地有、链上没有」的条目。
5. **`on_chain` meta 只在 rpc 后端出现**：文件后端条目没有这个键，`verify_session` 的交叉核对也相应跳过。
6. **RPC 后端每次调用都是新进程**（`cast`），因此慢但无状态；`timeout=120s` 可调。
7. **合约 artifact 入库**：改动 `Anchor.sol` 后必须重新生成 `Anchor.json`，否则部署的还是旧字节码。

---

## 8. 测试对应

| 测试 | 覆盖 |
|---|---|
| `tests/test_anchor.py` | 账本读写、`verify_ledger`、篡改检出 |
| `tests/test_anchor_chain.py::TestArtifact` | `Anchor.json` 结构（abi/bytecode/函数名） |
| `tests/test_anchor_chain.py::TestDigestEncoding` | `digest ⇄ bytes32`（含非法输入） |
| `tests/test_anchor_chain.py::TestBackendSelection` | `backend_from_env` 的分支与 `require=True` |
| `tests/test_anchor_chain.py::TestRpcBackendOffline` | `FakeChain` 注入：幂等、竞态（`already anchored`）、ledger meta 回写 |
| `tests/test_anchor_chain.py::TestCastCommandLines` | **参数顺序**：`--rpc-url` 在 `--create` 之前、尾参在最后、`cast wallet` 无 `--rpc-url`、`call_uint` 的后缀解析 |
| `tests/test_anchor_chain.py::TestAnvilEndToEnd` | 真 anvil（端口 8577）；**没有 foundry 时自动跳过** |
| `tests/test_verifier_only.py` | `prefer_verifier_only` 的三条件与 core 回落 |
| `scripts/anchor_e2e.sh` | 一键端到端：起节点 → 部署 → 14 张证书上链 → `--rpc` 核对 + 反例对照 |

CI（`.github/workflows/ci.yml`）单独跑 `tests.test_anchor` + `tests.test_anchor_chain`（离线 fake-RPC；
无 foundry 时 anvil e2e 自动跳过），因此 CI 不需要装 foundry。

---

## 9. 扩展指引

- **接到自备节点/测试网**：`python3 scripts/deploy_anchor.py --rpc <URL>` 打印
  `POP_ANCHOR_RPC` / `POP_ANCHOR_CONTRACT`，之后 `issue_cert.py` / `demo_e2e.py` 加 `--rpc/--contract` 即可。
- **换生产签名 + 上链密钥**：`CastRpc` 目前用 `--private-key` 传明文；
  可扩展为 `--account <keystore>` 或硬件签名（改动集中在 `CastRpc._run` 的构造处）。
- **换锚定后端**（如把摘要写进透明日志/CT 风格 Merkle 树）：实现 `AnchorBackend` 的
  `anchor` / `get`，然后让 `backend_from_env` 认识新的配置项。**保持返回字段名一致**，
  这样 `verify_session` 的交叉核对逻辑无需改动。
- **合约升级**：`Anchor.sol` 有意保持最小（无 owner、无升级、无费用）。要加撤销/多签，
  需要同时更新 `contracts/Anchor.json` 与 `tests/test_anchor_chain.py::TestArtifact` 的期望函数集。

---

**相关**：被锚定的摘要怎么来的 → [`03-certificate.md`](03-certificate.md)；
一键端到端脚本怎么用 → [`07-cli-scripts.md`](07-cli-scripts.md)；
安全论证（记录完整性）→ [`../security-model.md`](../security-model.md)。
