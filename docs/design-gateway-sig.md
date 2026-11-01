# 网关验签：降低网关信任的设计方案（A12）

> **状态**：2026-11-01，A12 设计稿。**只设计**：本文不改 `circuits/`、不改
> `policydsl/`、不重建 vkey、不改论文。分支 `bhv/a12-gateway`，基线 `4fe5c41`。
>
> 相关材料：[`bench/results/gateway_sig.md`](../bench/results/gateway_sig.md)
> （实测成本与 blocked 状态）、[`security-model.md`](security-model.md) §5.3/§5.4
> （截尾与 A4）、[`blockers/B1.md`](blockers/B1.md)（B1-circuit-ed25519）、
> [`blockers/Core.md`](blockers/Core.md)（guest 改动 ⇒ vkey 变化的先例）、
> [`policydsl/evidence/trace.py`](../policydsl/evidence/trace.py)、
> [`circuits/types/src/lib.rs`](../circuits/types/src/lib.rs)、
> [`scripts/verify/verify_cert.py`](../scripts/verify/verify_cert.py)、
> [`docs/design-policy-pp.md`](design-policy-pp.md)。

## 1. 现状与缺口

### 1.1 现在的四层各自保证什么

| 层 | 实现 | 保证 | 信任根 / 失败模式 |
|---|---|---|---|
| **电路内** | `pop_types::verify_receipt_chain` | 链**结构**自洽：`seq` 连续、`prev` 逐条咬合、每条摘要由内容重算 | 信任 vkey 与电路实现；**不**看签名 |
| **链下** | `trace.verify_chain` | 每条回执由 `keyid` 对应的 Ed25519 钥签过；非白名单方案前缀结构性拒绝 | **网关私钥**；密钥泄露即可伪造 |
| **公开值** | `ProofOutput::trace_root` | 证明绑定的是哪条链（链尾摘要） | 网关给的链；证明者不能换链而不换 root |
| **链下 + 证书** | `ToolSeal{count, trace_root, ts, keyid, sig}`，`verify_cert.py` 3d | 「网关说这条链到此为止」——截尾检测点 | **仍是网关签名**；网关可为截断链直接签 seal |

`ToolReceipt.sig` **刻意不在电路视图里**（`circuits/types/src/lib.rs` 的注释已写明：
zkVM 内验签代价高）。因此：

- 电路内验证的是「链自身自洽」，不是「回执可信」；
- 「回执可信」的根源是链下 Ed25519 验签，验证方必须持有网关公钥；
- 「链没有截尾」的根源是 `ToolSeal`，它也是网关签名。

### 1.2 缺口：A4 是显式信任点，不是密码学结论

`security-model.md` §5.4 已把「网关作恶」列为**模型最弱的一环**。具体拆开：

1. **执行真实性（A4）**：网关可以签一条与真实执行不符的回执（换
   `args`、换 `result_digest`、甚至整条伪造），链结构与签名都自洽。
   本文的所有方案都**不自动**消除这一点；能消除它的只有「网关被信任」之外
   的独立证据（TEE / zkTLS，且各有新假设）。
2. **单点密钥**：一把网关钥泄露即失守；2-of-3 原型把「1 把」改成「任意 2 把」，
   但仍是信任假设，不是证明。
3. **公钥分发**：验证方现在靠 `--gateway-key` 从带外拿公钥；没有经过认证的
   gateway roster。没有公钥时 3d 记 PASS +「截尾不可排除」（skipped）；
   给了公钥却没有 `trace_seal` 则 FAIL。这个不对称必须写进论文。
4. **密钥托管**：当前私钥是文件（口令可选），HSM/KMS 未落地（A7）。
5. **时间**：`ts` 是网关自报，没有可信时间源。
6. **覆盖**：提供方可以干脆不出证书；这一点不在本文范围，见
   [`paper/tdsc-paper.tex`](../paper/tdsc-paper.tex) §7.4 的 coverage 讨论。

### 1.3 为什么「电路内验签」不是「把 0.094 ms 搬进电路」

B1 的结论必须原样保留：

- `circuits/` 里**没有** Ed25519 验签代码，而且按设计就是这样；
- 要量它必须新增 guest 或改电路，B1 的文件所有权不允许；
- 本机 14.6 GiB / SP1 `core` 约 10.15 GiB 地板，且开工时没有
  `/tmp/pop-proof.lock`；
- 因此 `bench/results/gateway_sig.json` 的 `circuit` 字段是
  `status="blocked"`，`cycles` / `prove_time_s` / `peak_mem_mb` 全为 `null`。
  **不是 0，也不得由链下 0.094 ms 外推。**

本文给出的是**设计、成本驱动因素与测量计划**，不是电路内周期数。

### 1.4 任何方案都必须守住的不变量

这些不变量决定了「能不能只改证书层」还是「必须动 vkey」：

| 不变量 | 现状 | 对方案的约束 |
|---|---|---|
| 规范字节 | `canonical_receipt_bytes` = `pop-trace-v1` + 长度前缀 + 固定字段序；`sig` **不**参与摘要 | 签名方案可以换，但**不能改这段字节**；否则链摘要、`prev`、`trace_root` 全变 |
| 域分隔 | 回执 `pop-trace-v1`；seal `pop-trace-seal-v1` | 新签名方案/新用途必须用新域，防跨用途重放 |
| `keyid` | 在规范字节内，含方案前缀（如 `ed25519:`） | 换方案必须换前缀；验签方按前缀分派，未知前缀拒绝 |
| 链尾 | `trace_root` = 最后一条回执摘要，进公开值 | 不能在链上加「签名容器」改变摘要；签名只能是旁路 |
| seal 位置 | 证书载荷顶层 `trace_seal`，**不在** `outcome` 里 | 电路没有 seal；若要把 seal 纳入证明，必须新增公开值并改 outcome schema |
| vkey | 任何 guest 代码变更 ⇒ vkey 变化（`blockers/Core.md` 的 NFA 修复先例） | 电路内方案一律要重建、重出证、重标 binary/vkey；旧结果不能与新 vkey 同表 |
| outcome 严格相等 | `verify_cert.py` 用 `decoded == payload["outcome"]` 逐字段比 | 新增公开值 ⇒ 所有旧证书/旧工件对不上，必须版本化或 fail closed |

## 2. 评价口径

本文用六个维度比较方案，避免把「便宜」与「更可信」混为一谈：

1. **证明什么**：密码学上多出哪条可检验命题。
2. **不证明什么**：必须写进论文的边界。
3. **降低了哪个信任点**：从「必须信 X」变成「必须信 X′」，X′ 是否更小。
4. **新假设**：roster、notary、TEE、多网关视图一致性、新的密钥托管。
5. **证明成本**：周期 / 证明时间 / 峰值内存。**只有实测数才算数**；没有数就写
   `unmeasured` / `blocked`。
6. **兼容性**：vkey、证书 schema、密钥格式、验证方依赖、旧证书是否还能验。

## 3. 方案对比总表

| # | 方案 | 证明什么 | 不证明什么 | vkey / 产物影响 | 成本 | 状态 |
|---|---|---|---|---|---|---|
| A | SP1 电路内 Ed25519 | 回执/seal 的签名由公开值承诺的 roster 中某钥签出；链结构；可选的 seal count/root | 网关诚实、执行真实性、roster 真实性（除非另签）、密钥托管、时间、覆盖 | **guest 变 ⇒ vkey 变**；新增公开值 ⇒ outcome/证书 schema 变；旧证明需重出 | **blocked，未量**；驱动因素见 §4.5 | 设计 |
| B | STARK-friendly 签名 | 新方案下的签名持有；验证主要在原生域/哈希中完成 | 同样是网关诚实；新方案的安全性与成熟度；密钥管理 | guest 变 ⇒ vkey 变；`keyid` 方案前缀、证书、密钥格式全变 | **unmeasured**；大签名/新方案风险 | 研究 |
| C | 2-of-3 / 阈值网关 | ≥ t 个互异密钥签了同一段规范字节 | 网关合谋（t-of-n 仍可作恶）、视图一致性、roster 真实性、执行真实性 | **不改电路 ⇒ 不改 vkey**；`trace_seal`/证书 envelope 与 3d 验证器变 | 原型已实测；整链端到端未测 | 原型 → 可产品化 |
| D | zkTLS / 外部 attestation | 某个外部 TLS 服务器的响应字节（可绑定 host/请求/nonce） | 本地工具、调用完整性、网关诚实、服务器业务逻辑、notary 信任 | 链下验证 ⇒ 不改 vkey；证书新增 attestation 字段与验证器依赖 | **unmeasured**；外部依赖 | 研究 |
| E | TEE / HSM 网关（补充） | 密钥操作发生在经远程认证的环境/模块中 | 代码正确性、执行真实性、输入真实性；侧信道、厂商信任 | 不改 vkey；运营与证书 attestation 字段变 | 运营成本；未量 | 补充 |

> **读法**：A 与 B 把「验签」搬进证明，但**都不消除「信网关钥」**；C 降低单点
> 信任但引入多网关一致性；D 只对外部 HTTP 工具有意义；E 是部署加固，不是
> 密码学证明。没有哪一项能同时做到「零新假设 + 零成本 + 消除 A4」。

## 4. 方案 A：SP1 电路内 Ed25519

### 4.1 设计要点

**两个作用域，必须分开选：**

- **A1：逐回执验签**。guest 对每条 `ToolReceipt` 验 Ed25519。它证明「这条链
  的每一条回执都由 roster 中的钥签过」，但**不解决截尾**——截断后的前缀仍是
  一条逐条签名有效的真链（§10.2）。
- **A2：只验 `ToolSeal`**。guest 只验会话末端那一条签名，把
  `{count, trace_root}` 纳入公开值。它直接补「截尾保证依赖网关签名」这一步，
  每条会话只多验 1 条签名，是**最小原型**的首选。

**关键设计（两个作用域都适用）：**

1. **公钥必须进公开值，不能只做私有输入**。若 guest 只把网关公钥当私有输入，
   证明者可以塞自己的钥，证明「我签的」——没有意义。做法：公开值加
   `gateway_roster_hash`（或 `gateway_keys_hash`），验证方把它与自己信任的
   roster 比对。roster 本身可用 P-PP 式的权威签名清单（§10.4）。
2. **`keyid` 必须映射到 roster 条目**。`keyid` 已在规范字节内，验签方按
   `keyid` 取公钥；未知 `keyid`、未知方案前缀一律拒绝。
3. **用严格验签**。Ed25519 实现应使用 `verify_strict` 一类口径，拒绝非规范
   `S`、小阶公钥/点的可延展编码；否则同一签名的变体可能被重复利用。
4. **seal 要显式进公开值**。seal 现在只在证书载荷顶层，电路看不见。若 A2 要
   证明「seal 已被验」，公开值至少要加 `seal_count`、`seal_root`（以及
   `seal_present` 或版本位）。**可选的电路检查不是检查**：证明者可以省略
   seal 输入；验证方必须能看出「这次证明到底有没有验 seal」，并在要求时
   fail closed。
5. **A2 可以做成独立 companion guest**。若不想动 `pop-program` 的 vkey，可新增
   一个独立 guest（只验 seal），给它自己的 vkey，证书附一条 companion proof，
   验证方合取两者（与 `delegated` 的陪伴证明模式同构）。代价是多一次证明与
   一个组合假设；收益是 policy vkey 不动。两种做法都合法，但必须在论文里
   写清「哪块电路承诺了什么」。

### 4.2 SP1 6.7.0 的 precompile 事实（决定成本）

本仓 pin 的是 `sp1-zkvm = "6.7.0"`（`circuits/program/Cargo.toml`）。直接读
crate 源码可确认：

- 有 **`syscall_ed_add`** 与 **`syscall_ed_decompress`** 两个 Ed25519 点运算
  syscall；
- **没有**一体化的 `ed25519_verify` syscall；
- 哈希侧只有 **SHA-256** 的 `sha_compress` / `sha_extend` 与 Keccak 置换；
  **没有 SHA-512 compress precompile**；
- guest 当前只依赖 `sp1-zkvm`、`pop-types`、`sha2`，**没有** `ed25519-dalek`
  或 `curve25519-dalek`。

因此 A 的现实成本驱动是：

1. **SHA-512 软件实现**：Ed25519 每条签名要算一次 SHA-512；没有 precompile，
   这部分在 RISC-V 里跑。
2. **标量乘**：即使点加/解压走 syscall，一次标量乘仍是大量 `ED_ADD` 调用；
   syscall 自身有开销。
3. **每条回执线性**：A1 的成本随回执数线性增长；A2 每条会话只多一次。
4. **证明侧放大**：更多指令 ⇒ 更多周期 ⇒ 证明时间/内存上升；具体倍数**未量**。

**相邻选项**：SP1 6.7.0 对 secp256k1 也有 `secp256k1_add/double/decompress`
点运算 syscall，且 SHA-256 有 precompile。把网关签名换成 secp256k1
（ECDSA 或 Schnorr）**可能**比 Ed25519 更贴合现有 precompile，但它不是
STARK-friendly，且引入 ECDSA 的 nonce/可延展性与新的密钥格式；**不应仅为省成本
换曲线**，除非有独立的工程理由。

### 4.3 证明什么 / 不证明什么

**证明（A1）**：对每条回执，存在 roster 中某钥对
`canonical_receipt_bytes(receipt)` 的有效签名；链结构自洽；`trace_root` 是链尾。
**证明（A2，额外）**：存在 roster 中某钥对 `canonical_seal_bytes(seal)` 的有效
签名，且 `seal.count` / `seal.trace_root` 与证明承诺的链一致。

**不证明**：

- 网关**诚实**：它仍可签与真实执行不符的回执（A4）；
- roster 本身是真的（除非 roster 由权威签名并在公开值里承诺）；
- 密钥没有被盗用/托管正确；
- 时间戳真实；
- 调用**完整**：A1 不解决截尾；A2 只把「网关说链到此为止」变成「网关签名被
  电路验过」，网关仍可为截断链签 seal；
- 网关之间没有合谋。

**它实际买到的是**：验证方不必自己拿到整条链、不必在链下逐条验签，就能确认
「这份证明覆盖的链的每条回执/末端 seal 由 roster 内某钥签过」；信任点从
「验证方本地验签代码 + 网关钥」变成「电路 vkey + roster + 网关钥」。
**网关钥没有被移除。**

### 4.4 vkey / 产物影响

| 产物 | 影响 |
|---|---|
| guest ELF | 变；新增验签代码/依赖 |
| policy vkey | 若改 `pop-program`：**变**；旧证明、旧证书、旧结果表全部不能混用 |
| 独立 companion guest | 新增一个 vkey；policy vkey 可不变，但验证方要合取两条证明 |
| 公开值 / `outcome` | 新增 `gateway_roster_hash`、`seal_count`、`seal_root` 等 ⇒ outcome schema 变；`decoded == payload["outcome"]` 对所有旧证书失效 |
| 证书 | 需版本化；旧证书在新验证器下应 fail closed 或明确标「未覆盖这项」 |
| 论文数字 | 任何新证明成本必须标 binary sha256 / vkey；不得与旧 vkey 同表（`Core.md` 先例） |

### 4.5 预计成本

**状态：`blocked`，未量。** 引用 [`blockers/B1.md`](blockers/B1.md)：
`cycles` / `prove_time_s` / `peak_mem_mb` 全为 `null`；不得把链下
0.094 / 0.844 / 10.165 ms 当作电路内成本。

**测量计划（解除 blocker 后）**：

1. 在 `circuits/` owner 的授权下，新增最小 guest（A2）或给现有 program 加开关；
2. 用独立 `CARGO_TARGET_DIR`，避免与其它 agent 抢 target 锁；
3. 持 `flock /tmp/pop-proof.lock` 再跑；
4. 记录：执行周期、证明墙钟、峰值 RSS、证明大小、验证时间；
5. 至少跑 1 / 10 / 100 回执三档（A1）与 1 条 seal（A2），与当前 baseline
   证明同机同 binary 对比；
6. 所有结果标 host、binary sha256、vkey、commit。

### 4.6 实现步骤

1. **选作用域**：先 A2（seal-only），后 A1（逐回执）。
2. **定义 roster**：`{keyid: pubkey}` 的规范编码 + 哈希；用权威签名清单
   （P-PP 模式）或部署配置固定。
3. **扩展请求**：`ProofRequest` 增加 `seal` / `receipt_sigs` / `roster` 私有输入
   （注意 `deny_unknown_fields`，旧向量会解析失败，必须版本化）。
4. **扩展公开值**：`gateway_roster_hash`、`seal_count`、`seal_root`、
   `seal_present`（或等价版本位）。
5. **guest 验签**：按 `keyid` 取钥、严格验签、域分隔、拒绝未知前缀；seal 的
   count/root 与 `trace_root` 交叉核对。
6. **验证器**：核对 roster 哈希、seal 字段、outcome 逐字段相等；缺 seal 而部署
   要求时 fail closed。
7. **兼容策略**：旧证书标「未覆盖」或拒绝；不得静默把「没验」当「验过」。
8. **重建/重出证**：更新 vkey、binary、期望 vkey；重跑受影响的证书与论文表。

### 4.7 测试计划

- **正向**：1/10/100 条回执逐条有效；seal 有效；空链 + 有效 seal。
- **负向**：改 `args`/`seq`/`prev`/`keyid` 后签名失效；非 roster 钥；缺签名；
  跨回执重放签名（域/seq 绑定）；seal count/root 不符；seal 签名错；roster
  哈希不符；未知方案前缀；非规范 `S`/小阶点。
- **省略攻击**：不提供 seal 输入时，证明不得声称「已验 seal」；验证器必须能
  区分「未提供」与「验过且通过」。
- **交叉验证**：Python 链下验签与 guest 对同一向量给出相同结论（参考
  `tests/test_trace.py` 的逐字节核对）。
- **测量**：按 §4.5 的锁与标签跑；结果写回 `bench/results/gateway_sig.*` 的
  `circuit` 字段（由 bench owner 执行，本文不改）。

## 5. 方案 B：STARK-friendly 签名

### 5.1 候选与硬约束

「在 BabyBear 上做 Schnorr/EdDSA」不是一句话能落地的事。BabyBear 的
`p = 2^31 - 2^27 + 1`；素域乘法群的阶 `p-1 = 2^27 · 15` 只有约 2^31，而且
**平滑**（Pohlig–Hellman 比 2^15.5 的通用界还快），不能直接用。要在
BabyBear 上得到可接受的 DLP 安全，需要扩域 `GF(p^k)`：

- `k = 4` 时群阶约 2^124，通用 Pollard-rho 约 2^62，**低于 128-bit 目标**；
- `k = 9` 时约 2^279，通用攻击约 2^139，才谈得上 128-bit 级别，但算术是 9 个
  BabyBear  limbs，**不再“原生”**，成本优势需要实测。

因此更现实的 STARK-friendly 候选是：

1. **哈希型签名**（Winternitz / XMSS / SPHINCS+ 类）：验签主要是哈希调用，可
   复用 SHA-256 precompile 或原生哈希；缺点是签名显著大于 64 B、OTS 需要一次性
   状态、SPHINCS+ 类验签哈希次数多。
2. **扩域上的 Schnorr/EdDSA**：如上，先做安全参数评审；不要用 `p-1` 或 `p^4`
   草率上线。
3. **格签名（ML-DSA）**：标准化成熟，但 `q = 8380417` 与 BabyBear 不同，
   NTT/采样在 guest 里仍需非原生算术；签名/公钥为 KB 级；成本未量。
4. **多变量/编码型**：研究阶段，密钥/签名大，安全分析复杂；不建议作为近期路线。

### 5.2 证明什么 / 不证明什么

**证明**：在新方案下，签名由 roster 中某钥对规范字节签出；验证在原生域/哈希中
完成（若设计成立）。

**不证明**：网关诚实、执行真实性、roster 真实性、密钥托管、时间、覆盖；也
**不证明新方案本身达到 128-bit**——那是安全参数评审的结论，不是实现的副产物。

### 5.3 vkey / 产物影响

- guest 变 ⇒ **vkey 变**；新方案通常还改 `keyid` 前缀、签名/公钥编码、证书
  schema、密钥生成与托管流程；旧钥/旧证书需要双路径或迁移期。
- 若签名体积变大，证书/回执/链的字节数上升；`ToolSeal` 的 345 B 基线不再成立。
- 论文必须同时标新 vkey、新签名方案、新参数；不能与 Ed25519 结果同表。

### 5.4 预计成本

**未量。** 成本驱动：哈希调用次数、签名/公钥体积、guest 内非原生算术量、密钥
状态管理。必须先有参考实现与 guest 原型，才有资格谈“比 Ed25519 便宜”。
在拿到数字前，**不得**声称 STARK-friendly 一定更省。

### 5.5 实现步骤

1. 选一个候选（建议先做哈希型）并写安全参数说明；
2. Python 参考实现 + 测试向量；
3. Rust 参考实现，与 Python 逐字节对拍；
4. 定义 `keyid` 前缀、签名/公钥编码、证书字段；
5. 最小 guest 验签原型；
6. 测量周期/时间/内存/签名体积；
7. 安全评审与迁移方案；不通过则停止，不进入生产。

### 5.6 测试计划

- 参考向量正/负例；篡改消息、错误公钥、错误参数、畸形编码；
- 方案混淆：`ed25519:` 钥不能用于新方案，反之亦然；
- 一次性密钥重用（若 OTS）必须被检出/拒绝；
- 签名/公钥体积上限与拒绝路径；
- 与 Ed25519 路径的域分隔与 keyid 分派；
- 性能与体积测量（标 vkey/binary）。

## 6. 方案 C：2-of-3 / 阈值网关

### 6.1 已有原型（measured）

[`bench/bench_gateway_sig.py`](../bench/bench_gateway_sig.py) 已实现**宿主侧**
多签拼接原型：

- 三把 Ed25519 钥各签同一段规范字节，证书带 `signatures[]`；
- 验证方要求「至少 t 个**互异** `keyid` 的有效签名」；
- 机器校验：任意 2 个互异签名通过；只有 1 个拒绝；同一 `keyid` 的两条签名
  不算两个；
- 实测（[`gateway_sig.md`](../bench/results/gateway_sig.md) 表 c）：签名
  0.173 ms、合并 0.001 ms、验签 0.508 ms、证书 981 B（只带 2 个签名时 759 B，
  n=300）。

**边界**：这是**多签拼接**，不是紧凑阈值签名；证书大小随签名数线性增长；
**没有**接入 `trace.py`、没有改证书格式、没有改验证脚本；也**没有**解决
多网关视图一致性。

### 6.2 设计选择：阈值加在哪一层

| 选择 | 做法 | 买到什么 | 代价 |
|---|---|---|---|
| **C1：只阈值化 seal** | 会话末端 `ToolSeal` 由 t 个网关共同签；回执仍单签 | 单钥泄露不足以伪造「链到此为止」；证书只多 1 组签名 | 回执级伪造仍可能；共签者必须核对链 |
| **C2：逐回执 + seal 都阈值化** | 每条回执 t 签 | 单钥不能伪造任何回执 | 签名/体积/验签约 3 倍；链变长；工具网关吞吐下降 |
| **C3：紧凑阈值（BLS 类）** | 聚合签名，证书短 | 体积小 | 需要 DKG、配对/聚合验证、新假设；本仓未实现 |

**建议先做 C1**：它直接对准截尾这一最明确的缺口，成本可控，且不动电路。
C2 是“更强但更贵”的选项，等 C1 的运维与视图一致性跑通再评估。

**共签者到底承诺什么**必须写死，二选一（或分开标）：

- **视图承诺**：「我在 `ts` 看到一条长度为 `count`、链尾为 `root` 的链」；
- **执行承诺**：「我参与/见证了对这条回执对应的工具调用」。

前者便宜，但**不证明执行真实**；后者更强，但要求共签者真的参与执行或持有
独立证据。把两者混写，会把「多网关看到同一条链」误读成「多网关证明了执行」。

### 6.3 证明什么 / 不证明什么

**证明**：同一段规范字节上有 ≥ t 个互异、有效的网关签名。

**不证明**：

- **合谋**：任意 t 个网关仍可一起作恶；2-of-3 只是把「1 把钥」改成「2 把钥」；
- **视图一致性**：若网关看到不同链，各自签不同 root，诚实验证方拿不到 quorum；
  但若它们串通/被同一运营方控制，仍可为截断链签 seal；
- **roster 真实性**：谁规定这三把钥是“独立网关”？需要签名 roster 与运营分离；
- **执行真实性**（A4）：共签者若只做视图承诺，仍不知道工具真的执行了什么；
- **长期 split-view**：跨时间的“不同验证者看到不同链”需要透明日志的一致性
  证明与 gossip，本仓未实现（`B1-split-view`）。

### 6.4 vkey / 产物影响

- **不改 guest ⇒ 不改 vkey**：回执/seal 的签名仍在链下，电路仍只验结构。
- 证书/`trace_seal` schema 变：单 `sig` → `signatures[]`（或新增
  `trace_seal_sigs`），需要版本号；`verify_cert.py` 3d 改为阈值验证。
- keyring / roster 变：验证方需要 t 个公钥与「哪些算独立网关」的配置。
- 旧单签证书：新验证器应能按 schema 版本降级验证，或明确标「不满足阈值」。

### 6.5 预计成本

- 原型已测（见 §6.1）；**整链端到端未测**：100 条回执 × 3 个签名的签名/验签/
  证书体积没有一条实测曲线，不能把单条 0.508 ms × 100 直接当结果（还要加
  网络、合并、存储）。
- 预期随回执数线性、随签名数线性；这是**结构性预期**，不是测量结论。
- 验证方每条证书多验 t 个签名；证书体积增加；网关侧多 t-1 次签名与协调。

### 6.6 实现步骤

1. 选 C1 或 C2，写清共签者承诺语义；
2. 定义 envelope schema（版本、`signatures[]`、`keyid`、域分隔）；
3. 用 P-PP 模式签发 **gateway roster**：权威签 `{gateway_keyid → pubkey,
   operator, valid_from/through}`，验证方核对 roster 签名与吊销；
4. 改 `ToolSeal` 的序列化/反序列化与 `verify_cert.py` 3d：要求 t 个互异
   `keyid`、同一规范字节、count/root 一致；
5. 共签者策略：签名前核对本地链的 `count`/`root`；不一致拒签并告警；
6. 运维：密钥轮换、吊销、独立运营方、审计日志；
7. 若要跨时间防 split-view，接透明日志一致性证明/gossip（另立任务）。

### 6.7 测试计划

- 复用原型的三条阈值语义测试（2 个通过 / 1 个拒绝 / 同 keyid 不算两个）；
- 证书级：3 签、2 签、1 签、重复 keyid、未知 keyid、错钥、过期/吊销 roster；
- 截尾：原 seal + 截断链拒绝；伪造 seal 拒绝；2 个网关对**不同 root** 签名时
  无 quorum；
- 视图一致性：模拟两条分叉链，要求共签者拒签不一致 root；记录「哪些网关看到
  哪条链」；
- 重放：旧 seal 配新证书/nonce 必须拒绝；
- 合谋负对照：明确记录「t 个网关合谋可通过」——这是 residual trust，不是 bug。

## 7. 方案 D：zkTLS / 外部 attestation

### 7.1 适用范围

zkTLS 只对**外部 HTTP(S) 工具**有意义：它能把「某个服务器在某个 TLS 会话里返回
了这些字节」做成可验证的 attestation。对本地文件系统、shell、代码执行等
**没有 TLS 会话**的工具，它不适用；那些工具需要 TEE/进程 attestation 或继续
信任网关。

### 7.2 设计要点

1. **attestation envelope**：`{system, host, request_hash, response_hash,
   transcript_hash/commitment, notary_keyid, nonce, ts, proof}`；
2. **绑定**：`response_hash` 必须等于回执的 `result_digest`；`nonce` 必须与
   证书 challenge 绑定；`request_hash` 与回执的 `tool`/`args` 规范字节绑定；
3. **谁做 TLS 客户端**：
   - 网关做 TLS 客户端：它直接观察响应，可自己产出 attestation；若只签名而不
     附 attestation，第三方仍只信网关；
   - agent 自己做 TLS 客户端：attestation 由 agent 生成，**网关必须先验
     attestation 再签回执**，否则「有 attestation」不等于「网关确认过」，
     网关签名也没有覆盖这次 TLS 观察；
4. **验证位置**：优先链下验证（不改 vkey）；若放进电路，需要 TLS transcript
   解析 + 外部证明系统验证，guest 很大、vkey 变、且引入跨系统假设。

### 7.3 证明什么 / 不证明什么

**证明**：存在一个与指定 host 的 TLS 会话，其响应字节哈希等于 `response_hash`；
在 nonce 绑定下，该响应是本次挑战之后/之内的（取决于构造）。

**不证明**：

- 本地工具执行；
- 调用**完整性**：agent/网关可以选择只 attest 有利的调用，隐藏其他调用；
- 网关诚实：网关仍可选择哪些会话进证书；
- 服务器业务逻辑正确、结果内容合规；
- notary/MPC 不串谋（取决于 zkTLS 构造）；
- 长期密钥/证书吊销、时间真实性（依赖 PKI/时间假设）。

### 7.4 vkey / 产物影响

- 链下验证：**不改 vkey**；证书新增 `attestation` 字段，验证器新增依赖与
  失败路径；旧证书缺字段时按策略 fail closed 或标「未覆盖」。
- 电路内验证：guest 变 ⇒ **vkey 变**；证明成本/体积未量；还可能要求把外部
  证明系统接进 SP1（组合假设）。
- 隐私：TLS transcript/请求响应可能含敏感内容；attestation 的披露范围要单独
  设计，不能默认全公开。

### 7.5 预计成本

**未量。** 成本驱动：zkTLS 证明生成/验证时间、proof 体积、网络往返、notary
可用性、证书体积、验证方依赖。没有本仓测量，不得给数字。

### 7.6 实现步骤与测试

**步骤**：工具分类（外部 HTTP / 本地）→ 选 zkTLS 栈 → 定义 envelope 与绑定 →
网关验 attestation 后签回执 → 验证器链下核对 → 策略声明「哪些工具需要
attestation」→ 文档化信任假设。

**测试**：有效 attestation；错 host；改 response；重放旧 attestation 配新
nonce；attestation 绑到另一条回执；缺 attestation 而策略要求（fail closed）；
本地工具被要求 attestation（应判不适用/拒绝，不得假装通过）；隐私 canary。

## 8. 方案 E（补充）：TEE / HSM 网关

### 8.1 设计

- 网关私钥放 HSM/KMS，或网关进程跑在 TEE（SGX/TDX/SEV）中；
- 远程认证（quote/measurement）绑定「哪段代码在什么环境里持有这把钥」；
- 回执/seal 由该环境签名；证书可附 attestation（或验证方从网关服务获取）；
- 验证方核对 measurement/roster/吊销。

### 8.2 证明什么 / 不证明什么

**证明**：签名操作发生在一个经认证的环境/模块中，密钥未以明文暴露给普通主机
（取决于威胁模型）。

**不证明**：代码逻辑正确、执行结果真实、输入未被篡改、侧信道安全、硬件厂商
可信、吊销/回滚已处理。它是**部署加固**，不是 A4 的密码学解。

### 8.3 vkey / 产物影响

不改 vkey；改密钥托管、证书 attestation 字段、运维与验证器依赖。成本是运营
成本，未在本仓测量。

## 9. 推荐路线

### 9.1 短期（本轮投稿 / 不改 vkey）

**结论：保留链下 Ed25519 验签，阈值网关作为可选部署形态，论文明确 residual
trust。** 具体：

1. **不改电路、不重建 vkey**。`ToolReceipt.sig` 继续留在电路视图外；电路继续
   只验链结构；`trace_root` 继续进公开值。
2. **保留 `ToolSeal` + `--gateway-key` 的现有语义**。没有网关公钥时 3d 记
   PASS +「截尾不可排除」；给了公钥却没有 seal 则 FAIL——这个不对称要在论文里
   写清。
3. **阈值网关作为部署选项，而不是论文的“已解决”**。用已测的 2-of-3 拼接原型
   做 C1（seal-only）；要求 t 个互异 `keyid`、同一规范字节、count/root 一致；
   用 P-PP 式签名 roster 解决「这三把钥是谁」；明确「任意 t 个网关合谋仍可
   作恶」。
4. **密钥托管**：生产部署用 HSM/KMS（A7）；没有就如实写文件私钥。
5. **论文 §7.5**：用不超过 ~100 词的增量写「信任根仍含网关钥；阈值降低单点
   但不消除合谋/视图一致性；电路内验签 blocked、无数字」。不新增表格。
6. **不做**：不在本轮改 guest、不新增公开值、不把链下 0.094 ms 写成电路内成本。

### 9.2 中期（等 X1/vkey 排期后）

按顺序，**每一步都有停止条件**：

1. **最小 guest 原型（A2：只验 seal）**。用 SP1 6.7.0 的 `ED_ADD` /
   `ED_DECOMPRESS` + 软件 SHA-512；公开 `seal_count`/`seal_root`/
   `gateway_roster_hash`；在 `flock /tmp/pop-proof.lock` 下量 1 条 seal 的
   周期/时间/内存。若成本超出预先约定的预算（相对当前证明 baseline），**停止**，
   保留链下方案。
2. **若 A2 可接受，再评估 A1（逐回执）**。A1 的成本随回执数线性；只有 A1 才能
   让验证方不必自己拿整条链验签，但它**仍不解决截尾**。
3. **若 Ed25519 成本不可接受，转 STARK-friendly 研究**（优先哈希型）。先做参考
   实现、安全参数评审、体积/成本测量；不通过就不进生产。**不要**直接上
   BabyBear `p-1`/`p^4` 的 Schnorr/EdDSA。
4. **阈值网关与透明日志并行**（证书层，不动 vkey）：C1 → 视图一致性 → 一致性
   证明/gossip（`B1-split-view` 的解除条件）。
5. **zkTLS 只对确定的外部 HTTP 工具做试点**，不作为本地工具或通用执行真实性的
   答案。

### 9.3 取舍原则

> **不要为了消除一个信任点，引入更大的证明成本或新的、更弱的信任假设。**

| 方案 | 消除/降低了什么 | 新增什么 | 什么时候值得 |
|---|---|---|---|
| A（电路内 Ed25519） | 验证方对回执/seal 的链下验签依赖；把「验签」纳入 vkey | vkey 重建、证明成本（未量）、公开值/schema 变更 | 实测成本可接受，且确实需要「无链验签」 |
| B（STARK-friendly） | 可能降低验签的证明成本 | 新方案安全性、新密钥/格式、迁移风险 | 有参考实现 + 安全评审 + 实测优势 |
| C（阈值） | 单钥泄露即失守 | t-of-n 合谋、视图一致性、roster、运营复杂度 | 有独立运营方与签名 roster；接受 residual trust |
| D（zkTLS） | 外部 HTTP 响应的来源真实性 | notary/PKI/时间假设、外部依赖、隐私面 | 工具确实是外部 HTTP，且策略需要来源证明 |
| E（TEE/HSM） | 私钥明文暴露/托管风险 | 硬件/厂商信任、侧信道、运营 | 生产密钥托管，而不是替代 A4 |

**决策门（全部满足才推进电路内方案）**：

1. 有锁、有独立 target、有机器内存；
2. 实测周期/时间/内存，且相对 baseline 在预算内；
3. 没有新增比「信网关钥」更弱的假设；
4. roster/密钥托管/吊销可运维；
5. outcome/证书 schema 版本化，旧证书 fail closed 或明确降级；
6. vkey/binary 重标，论文结果不分表混用。

### 9.4 明确不要做的事

- **不要**把「链下 0.094 ms」写成「电路内只贵一点」；B1 是 blocked，不是便宜。
- **不要**把 2-of-3 写成「消除网关信任」；它把 1 把钥换成任意 2 把钥。
- **不要**把「电路内逐回执验签」写成「解决截尾」；截断前缀仍是真链。
- **不要**用没有安全评审的 BabyBear 素域/小扩域 Schnorr。
- **不要**在没有实测前把 zkTLS 写成通用执行真实性方案；它只覆盖外部 TLS。
- **不要**在未版本化的情况下新增公开值；`decoded == payload["outcome"]` 会让
  所有旧证书对不上。
- **不要**把新旧 vkey 的结果放同一张表。

## 10. 与 ToolSeal/截尾、回执链结构、P-PP 的关系

### 10.1 方案 × 四层

| 方案 | 电路内结构 | 链下逐条签名 | 公开值 `trace_root` | 链下 seal（截尾） |
|---|---|---|---|---|
| 现状 | 验 | 验（链下） | 承诺 | 验（链下，信网关） |
| A1 逐回执入电路 | 验 | **电路内验** | 承诺 | 仍链下；截尾不变 |
| A2 seal 入电路 | 验 | 链下 | 承诺 | **电路内验 seal**；仍信网关陈述 |
| B STARK-friendly | 验 | 可电路内/链下 | 承诺 | 取决于是否也换 seal 方案 |
| C 阈值 | 验（不变） | 链下 t-of-n | 承诺 | t-of-n seal；信 t 个网关 |
| D zkTLS | 验（不变） | 链下（可加 attestation） | 承诺 | 不直接覆盖；只证外部响应 |
| E TEE/HSM | 验（不变） | 链下，钥在认证环境 | 承诺 | 钥托管加固；不证完整 |

### 10.2 截尾真相表

| 措施 | 能否排除截尾 | 为什么 |
|---|---|---|
| 仅链下逐条验签 | **否** | 截断后的前缀仍是逐条签名有效的真链 |
| 仅电路内逐条验签（A1） | **否** | 同上；电路只多证了“签名有效” |
| 链下 `ToolSeal`（现状） | **在网关诚实且验证方有公钥时是** | seal 承诺 count/root；但网关可为截断链签新 seal |
| 电路内验 seal（A2） | **不改变信任，只把验签搬进证明** | 仍要信网关签的 count/root；网关作恶仍可签 |
| 阈值 seal（C1） | **在 <t 个网关被攻陷且共签者核对链时是** | t 个合谋仍可签截断链；视图一致性需另证 |
| 透明日志 + gossip | 可检测 split-view/截尾（需一致性证明） | 本仓未实现（`B1-split-view`） |
| zkTLS | **否** | 它证明外部响应来源，不证明调用序列完整 |
| TEE/HSM | **否** | 它证明钥在认证环境，不证明会话完整 |

**一句话**：截尾是**完整性/覆盖**问题，不是**签名验证位置**问题。把 Ed25519
搬进电路不会让截尾消失；只有「谁对链尾做了承诺、验证方能否独立比较」改变它。

### 10.3 回执链结构

- `canonical_receipt_bytes` 是签名与摘要的**共同原像**；任何新签名方案必须
  对同一段字节签名，否则链摘要/`prev`/`trace_root` 全变。
- `sig` 不参与摘要，这是自指的必要设计；多签/阈值签名也只能是**旁路容器**，
  不能进 `prev` 链。
- `keyid` 在规范字节内，换钥/换方案必须换签名；`prev` 绑定的是内容，不是
  签名容器；因此加签不会改变链结构，但会改变证书体积。
- 域分隔必须保持：回执 `pop-trace-v1`、seal `pop-trace-seal-v1`；新方案用新域，
  防跨用途重放。
- 若 A2 把 seal 纳入证明，seal 的 `count`/`root` 必须与 `trace_root` 在电路内
  交叉核对；否则证明只是“某条 seal 被验过”，不与这条链绑定。

### 10.4 P-PP 的关系

P-PP（[`design-policy-pp.md`](design-policy-pp.md)）解决的是**策略哈希的出处**：
权威签发策略清单，验证方确认证书里的 `policy_hash` 在清单里。它与本文的
**执行出处**是正交的两件事：

| | P-PP | 网关验签 |
|---|---|---|
| 对象 | 策略 π 的哈希 | 工具回执/seal |
| 签名者 | 规范方 R | 网关 |
| 证明什么 | 这个 `policy_hash` 被 R 签发过 | 这条链由网关钥签过 |
| 不证明什么 | 策略内容正确、执行真实 | 策略出处、执行真实（A4） |
| 对 vkey | 无（证书层） | 取决于方案 A/B |

**可复用的模式**：P-PP 的“权威签名清单 + 只追加 registry + 哈希查询”正好可以
用来做 **gateway roster**：权威签 `{keyid, pubkey, operator}` 清单，验证方按
`gateway_roster_hash` 查；这样至少把「验证方从带外拿到一把钥」升级为「验证方
核过一份被签发的网关名册」。但要注意：

- roster 签名只证明“这些钥被某个权威登记过”，**不证明**网关执行诚实；
- 若策略权威与网关运营方是同一实体，信任会塌缩成一点，论文必须说明角色分离；
- P-PP 的 registry 不解决吊销/轮换的实时性；需要 `valid_from/through` 与吊销
  列表，否则旧钥仍可验。

## 11. 论文 §7 的输入要点与页数影响

### 11.1 需要写进 §7.5 的要点（按优先级）

1. **信任根仍含网关钥**：链下 Ed25519 是验证方侧的检查，不是电路性质；
   网关可签与执行不符的回执（A4）。
2. **截尾保证依赖网关公钥**：没有 `--gateway-key` 时 3d 是 PASS +「截尾不可
   排除」；有公钥但无 `trace_seal` 则 FAIL。这是现有语义，不能写成“已解决”。
3. **阈值只降低单点**：2-of-3 把「1 把钥泄露」改成「任意 2 把钥」；不消除合谋，
   不证明多网关视图一致性，不关闭截尾。
4. **电路内验签 blocked**：没有 guest、没有 cycle/time/memory 数字；不得由
   链下 0.094–10.165 ms 外推。
5. **中期路线是“先测再决定”**：先做 seal-only 最小 guest，实测成本可接受才
   继续；否则保留链下方案。不要承诺“将会入电路”。
6. **zkTLS 只覆盖外部 HTTP**：不是本地工具或通用执行真实性的答案（若正文
   不展开，可在 artifact/design doc 里指路）。

### 11.2 可直接改写的英文句子（约 90 词，供 §7.5 用）

> The trust root still contains the gateway key: off-circuit Ed25519 verification
> checks signatures, but a compromised gateway can sign receipts that do not match
> execution, and the session-end seal is itself a gateway statement. A 2-of-3
> prototype reduces the single-key risk to any two keys, yet it neither prevents
> collusion nor proves that the gateways agree on the chain tail, and it does not
> close truncation. In-circuit verification remains blocked; we report no cycle,
> time or memory figure and do not infer one from the off-circuit cost.

（约 90 词；若 §7 页数吃紧，可删最后一句，保留前三句。）

### 11.3 页数影响

以 [`tdsc-writing-plan.md`](tdsc-writing-plan.md) 的口径（§7 约 1371 词 / 2.0 页，
约 740 词/页；终稿预计 11.6–11.7 页，12 页上限，余量约 0.3–0.4 页）：

| 改动 | 增量 | 页数 | 备注 |
|---|---:|---:|---|
| §7.5 现状 | `wc -w` 179（含少量 LaTeX 命令） | ≈ 0.24 页 | 已含 blocked 与阈值边界 |
| 加 80–120 词（§11.2） | +80–120 词 | **+0.11–0.16 页** | 推荐；余量仍有 0.14–0.29 页 |
| §7.6 的一条限制改一句 | 0–20 词 | +0.00–0.03 页 | 与 §7.5 不重复即可 |
| 加 5 行方案对比表 | 约 150–200 词当量 | **+0.25–0.40 页**（含表格占位） | **不推荐**；会吃光余量 |
| 中期原型出数后 §5.6 加一行 | 1 行 + 2–3 句 | +0.05–0.10 页 | 仅在实测并标 vkey 后 |

**建议**：正文只加 §11.2 的 ~90 词，方案对比表留在本文/artifact，不进论文；
§5 的 `tab:gateway` 不变，`In-circuit Ed25519` 继续是 blocked 行。

### 11.4 不要写进论文的

- “电路内验签只贵一点/大约多少周期”——没有数；
- “2-of-3 消除了网关信任”——没有；
- “zkTLS 证明了工具执行真实”——只对外部 TLS 响应，且不证明完整性；
- “STARK-friendly 一定更便宜”——没有原型；
- 把新旧 vkey 的证明数字放同一张表。

## 12. 开放问题与验收

### 12.1 开放问题

1. **roster 权威是谁**：策略权威、平台运营方、还是独立审计方？角色分离如何
   在部署中强制？
2. **阈值运营独立性**：2-of-3 的三把钥是否真由三个独立运营方持有？同一云
   账号下的三把钥不构成 2-of-3 信任。
3. **共签者承诺语义**：视图承诺还是执行承诺？前者便宜但不证明执行。
4. **zkTLS 栈选择**：notary/MPC 的信任假设、隐私披露、可用性。
5. **STARK-friendly 安全目标**：需要多少 bit？扩域次数/参数由谁评审？
6. **测量资源**：`/tmp/pop-proof.lock`、独立 `CARGO_TARGET_DIR`、≥10.15 GiB
   内存；谁在何时跑？
7. **vkey 排期**：A2/A1 是否与 X1 的 binary/vkey 更新同批？旧结果如何标注？

### 12.2 本文验收

- 四个主方案（A/B/C/D）均有「证明 / 不证明 / 成本 / vkey / 步骤」；
- 推荐路线明确短期/中期；
- 不编造周期数；B1 的 blocked 状态原样引用；
- 只新增本文，不改代码/circuits/vkey/论文；
- `python3 -m unittest tests.test_doc_links -v` 通过。

## 13. 来源

- [`bench/results/gateway_sig.md`](../bench/results/gateway_sig.md) /
  [`gateway_sig.json`](../bench/results/gateway_sig.json)：链下 Ed25519、
  ToolSeal、2-of-3 原型实测；电路内 blocked。
- [`docs/blockers/B1.md`](blockers/B1.md)：B1-circuit-ed25519 的 blocked 原因、
  解除条件、不得外推的声明。
- [`docs/blockers/Core.md`](blockers/Core.md)：guest 代码变更 ⇒ vkey 变化的先例
  （旧/新 vkey、binary sha256、不得混表）。
- [`docs/security-model.md`](security-model.md) §5.3/§5.4：截尾、ToolSeal、
  A4 网关作恶、A7 密钥托管。
- [`circuits/types/src/lib.rs`](../circuits/types/src/lib.rs)：`ToolReceipt`、
  `canonical_receipt_bytes`、`verify_receipt_chain`、`ProofOutput::trace_root`。
- [`policydsl/evidence/trace.py`](../policydsl/evidence/trace.py)：`ToolSeal`、
  `canonical_seal_bytes`、`verify_seal`、三层/四层边界。
- [`scripts/verify/verify_cert.py`](../scripts/verify/verify_cert.py)：3d 的
  `trace_seal` 检查与 `--gateway-key` 语义。
- [`bench/bench_gateway_sig.py`](../bench/bench_gateway_sig.py)：2-of-3 多签
  原型与阈值语义测试。
- [`docs/design-policy-pp.md`](design-policy-pp.md)：P-PP 的签名清单/registry
  模式（可复用于 gateway roster）。
- [`docs/plan-m2-m6.md`](plan-m2-m6.md) A12：本文的任务边界（设计/成本估算，
  不实现，等 vkey 排期）。
- [`docs/tdsc-writing-plan.md`](tdsc-writing-plan.md)：§7 页数与预算。
- [`paper/tdsc-paper.tex`](../paper/tdsc-paper.tex) §7.5/§7.6：现有
  “Gateway trust, and a blocked circuit check” 与限制列表。
