# Proof-of-Policy 安全模型

> 草稿（Phase 6 / W7）。形式化程度：定义 + 归约论证 + 对应实验；完整游戏式证明见论文附录。
> 记号：策略 `π`（ConstraintSpec，含 `policy_hash`）；响应/轨迹 `T`；判定函数 `J(π,T) ∈ {passed, violations}`；
> 证明 `p`；公共值 `pub`；承诺 `c = H(T)`（SHA-256）；一次性挑战 `n`（nonce）；响应绑定 `b = H(BIND_DOMAIN ‖ len(n) ‖ n ‖ T)`。

## 1. 参与方与威胁模型

| 参与方 | 能力/目标 |
|---|---|
| 证明者（agent 运营方） | 拥有 `T`，生成证明与证书；**不可信**（可能试图伪造合规或隐藏违规） |
| 验证者（监管/审计/第三方） | 只持公共产物（`π`、ELF/vkey、`pub`、证据可选开示、账本） |
| 策略作者 | 发布 `π`，其 `policy_hash` 绑定进证明与证书 |

**对抗目标**：(A1) 对违反 `π` 的 `T` 伪造“通过”；(A2) 从公共值中推断 `T` 的内容；
(A3) 伪造/否认违规证据；(A4) 换用不同策略/程序后仍复用旧证书；(A5) 事后篡改审计记录；
**(A6) 换响应**：用一条合规的 `T` 出证/出证明，却把一条不合规的 `T′` 送达验证者/用户
（「证明的 T」与「送达的 T′」脱钩）。

## 2. 定义

**完备性 Completeness.** 若 `J(π,T).passed = true`，诚实证明者以可忽略失败概率产出被验证者接受的 `(p, pub)`。

**合规健全性 Soundness (A1).** 对任意多项式时间对手 `A`：对不满足 `π` 的 `T`，`A` 产出被接受的 `pub` 的概率可忽略。
*论证*：程序在 zkVM 内**确定性**计算 `J(π,T)` 并 `commit(pub)`。被接受 ⇒ `pub` 等于该 zkVM 执行输出（zkVM 健全性），
而确定性保证输出唯一 = `J(π,T)`。故伪造需攻破 zkVM 健全性（或哈希碰撞）。**边界**：仅对**入电路**的规则种类成立
（keyword/length/pattern）；工具参数/`format`/`budget` 目前为链下参考判定，证书标 `zk:false`，不适用本定义（见 §5）。

**策略绑定 Provenance (A4).** 证明的公开值**必然携带** `policy_hash = H(canonical(π))` —— 它由 guest 从
**参与判定的同一段规范字节**上算出来（P0-1），因此不可能「用策略 π′ 判定、却声称 π 的哈希」。
验证者做**三方比对**，三者必须同时相等：

1. 证书载荷声明的 `policy_hash`（及证书 `outcome` 内嵌的那份，二者须自洽）；
2. 由策略包**现场重编译**得到的 `sha256`；
3. **证明公开值**解出来的 `policy_hash`（`pop-verify` 现在会解码公开值，而不只是哈希一遍）。

只有两个来源时一律判**失败**（防止「三方比对」退化成恒真）。此外
`binding.vkey_hash` 绑定程序（由 ELF 派生），`binding.proof_sha256` 绑定证明工件，
`binding.proof_mode`（P0-4）**诚实标注这一档证据的隐藏程度**（`core`/`compressed` 的
STARK **不是零知识**，见 §5 的 ③）——三者任一被替换 ⇒ 验证失败，而「标了某档却拿不出
工件」还会被 `verify_cert.py` 单独判 FAIL。实验：`tests/test_policy_binding.py`（含「空策略证明 + 真策略哈希」
攻击回归，以及「真证明 + 假哈希必须被拒」的证明层测试）。

**响应绑定 Response binding (A6).** 验证者（或客户端）在出证前出一个一次性挑战 `n`；电路把
`b = H(BIND_DOMAIN ‖ u32_be(len(n)) ‖ n ‖ T)` 写进公开值，证书把它连同 `n` 一起记录。
*论证*：被接受的 `pub` 必然携带 `b`，而 `b` 由 zkVM 内用**参与判定的同一条 `T`** 算出（与
`policy_hash` 同源，见 §2 Provenance）。若送达的 `T′ ≠ T`，验证者用 `(n, T′)` 重算得到
`b′ ≠ b`（`H` 抗碰撞 + 编码单射），绑定核对失败。因此对手只能：① 攻破 zkVM/哈希；
② 让送达的 `T′` 就是被证明的 `T`。**边界**：`n` 必须由**验证者**选取且**一次性**——
`b` 绑定的是「本次会话的这条 T」，不是「任何一次会话的这条 T」，重放一条已用 nonce 的合法证书
在密码学上成立（危害是会话计数，不是伪造 `T′`）；nonce 是公开值，必须公开否则无人能核对。
一次性由协议使用方保证（`policydsl.challenge.NonceStore` 为最小参考实现）。
实验：`tests/test_binding.py`（换 `T` 拒、换 `n` 拒、域分离）。

**承诺隐私 Committed-value privacy (A2, 私有模式).** 验证者视图 `V = (b, c, {rule_i, kind_i, e_i}, redaction)`，其中 `e_i = H(evidence_i)`。
*论证*：`V` 不含 `T` 的任何明文（仅 64-hex 承诺）；由 `H` 的抗碰撞/抗原像性，`V` 对 `T` 的泄露仅为“承诺可验证性”。
新增的 `b` 也不扩大泄露面：它与 `c` 同为 `T` 的哈希——拿到 `V` 的人能做的只是**猜测—验证**
（猜一条 `T′` 看 `b` 是否吻合），这对任何承诺都成立，不能反推 `T`。
*实验*：Leak 实验——公开值中不含响应/证据明文，且 `c ≠ T`（`tests/test_commit.py::TestPrivateOutput`、`scripts/private_demo.py`）。

> ⚠️ **本定义的上界必须读准（P0-4 核查后收紧）**：它保证的是「**公开值不出现明文**」，
> **不是**「`T` 不可恢复」。`b` 与 `c` 都是**公开且可离线重算**的 `T` 的函数，而自然语言响应的熵远低于
> SHA-256 的 256 bit，因此「猜测—验证」是**可行**的离线枚举，不是理论摆设。更关键的是：
> P0-2 要求 `b` 必须可由任意持 `(n, T′)` 的一方重算（这正是它防「换响应」的价值），
> 所以**在「验证者独立重算绑定」这一前提下，「响应绑定」与「响应内容隐藏」对低熵 `T` 互斥**——
> 想要后者只能让 `n` 保密（退化为信任出证方）或让 `T` 高熵。
> 因此私有模式的正确定位是「**不公开明文 + 违规只暴露证据承诺**」，
> 不可宣传为「`T` 不可恢复」。核查全文见 [`sp1-zk-audit.md`](sp1-zk-audit.md) §4。

**选择性披露与脱敏健全性.** `redaction_ok` ⇒ 同长且 `R` 与 `T` **仅在掩码位置不同**（掩码位为 `*`，VDR 式位选择器性质）；
`mask_covered` ⇒ 每个掩码位落在**电路内验证为真实完整匹配**的见证 span 内（`anchored_full_match` 逐 span 校验）。
二者合取 ⇒ 脱敏只遮蔽真实命中内容，不能借掩码掩盖任意文本。

**证据不可伪造/开示 (A3).** 开示片段 `f` 对承诺 `e` 有效当且仅当 `H(f)=e`；由抗原像性，未持有 `T` 不能伪造有效开示；
篡改开示被 `verify_bundle` 拒绝（`TestEvidenceOpening`）。

**证书不可伪造与记录完整性 (A5).** 证书为 DSSE 信封（签名覆盖规范化 payload）+ `cert_digest` 入**哈希链账本**：
任一条目增/删/改导致链校验失败（`policydsl.anchor.verify_ledger`，`TestAnchorLedger::test_tamper_detected`）。
流式证书额外成链（`streaming.chain={index,prev}`，`verify_chain` 检出重排/插入/篡改）。

**链上锚定（可选，`RpcAnchorBackend`）.** `cert_digest` 作为 `bytes32` 登记进 `contracts/Anchor.sol`
（`anchor(bytes32)`，**首次即最终**：重复登记 revert，链上时间戳不可被后来者覆盖）。链上**只存摘要**，
不泄露响应/策略内容。安全性来自链的不可篡改性与时间戳：验证方 `verify_session --rpc` 逐证书
`anchoredAt(digest)` 读回，并交叉核对本地账本记录的区块/时间戳与链上一致（`TestAnvilEndToEnd`）。
*边界*：链上 `anchoredAt=0` 表示未登记（区块时间戳不为 0）；锚定只证明「该摘要在某时刻已存在」，
不证明「证书内容为真」——后者由签名 + policy_hash + 证明承担。

**流式早停健全性.** 部分证书为**前缀判定**（`streaming.partial=true`），仅用于早告警；**权威结论**是 `on_llm_end` 的完整证书。
早停（`stop_on_violation`）在首次违规即产出 `streaming.stop` 并停止后续出证——不改变最终判定的健全性。

## 3. 为什么「违反策略的轨迹无法通过验证」

设 `T ⊭ π`，即 `J(π,T).passed = false`（存在违规 `v`）。若对手产出被接受的证明，则 `pub.passed = true` 且 `pub` 等于
zkVM 执行输出；确定性判定给出 `J(π,T).passed = false`，矛盾。因此在 zkVM 健全性与 `H` 抗碰撞的假设下，
对手只能：① 攻破 zkVM；② 更换策略/程序（被 `policy_hash` 三方比对 / `vkey_hash` 检测 —— 注意
**换策略这一路现在是电路内强制的**：想判 `π′` 就必然承诺 `H(π′)`，无法再声称 `H(π)`）；
③ 对**未入电路**的规则种类伪造（此时证书不声称 `zk`，见 §5）。

注意这一论证有个**前提**：验证者拿到的 `T` 必须就是被证明的那条。P0-2 之前这一点是**缺的** ——
对手完全可以拿合规的 `T` 出证、送出不合规的 `T′`，上述「设 `T ⊭ π`」根本不适用，
因为 `T` 与 `T′` 是两条不同的串。响应绑定（§2）补上的正是这条前提：验证者用自己出的 `n`
核对 `b`，`T′ ≠ T` 时核对必败。所以 §3 的论证应当读作「**在 `b` 核对通过的前提下**，
`T′ ⊭ π` 无法通过验证」。

## 4. 实验对照（可复现）

| 定义 | 对应测试/实验 |
|---|---|
| Completeness | `scripts/prove_policy.py`（eu pass）、`scripts/cross_validate.py` host/prove 14/14 |
| Soundness (入电路规则) | 违规向量证明产出 `passed=false`（`cross_validate` 的 hit 向量；`private_demo` 违规） |
| Provenance | `scripts/verify_cert.py` 各卡（policy_hash 三方比对 / vkey / proof_sha256）；`tests/test_policy_binding.py`（攻击回归 + 证明层 opt-in） |
| Response binding (A6) | `scripts/verify_cert.py --response T′`（第 3b 卡）；`tests/test_binding.py`（换 T′ 拒 / 换 nonce 拒 / 域分离 / 空 nonce）；`scripts/demo_e2e.py` 的 challenge 实验 |
| Committed-value privacy | Leak 实验（`private_demo`）；`test_private_output_no_leak` |
| Redaction soundness | `TestMaskCoverage`（伪造 span → `mask_covered=false`） |
| Evidence unforgeability | `TestEvidenceOpening`（篡改开示 → 失败） |
| Ledger integrity | `TestAnchorLedger`（链篡改检出）；`verify_session.py::ledger_chain` |
| Stream chain | `TestStreamingChain`（链路验证/篡改/早停） |
| End-to-end | `scripts/verify_session.py` 全 PASS（含真实 SP1 证明） |

## 5. 假设、边界与非目标

1. **zkVM 假设**：SP1 的**健全性**（成立，我们复用其 verifier）+ **零知识性**（**不成立**）。
   链上最终性（Groth16 合约）在 Phase 5 仅做接口（file 账本后端）。
   > ✅ **已核实（P0-4，2026-09-11）**：核查结论见 [`sp1-zk-audit.md`](sp1-zk-audit.md)。三句话：
   > ①**健全性成立**（官方安全模型 + Zellic 审计 + 本项目实测反例，三者一致），§3 的论证不受影响；
   > ②**`core` / `compressed` 证明不满足零知识性** —— Succinct 官方安全模型明文
   >   "individual STARK proofs in SP1 do not currently satisfy the zero-knowledge property"，
   >   源码侧独立印证：整个 SLOP 栈对 blinding/hiding/randomizer **命中 0**，
   >   `ShardProof` 把 `main_commitment`（轨迹 Merkle 根）与 `opened_values`（轨迹在挑战点的真实开值）**明文**放进证明；
   >   唯一可能的 ZK 路径是 `groth16`/`plonk`（内部 STARK 证明作为 gnark 电路的**私有见证**，
   >   公开输入只有 5 个），但该性质属**包装器层面声明、未被任何审计评估、非后量子，且本机 12 GB 出不了证**；
   >   原生 ZK 的 `slop-veil`（eprint 2026/683）已发布但**未被任何证明路径依赖**。
   > ③因此**私有模式的准确定义是「公开值不泄露明文」**，不是「证明工件不泄露见证」，
   >   更不是「`T` 不可恢复」（后者对低熵 `T` 由 §2 的猜测—验证论证直接否证，与 SP1 无关）。
   > **已落地**：证书 `binding.proof_mode` 字段（`cert.PROOF_MODE_HIDING` / `proof_hiding()`；
   > `verify_cert.py` 把它与**工件自报的模式**交叉核对，无工件只能标 `unproven`，未知模式
   > 一律 `"unknown"` 而不猜）；论文/README 的「零知识」口径已收紧为
   > 「策略零知识 + 响应内容隐藏有明确上界」。
2. **哈希假设**：SHA-256 抗碰撞/抗原像。
3. **签名**：**Ed25519**（`policydsl/cert.py` 的 `Ed25519Signer` + `policydsl/keys.py`）。私钥留在出证方，验证方只持公钥，因此**无法伪造**签名 —— 这是「证书可交第三方审计」的前提。P0-3 之前的 `DEMO_KEY` HMAC（对称，验证方也能伪造）已**结构性废弃**：`verify_envelope` 按 `keyid` 前缀分发，`demo-hmac-sha256` 不在白名单里，连配对密钥放进 keyring 也会被拒。**HSM/KMS 托管仍待补**（当前私钥是文件，口令可选）。
4. **规则覆盖（P7-b 后更新）**：`keyword_block` / `length_bound` / `pattern_block` / **`format_check`（json/int/float 规范子集）**
   / **`tool_arg_guard`（工具回执，含 `tools` 限定）** / **`budget_bound`（calls 数回执；tokens 电路内自算）**
   均已**入电路**（`pop-types::evaluate`），因此 §2 的健全性定义覆盖这 6 类。
   两点仍需注意：① Agent 工具路径证书的 `zk:true` 表示**规则可证**，是否**附证明**由证书
   `binding.vkey_hash`（`unproven` 表示仅链下判定）表明；② 轨迹类规则的**输入**（工具回执链）不是
   证明者的自述，但**回执确由网关签发**这一步在**链下**验签完成（见下条「轨迹绑定」）。
   `budget_bound(unit="tokens")` 的口径已从「证明者声明的 `token_count`」改为**电路内按固定空白字节集自算**的
   run 数（不兼容变更，见「轨迹绑定」）。

   **轨迹绑定（P1-5）**：`ProofRequest`/`PrivateRequest` 里的 `tool_calls`/`token_count` 已**删除**，
   代之以网关签发的 `receipts`（`{seq,tool,args,result_digest,ts,prev,keyid,sig}` 链）。健全性主张分三层，
   必须分别陈述，不可合并成"电路证明了整个轨迹"：
   | 层 | 保证 | 不保证 |
   |---|---|---|
   | 电路内（`verify_receipt_chain`） | 链**结构**自洽：`seq` 连续、`prev` 逐条咬合、摘要由内容重算；不自洽则 `trace_unbound` **fail-closed** | 也**不**验签：改动链**尾**那条的内容，结构上仍自洽 |
   | 链下（`trace.verify_chain`） | 每条回执确由 keyring 里的 `keyid` 钥签过（Ed25519）；非白名单方案前缀结构性拒绝 | 不防**网关自身**作恶 |
   | 公开值（`trace_root`） | 链尾摘要随证明承诺，验证方拿网关侧回执重算即可核对「证明绑的是哪条链」 | 公开的只是摘要，不是链本身 |
   第三层已落成**可执行的验证路径**：`verify_cert.py --receipts R.json` 由验证方**自己手上**的回执
   重算链尾（与 `--response` 之于响应对称），`--gateway-key` 再跑一遍链下验签。
   这两道关**不可互相替代**：摘要比对回答「送检的链与证明绑的是不是同一条」，
   验签回答「这条链是不是网关签的」。链尾被改内容而保留原签名、且送检的链正是被改的那一份时，
   结构校验与摘要都过得去（`trace_binding` PASS）而 `receipt_chain` 判 FAIL —— 这正是
   「只核对一致性不等于核对来源」的实例。该边界被写成显式用例而不是被含糊过去
   （`tests/test_trace.py::TestVerifyCertTraceBinding`，含缺 `--gateway-key` 时如实报「签名未验」）。
   因此**信任前提**是「网关密钥不被滥用」——网关是被显式信任的第三方，不在被证明之列。旧向量里的
   `tool_calls`/`token_count` 现在是**未知字段**且三处请求结构（`VectorIn`/`ProofRequest`/`PrivateRequest`）
   都 `deny_unknown_fields`：拿旧向量出证会**解析失败**，不会退化成"零次工具调用"照样出证。
5. **语义**：正则为受支持子集 + ASCII 语义；长度按码点。非 ASCII 字母大小写等差异已在代码/文档标注。
6. **非目标**：不证明“模型推理”本身（那是 zkAgent/zkML 层）；不覆盖训练数据/模型卡（EU AI Act Art.11 等）。
