# Proof-of-Policy 安全模型

> 草稿（Phase 6 / W7）。形式化程度：定义 + 归约论证 + 对应实验；完整游戏式证明见论文附录。
> 记号：策略 `π`（ConstraintSpec，含 `policy_hash`）；响应/轨迹 `T`；判定函数 `J(π,T) ∈ {passed, violations}`；
> 证明 `p`；公共值 `pub`；承诺 `c = H(T)`（SHA-256）。

## 1. 参与方与威胁模型

| 参与方 | 能力/目标 |
|---|---|
| 证明者（agent 运营方） | 拥有 `T`，生成证明与证书；**不可信**（可能试图伪造合规或隐藏违规） |
| 验证者（监管/审计/第三方） | 只持公共产物（`π`、ELF/vkey、`pub`、证据可选开示、账本） |
| 策略作者 | 发布 `π`，其 `policy_hash` 绑定进证明与证书 |

**对抗目标**：(A1) 对违反 `π` 的 `T` 伪造“通过”；(A2) 从公共值中推断 `T` 的内容；
(A3) 伪造/否认违规证据；(A4) 换用不同策略/程序后仍复用旧证书；(A5) 事后篡改审计记录。

## 2. 定义

**完备性 Completeness.** 若 `J(π,T).passed = true`，诚实证明者以可忽略失败概率产出被验证者接受的 `(p, pub)`。

**合规健全性 Soundness (A1).** 对任意多项式时间对手 `A`：对不满足 `π` 的 `T`，`A` 产出被接受的 `pub` 的概率可忽略。
*论证*：程序在 zkVM 内**确定性**计算 `J(π,T)` 并 `commit(pub)`。被接受 ⇒ `pub` 等于该 zkVM 执行输出（zkVM 健全性），
而确定性保证输出唯一 = `J(π,T)`。故伪造需攻破 zkVM 健全性（或哈希碰撞）。**边界**：仅对**入电路**的规则种类成立
（keyword/length/pattern）；工具参数/`format`/`budget` 目前为链下参考判定，证书标 `zk:false`，不适用本定义（见 §5）。

**策略绑定 Provenance (A4).** 证书携带 `policy_hash = H(canonical(ConstraintSpec))`，验证者**重算** `compile(π)` 并比对；
`binding.vkey_hash` 绑定程序（由 ELF 派生），`binding.proof_sha256` 绑定证明工件。任一被替换 ⇒ 验证失败。

**内容隐私 Content privacy (A2, 私有模式).** 验证者视图 `V = (c, {rule_i, kind_i, e_i}, redaction)`，其中 `e_i = H(evidence_i)`。
*论证*：`V` 不含 `T` 的任何明文（仅 64-hex 承诺）；由 `H` 的抗碰撞/抗原像性，`V` 对 `T` 的泄露仅为“承诺可验证性”。
*实验*：Leak 实验——公开值中不含响应/证据明文，且 `c ≠ T`（`tests/test_commit.py::TestPrivateOutput`、`scripts/private_demo.py`）。

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
对手只能：① 攻破 zkVM；② 更换策略/程序（被 `policy_hash`/`vkey_hash` 检测）；③ 对**未入电路**的规则种类伪造（此时证书不声称 `zk`，见 §5）。

## 4. 实验对照（可复现）

| 定义 | 对应测试/实验 |
|---|---|
| Completeness | `scripts/prove_policy.py`（eu pass）、`scripts/cross_validate.py` host/prove 7/7 |
| Soundness (入电路规则) | 违规向量证明产出 `passed=false`（`cross_validate` 的 hit 向量；`private_demo` 违规） |
| Provenance | `scripts/verify_cert.py` 各卡（policy_hash / vkey / proof_sha256）；`TestCertificate` |
| Content privacy | Leak 实验（`private_demo`）；`test_private_output_no_leak` |
| Redaction soundness | `TestMaskCoverage`（伪造 span → `mask_covered=false`） |
| Evidence unforgeability | `TestEvidenceOpening`（篡改开示 → 失败） |
| Ledger integrity | `TestAnchorLedger`（链篡改检出）；`verify_session.py::ledger_chain` |
| Stream chain | `TestStreamingChain`（链路验证/篡改/早停） |
| End-to-end | `scripts/verify_session.py` 全 PASS（含真实 SP1 证明） |

## 5. 假设、边界与非目标

1. **zkVM 假设**：SP1 的健全性/零知识性；我们复用其 verifier。链上最终性（Groth16 合约）在 Phase 5 仅做接口（file 账本后端）。
2. **哈希假设**：SHA-256 抗碰撞/抗原像。
3. **签名**：当前为 **HMAC-SHA256 demo signer**（`policydsl/cert.py`），仅演示完整性；生产应替换为 Ed25519/HSM（信封结构不变）。
4. **规则覆盖（P7-b 后更新）**：`keyword_block` / `length_bound` / `pattern_block` / **`format_check`（json/int/float 规范子集）**
   / **`tool_arg_guard`（工具参数，含 `tools` 限定）** / **`budget_bound`（calls；tokens 用请求携带的 `token_count`）**
   均已**入电路**（`pop-types::evaluate`），因此 §2 的健全性定义覆盖这 6 类。
   两处仍需注意：① `budget_bound` 的 `tokens` 依赖 `token_count`，该值是**证明者声明**而非电路内分词结果（文档标注）；
   ② Agent 工具路径证书的 `zk:true` 表示**规则可证**，是否**附证明**由证书 `binding.vkey_hash`（`unproven` 表示仅链下判定）表明。
5. **语义**：正则为受支持子集 + ASCII 语义；长度按码点。非 ASCII 字母大小写等差异已在代码/文档标注。
6. **非目标**：不证明“模型推理”本身（那是 zkAgent/zkML 层）；不覆盖训练数据/模型卡（EU AI Act Art.11 等）。
