# Proof-of-Policy 安全模型 **v2**（游戏式定义 + 归约）

> **v2（2026-09-11，P1-8）。** v1 是一份「我们检查过这些性质」的**清单**；v2 把它改写成
> **游戏 + 归约**：每个性质给出游戏、对手能力、归约到的标准假设、**代码落点**，
> 以及**它不保证什么**。
>
> 三条口径纪律贯穿全文 —— 它们分别来自 P0-1、P0-4、P1-5 三次自查的教训：
>
> | # | 纪律 | 反面例子（本项目真实踩过/差点踩的） |
> |---|---|---|
> | D1 | **未证的性质不写成已证** | v1 把「链下参考判定」的规则也算进健全性定义 |
> | D2 | **链下完成的步骤不算进电路** | 「电路证明了轨迹」——实际验签在链下 |
> | D3 | **「公开值不含明文」≠「内容不可恢复」** | 「零知识」口碑；见 §5.2 |
>
> **v2 最重要的产出不是把已做的说清楚，而是发现了一个真缺口**：回执链的**截尾**
> 攻击三层防线全不设防，实测可复现。见 **§5.3** —— 这正是"把安全模型写成
> 游戏"的价值：清单式的 v1 永远问不出"链短了一条会怎样"。
>
> **本次（P1-5b）把该缺口堵上**（`ToolSeal`）：网关在会话末端签 `{count, trace_root}`，
> 验证方核对链长/链尾即无从截尾。**残留边界同样如实登记**：验证方必须持有网关公钥
> （`--gateway-key`）才拿得到这个保证，且 seal 把信任挪向网关（A4）而非消除信任。

---

## 0. 记号、参与方与信任边界

### 0.1 记号

| 记号 | 含义 |
|---|---|
| `π` | 策略 = `ConstraintSpec`（含 `policy_hash = H(canonical(π))`） |
| `T` | 响应（或「响应 + 工具轨迹」整体） |
| `J(π,T)` | 判定函数 `∈ {passed, violations}`；实现见 `policydsl/evaluate.py`（golden）与 `pop-types::evaluate`（电路内，二者交叉验证） |
| `p, pub` | 证明与其**公开值**（`passed / policy_hash / response_binding / trace_root`） |
| `c = H(T)` | 响应承诺（私有模式） |
| `n, b` | 一次性挑战 `nonce`，与响应绑定 `b = H("pop-bind-v1" ‖ u32be(len(n)) ‖ n ‖ T)` |
| `R` | 回执链 `r₀…r_{m-1}`，`r_i = {seq=i, tool, args, result_digest, ts, prev=d(r_{i-1}), keyid, sig}`，`d` = 规范字节的 SHA-256，`r₋₁ = "genesis"` |
| `H` | SHA-256；`‖` 为拼接；`u32be` 为大端 4 字节长度前缀 |

### 0.2 参与方

| 参与方 | 诚实性 | 能力 |
|---|---|---|
| **证明者 / agent 运营方** | **不可信**（核心对手） | 持 `T` 与回执链（或其中的一部分），生成证明与证书；可任意选择要证明什么 |
| **工具网关** | **显式信任**（见 §0.3） | 每次工具调用**执行后**签发回执并接链；持 Ed25519 私钥 |
| **验证者**（监管/审计/第三方） | 诚实 | 只持公共产物；**可出 nonce**；**可独立重算**绑定 |
| **策略作者** | 诚实 | 发布 `π` |
| **账本 / 链** | 弱信任（不可篡改性） | 存 `cert_digest` |

### 0.3 信任边界（**v2 明确划线**）

被证明的东西只有一件：**「zkVM 确定性执行 `J(π,T)` 得到的 `pub`」**。以下都**不在**被证明之列，
而是**假设**或**链下步骤**：

| 环节 | 在哪一层 | 若不成立会怎样 |
|---|---|---|
| `T` 确由某个真实 LLM 产出 | **不在任何层**（非目标，见 §6） | 健全性不受影响；这属于「推理完整性」= P1-6 的范围 |
| 回执确由**网关**签发 | **链下** Ed25519 验签（D2） | 见 L3：退化为「证明者自述轨迹」 |
| 网关**不作恶** | **假设** A4 | 网关可签一条与真实执行不符的回执 —— 这是本模型**最弱的一环**，如实标注 |
| 链是否**完整**（没被截尾） | **链下 + 证书**：网关会话末端承诺 `ToolSeal{count, trace_root}` + 验签（P1-5b） | 验证方须持网关公钥；见 **§5.3** |

### 0.4 对手能力（统一约定）

对手 `A` 是概率多项式时间算法，可用：任意次调用出证接口（自选 `T`、自选要证的回执链子序列）、
任意次向验证者索取 `nonce`、任意次向网关请求工具调用（**自适应选择参数**，
故可拿到任意消息的合法回执签名）、读取一切公开产物。`A` **不持有**：网关私钥、出证方私钥、
zkVM 的 soundness 突破能力。

---

## 1. 假设

| # | 假设 | 状态 |
|---|---|---|
| **A1** | **SP1 zkVM 健全性**：不能为非确定性执行输出伪造可接受证明 | ✅ 官方安全模型 + Zellic 审计 + 本项目实测反例三者一致（[`sp1-zk-audit.md`](sp1-zk-audit.md)） |
| **A2** | **SHA-256** 抗碰撞 + 抗原像 | 标准 |
| **A3** | **Ed25519** EUF-CMA（选择消息攻击下存在性不可伪造） | 标准 |
| **A4** | **网关诚实**：签名前确已执行该调用，且不在链上开天窗 | ⚠️ **信任假设，非密码学结论**（§0.3） |
| **A5** | **账本/链**不可篡改且时间戳单调 | 弱假设；链上锚定把它强化为公开可验证 |
| **A6** | **规范字节编码单射**：不同内容 ⇒ 不同字节串 | ✅ **实测**：Python ↔ Rust 的 `trace_root` 逐字节一致（`test_full_chain_parity`） |
| **A7** | 出证方私钥保密 | ⚠️ 当前是文件（`HSM/KMS 待补`） |

---

## 2. 游戏

每个游戏返回 1 表示 `A` 获胜。`Verify` 指**验证方的全部检查**（= `scripts/verify_cert.py`
逐卡 PASS，或 `verify_session.py` 对整条会话），而不是其中任意一条。

```
G_Sound(π, A):
  (T, p, pub, cert) ← A(π)                  ; 要求 J(π,T).passed = false
  return 1 iff Verify(π, pub, p, cert) = 1 ∧ pub.passed = true

G_Bind_pol(A):                              ; 用 π′ 判定却声称 π
  (π, π′, cert) ← A()                       ; 要求 π′ ≠ π
  return 1 iff Verify 接受 ∧ cert 声称的 policy_hash = H(canonical(π))

G_Bind_resp(A):                             ; 「证明的 T」≠「送达的 T′」
  n ← V                                     ; 验证者出一次性挑战，A 可多次索取
  (cert, T′) ← A(n)
  return 1 iff Verify 接受该证书 ∧ T′ ≠ T_n  （T_n = 证书所绑挑战对应的那条被证明的 T）
                 ∧ b(n, T′) = cert.challenge.response_binding

G_Bind_trace(A):                            ; 绑到一条网关没签过的链
  (cert, R′) ← A()                          ; R′ = 交付给验证者的回执链
  return 1 iff Verify(cert, R′, vk_gw) 接受 ∧ R′ ⊄ 网关实际签发过的链集合

G_Priv(A):                                  ; 私有模式：区分两条响应
  (T₀, T₁, V) ← A()                          ; |T₀| = |T₁|
  γ ← {0,1};  return 1 iff A(V(T_γ, n)) = γ

G_Redact(A):                                ; 用掩码掩盖非真实命中的内容
  (T, R) ← A()                              ; R 与 T 同长、仅掩码位不同
  return 1 iff Verify 接受 ∧ redaction_ok ∧ mask_covered ∧ R 遮蔽了某个非命中 span

G_Ledger(A):                                ; 事后篡改审计记录
  (ledger′) ← A(ledger)
  return 1 iff verify_ledger(ledger′) = ok ∧ ledger′ ≠ ledger  （且未被检出）
```

---

## 3. 引理链

### L1 策略绑定（P0-1）—— 归约到 A2

**命题**：`Pr[G_Bind_pol(A) = 1] ≤ Adv^{CR}_{SHA256}(B) + Pr[A1 被攻破]`。

**论证**：`pub.policy_hash` 由 guest 在 zkVM 内、从**参与判定的同一段规范字节**上算出
（不是另算一份）。若 `A` 用 `π′` 判定却声称 `H(π)`，则要么 `pub` 不等于 zkVM 执行输出
（违反 A1），要么 `H(canonical(π)) = H(canonical(π′))` 而两个字节串不同（违反 A2）。
验证方侧另做**三方比对**（证书顶层 / 证书 `outcome` / 现场重编译 / 证明公开值），
且**少于两个来源一律判失败** —— 这一条防的是「比对退化成恒真」。

**代码落点**：`circuits/program`（guest 内算 hash）、`policydsl/verifier.py::check_policy_binding`、
`scripts/verify_cert.py` 检查 3。
**不保证**：策略本身写得对不对（那是策略作者的事）；`vkey_hash` 之外的 ELF 一致性由证明工件哈希承担。

### L2 响应绑定（P0-2）—— 归约到 A2（域分离）

**命题**：`Pr[G_Bind_resp(A) = 1] ≤ Adv^{CR}_{SHA256}(B) + Pr[A1 被攻破]`。

**论证**：`b = H(DOM ‖ u32be(len(n)) ‖ n ‖ T)` 由 zkVM 内用**参与判定的同一条 `T`** 算出。
`T′ ≠ T` 时，验证者重算 `b′ = H(DOM ‖ u32be(len(n)) ‖ n ‖ T′)`；若 `b′ = b` 则构成 A2 的碰撞。
长度前缀（`u32be(len(n))`）与域前缀 `"pop-bind-v1"` 共同保证编码单射（A6），
防止 `n‖T` 的拼接歧义与跨用途复用。

**代码落点**：`policydsl/commit.py::response_binding`、`circuits` 内同构实现、
`verify_cert.py` 检查 3b、`tests/test_binding.py`（Python↔Rust 逐字节对齐）。
**不保证**：`n` 的一次性 —— 若验证者复用 `n`，一条旧证书可以重放（危害是**会话计数**，
不是伪造 `T′`）。一次性由协议使用方保证（`policydsl.challenge.NonceStore` 是最小参考实现）。

### L3 轨迹绑定（P1-5）—— **三层分解，不可合并陈述**

**命题（三层各有其界）**：

```
Pr[G_Bind_trace(A) = 1]
   ≤ Adv^{EUF-CMA}_{Ed25519}(B)          ← 来源：链下验签（A3）
   + Adv^{CR}_{SHA256}(B)                ← 结构：seq/prev 咬合 + 链尾摘要（A1+A2）
   + Adv^{forge}_{Ed25519}(B)             ← 截尾：伪造会话末端承诺 seal（P1-5b）
```

| 层 | 保证 | 落点 | **不保证** |
|---|---|---|---|
| **电路内** `verify_receipt_chain` | 链**结构**自洽：`seq` 从 0 连续、`prev` 逐条咬合、摘要由内容重算；不自洽 → `trace_unbound` **fail-closed** | `circuits/types`（guest 与宿主共用） | **不验签**；改动**链尾**那条的内容，结构上仍自洽 |
| **链下** `trace.verify_chain` | 每条回执确由 keyring 里 `keyid` 对应的 Ed25519 钥签过；非白名单方案前缀**结构性拒绝** | `policydsl/trace.py`、`verify_cert.py --gateway-key` | 不防**网关自身**作恶（A4）；**完整性**由下一行的 seal 层提供（见 §5.3） |
| **链下 + 证书** `trace.verify_seal` | 链**没有被截尾**：网关会话末端承诺的 `count`/`trace_root` 与交付链一致、签名有效（P1-5b） | `policydsl/trace.py::verify_seal`、`verify_cert.py` 3d | 须持网关公钥；seal 仍是**网关的**陈述（A4） |
| **公开值** `trace_root` | 链尾摘要随证明承诺；验证方拿**自己手上**的链重算即可核对「证明绑的是哪条链」 | `pub.trace_root`、`verify_cert.py --receipts` | 公开的只是摘要，不是链本身 |

**为什么结构层会落到 A2**：删/换/重排任一条回执，都会让它**后继**那条的 `prev` 对不上
（`prev = H(规范字节(r_{i-1}))`），于是要么结构校验失败，要么构造出 `H` 的碰撞。

**为什么"电路内不验签"是可接受的取舍**：zkVM 内验 Ed25519 代价高（把签名验证电路化会主导
整个证明开销）。代价是**链尾**成为结构层的盲点 —— 抓住它的是链下验签。
这两道关**不可互相替代**：摘要比对回答「送检的链与证明绑的是不是同一条」，
验签回答「这条链是不是网关签的」。实测：送检链与证书同为被改过的那一份时，
`trace_binding` **PASS** 而 `receipt_chain` **FAIL**
（`test_forged_last_element_caught_by_gateway_key`）。

**链的完整性**由第四层（`verify_seal`，P1-5b）承担 —— 但**有前提**：验证方必须持网关
公钥，且 seal 是网关的陈述（A4）。**少了前提就退回"完整性无保证"**，见 §5.3。

### L4 脱敏健全性 —— 归约到电路内的匹配见证

**命题**：`Verify 接受 ∧ redaction_ok ∧ mask_covered ⇒ R 仅遮蔽真实命中的内容`。

**论证**：`redaction_ok` 保证 `R` 与 `T` 同长且**仅在掩码位不同**（VDR 式位选择器）；
`mask_covered` 要求每个掩码位落在**电路内验证为真实完整匹配**的见证 span 内
（`anchored_full_match` 逐 span 校验）。二者合取后，掩码不可能落在非命中处 ——
否则要么 `redaction_ok` 失败，要么该位不在任何已证 span 内。

**代码落点**：`policydsl/commit.py`、`circuits` 内 `mask_covered` 见证。
**不保证**：`T` 中未命中部分仍可能因**其它**通道泄露（见 L5 的隐私界）。

### L5 账本完整性 + 承诺隐私 —— 归约到 A2 / A5

**账本完整性**：`cert_digest` 进**哈希链账本**，任一条目增/删/改使链校验失败；
更弱的下界由链上锚定强化为「公开可验证的某时刻已存在」。
`Pr[G_Ledger(A) = 1] ≤ Adv^{CR}_{SHA256}(B)`。
**代码落点**：`policydsl/anchor.py::verify_ledger`、`contracts/Anchor.sol`（`anchor(bytes32)` **首次即最终**，
重复登记 revert ⇒ 后来的时间戳无法覆盖先到的）。
**不保证**：锚定只证「该摘要某时刻已存在」，**不证「证书内容为真」** —— 后者由签名 + L1 + L2 承担。

**承诺隐私**：`Pr[G_Priv(A) = 1] ≤ 1/2 + ε`，`ε` 由 **A2** 与**`T` 的熵**共同决定。
在 A2 下，`A` 无法从 `c = H(T)` 反推 `T`；但**区分游戏**里 `A` 自选 `(T₀,T₁)`，
所以 `ε` 的上界**只能是**「`A` 猜不中 `H(T_γ)`」—— 对**低熵** `T`，`A` 可以离线枚举
（§5.2）。因此本项目的私有模式**只主张 §5.2 的那条弱性质**。

### L6 组合义务（P1-6）—— ⏳ **规划中，未实现**

`Compose = (推理完整性 ∧ 策略合规)`；`Compose` 的证明由两次独立证明经**键分离**
（不同的 vkey / 不同的域前缀）组合而成，`CompositeCertificate` 同时引用两个证明摘要与两个 vkey。
**计划命题**：替换任一子证明被拒（`tests/test_compose.py` 的反例）。
**当前状态**：P1-6 **未开始**，本节是接口约定，不是已证结论 —— 按 D1 如实标注。

---

## 4. 主定理

> 在 A1–A3、A6 下，对使用**入电路**规则的策略 `π`：
>
> ```
> Adv_{Sound_π}(A)  ≤  Adv^{sound}_{zkVM}(B₁) + Adv^{CR}_{SHA256}(B₂) + Adv^{EUF-CMA}_{Ed25519}(B₃)
> ```
>
> 其中 `B₃` 项**仅在 `π` 含轨迹类规则**（`tool_arg_guard` / `budget_bound`）时出现 ——
> 那类规则的输入是回执链，其**来源**由链下验签承担（L3）。`B₃` 归约到的是
> **网关密钥**的不可伪造性，而不是 agent 的诚实性。

**证明梗概**：设 `T ⊭ π` 且 `Verify` 接受。于是 `pub` 等于 zkVM 的确定性执行输出（A1），
而确定性保证该输出唯一 = `J(π,T)`，故 `pub.passed` 必为 `false`。矛盾。
要把 `T` 换成 `T′` 需要 L2（否则 §"设 `T ⊭ π`" 根本不适用，因为被证明的是**另一条**串）；
要把 `π` 换成 `π′` 需要 L1；要让轨迹规则判在一条**假**链上，需要 L3 的签名层。
**覆盖范围**：`keyword_block` / `length_bound` / `pattern_block` / `format_check` /
`tool_arg_guard` / `budget_bound` 六类**均已入电路**（`pop-types::evaluate`，与 Python golden 交叉验证 14/14）。
**未覆盖**：语义级规则（P2-9，未实现）；`budget_bound(tokens)` 的分词语义（见 §6）。

---

## 5. 诚实边界（**不成立 / 不覆盖**）

### 5.1 证据开示与流式

- **证据不可伪造**：开示片段 `f` 对承诺 `e` 有效 ⟺ `H(f) = e`；由 A2 的抗原像性，
  未持 `T` 者不能伪造有效开示。`Pr ≤ Adv^{OW}_{SHA256}`。
- **流式早停**：部分证书是**前缀判定**（`streaming.partial=true`），**只用于早告警**；
  权威结论是 `on_llm_end` 的完整证书。早停不改变最终判定的健全性。

### 5.2 「零知识」不成立 —— 三句话（P0-4 核查，全文见 [`sp1-zk-audit.md`](sp1-zk-audit.md)）

1. **健全性成立**（官方安全模型 + Zellic 审计 + 本项目实测反例，三者一致）⇒ §4 的论证不受影响。
2. **`core` / `compressed` 证明不满足零知识性**：Succinct 官方安全模型明文
   *"individual STARK proofs in SP1 do not currently satisfy the zero-knowledge property"*；
   源码侧独立印证：整个 SLOP 栈对 blinding/hiding/randomizer **命中 0**，
   `ShardProof` 把 `main_commitment`（轨迹 Merkle 根）与 `opened_values`（轨迹在挑战点的**真实开值**）
   明文放进证明。唯一可能的 ZK 路径是 `groth16`/`plonk`（内部 STARK 作为 gnark 电路的私有见证），
   但它是**包装器层面的声明、未被任何审计评估、非后量子，且本机 12 GB 出不了证**；
   原生 ZK 的 `slop-veil`（eprint 2026/683）已发布但**未被任何证明路径依赖**。
3. 因此私有模式的**准确定义是「公开值不泄露明文」**（L5），
   不是「证明工件不泄露见证」，更不是「`T` 不可恢复」——
   后者对低熵 `T` 由猜测—验证**直接否证**，与 SP1 无关：
   `b` 与 `c` 都是公开且可离线重算的 `T` 的函数，而自然语言响应的熵远低于 256 bit。
   更关键的是，L2 **要求** `b` 可被任意持 `(n, T′)` 的一方重算（这正是它防「换响应」的价值），
   所以**在「验证者独立重算绑定」这一前提下，「响应绑定」与「响应内容隐藏」对低熵 `T` 互斥**。
   想要后者，只能让 `n` 保密（退化为信任出证方）或让 `T` 高熵。

**已落地**：证书 `binding.proof_mode` 字段（`cert.PROOF_MODE_HIDING` / `proof_hiding()`）；
`verify_cert.py` 把它与**工件自报的模式**交叉核对，无工件只能标 `unproven`，未知模式一律
`"unknown"` 而不猜。

### 5.3 ✅ **回执链的「截尾」缺口（v2 发现 → P1-5b 堵上）**

**攻击（v2 发现时未修复，此处保留）**：`A` 跑到第 `m` 次调用时产生了一条违规回执
`r_{m-1}`（比如带了 `token` 参数）。`A` **把这条整条删掉**，用前 `m-1` 条出证，
并把**同一条截断链**交给验证者。

**为什么原三层都拦不住**：剩下的 `m-1` 条是一条**真链** —— 结构自洽（`seq` 0..m-2
连续、`prev` 咬合）、逐条签名有效、`trace_root` 由它自己算出。`trace_binding` 比较的
是「证书绑的链」与「送检的链」，而攻击者让**两边同时**是截断的那条，于是相等。
**这不是"再比一次"能补的**：任何只基于**交付链本身**的检查都无法知道「后面还有没有」。

**对策（已实现）**：网关在**会话末端**签一条 `ToolSeal{count, trace_root, ts, keyid, sig}`
（`policydsl/trace.py::ToolGateway.seal`，域分隔 `pop-trace-seal-v1`），随证书载荷顶层
`trace_seal` 字段一起走。验证方（`verify_cert.py` 卡 **3d**）核对三件事：

1. `seal.sig` 由网关钥签出（链下 Ed25519，与回执验签同一道关）；
2. `seal.trace_root == 证书/证明承诺的 trace_root`；
3. 手上有链时（`--receipts`）：`len(chain) == seal.count ∧ trace_root(chain) == seal.trace_root`。

攻击者于是只剩两条路，都不通：拿**原始** seal 配截断链（`count`/链尾对不上），
或为截断链**新签**一条 seal（没有网关私钥）。**缺口用例已翻转为「截尾必须被拒」**：
`tests/test_trace.py::TestVerifyCertTraceBinding::test_tail_truncation_is_rejected`
（(a) 原 seal + 截断链、(b) 冒充 keyid 的伪造 seal、(c) 索性不带 seal，外加"没截尾时全 PASS"的对照）。

**设计取舍（如实登记）**：

- **不改电路**：`trace_root` 本来就在电路内计算并进公开值，「这条证明绑的是哪条链」
  已有电路保证；seal 补的是「网关说这条链到此为止」，那是一个**签名**问题。按本项目
  「结构入电路、签名在链下」的既有分工放在链下（`policydsl/trace.py` 的"三层"表因此
  多出第四行"链下 + 证书"）。这偏离了计划稿 `plan-p0p1p2.md` 待办 T4 里
  「+ 电路内对 seal 的结构校验」的设想。
- **seal 在载荷顶层，不在 `outcome` 里**：`outcome` 是**证明公开值的镜像**（验证方逐字段
  比对），而电路里没有 seal —— 放进 `outcome` 会让**每一张带真实证明的证书**都对不上。
- **残留信任边界 A4 传染**：seal 是**网关的**陈述。网关作恶（签一条与真实执行不符的回执，
  §5.4 已列为最弱一环）时，它可以为截断链直接签 seal。**seal 把"信不信证明者"换成
  "信不信网关"，没有消除信任**，只是把它挪到一个本来就必须被显式信任的实体上。
- **没有网关公钥就核不了**：`--gateway-key` 缺席时，验证方分不开「出证方没承诺」与
  「承诺了但没给我看」，此时 3d 记为 **PASS + 「截尾不可排除」(skipped)** —— 与 3c
  「只有一份检材」的诚实口径一致。**给了网关公钥却没有 `trace_seal` 的证书判 FAIL**
  （既然知道这段会话有网关，就该有它的末端承诺）。所以：

> **结论：验证方要拿到截尾保证，必须持有网关公钥（`--gateway-key`）。
> 只给 `--receipts` 时，链尾摘要可比对，但「有没有被截尾」仍未排除。**

登记见 [`plan-p0p1p2.md`](plan-p0p1p2.md) §9 待办 **T4（P1-5b）**；
L3 的命题把 `Pr[截尾攻击]` 单列一项 —— 该概率现在由 `Adv^{forge}_{Ed25519}` 界定
（伪造 seal 的代价），而不是"无覆盖"。

### 5.4 其它

| 项 | 状态 |
|---|---|
| **网关作恶**（A4） | 本模型**最弱的一环**：网关可签一条与真实执行不符的回执。它不是密码学结论，是**信任假设** —— 网关须是被显式信任的第三方 |
| **出证方私钥托管** | 当前是文件（口令可选）；**HSM/KMS 待补**（A7） |
| **链上最终性** | `groth16` 验证合约**未落地**（P1-7 缺 ≥64 GB 机器，见待办 T1）；当前链上只存摘要，**不验证证明** |
| **`budget_bound(tokens)` 语义** | 电路内按**固定空白字节集** `{0x20,09,0a,0b,0c,0d}` 切分计数，**不**依赖 Unicode White_Space（该定义随 Unicode 版本漂移），也**不**假称是任何真实分词器。口径变更**不兼容**：`policy_hash` 随之变化 |
| **规则语义** | 正则为受支持子集 + ASCII 语义；长度按码点；`int`/`float` 仅规范子集（超集输入按子集规则拒绝） |
| **重放** | 无 `n` 的证书可被重放（危害是会话计数）；带 `n` 的证书重放可被 `NonceStore` 检出 |
| **非目标** | 不证明「模型推理本身」（P1-6 若落地则部分覆盖）；不覆盖训练数据/模型卡（EU AI Act Art.11 等） |

---

## 6. 代码落点对照表

| 引理 / 性质 | 实现 | 测试 |
|---|---|---|
| 判定函数（golden ⇄ 电路） | `policydsl/evaluate.py` ⇄ `circuits/types/src/lib.rs::evaluate` | `tests/test_rules_incircuit.py`（9）、`cross_validate` host/prove 14/14 |
| **L1** 策略绑定 | `circuits/program`（guest 内算）、`policydsl/verifier.py::check_policy_binding` | `tests/test_policy_binding.py`（22） |
| **L2** 响应绑定 | `policydsl/commit.py::response_binding`、`policydsl/challenge.py` | `tests/test_binding.py`（19） |
| **L3** 轨迹绑定 | `policydsl/trace.py`、`circuits/types::verify_receipt_chain`、`verify_cert.py` 3c | `tests/test_trace.py`（29） |
| **L4** 脱敏健全性 | `policydsl/commit.py`、`circuits` 内 `mask_covered` | `tests/test_commit.py`（12） |
| **L5** 账本 + 锚定 | `policydsl/anchor.py`、`contracts/Anchor.sol` | `tests/test_anchor.py`（4）、`test_anchor_chain.py`（22） |
| 证书签名（A3/A7） | `policydsl/cert.py::Ed25519Signer`、`policydsl/keys.py` | `tests/test_cert.py`（19） |
| 证明模式诚实标注 | `cert.PROOF_MODE_HIDING`、`verifier.artifact_proof_modes` | `tests/test_verifier_only.py`（8） |
| **L6** 组合义务 | ⏳ 未实现（P1-6） | — |

**回归总盘**：`python3 -m unittest discover -s tests -t .` → **261 passed / 5 skipped**（skip 均为设计内）。

---

## 7. 实验对照（可复现）

| 定义/引理 | 对应实验 |
|---|---|
| Completeness | `scripts/prove_policy.py`、`cross_validate.py` host/prove 14/14 |
| **G_Sound** | 违规向量出证得到 `passed=false`；「空策略证明 + 真策略哈希」攻击回归必须失败 |
| **G_Bind_pol** | `verify_cert.py` 的 `policy_hash` 卡；`test_policy_binding.py`（含证明层 opt-in） |
| **G_Bind_resp** | `verify_cert.py --response T′`（3b）；换 `T′`/换 `n`/域分离/空 nonce 四组反例 |
| **G_Bind_trace** | `verify_cert.py --receipts [--gateway-key]`（3c）；删/换/重排/伪造链尾四组反例；`verify_cert.py --gateway-key`（3d）**截尾必须被拒**（原 seal+截断链 / 伪造 seal / 不带 seal 三路，§5.3） |
| **G_Priv** | Leak 实验（`private_demo`、`test_private_output_no_leak`）；上界论证见 §5.2 |
| **G_Redact** | `TestMaskCoverage`（伪造 span → `mask_covered=false`） |
| **G_Ledger** | `TestAnchorLedger`（链篡改检出）、`TestAnvilEndToEnd`（真链读回） |
| 端到端 | `scripts/verify_session.py` 全 PASS（含真实 SP1 证明） |
