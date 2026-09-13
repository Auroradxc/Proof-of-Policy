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
| `T` 确由某个真实 LLM 产出 | **不在任何层**（非目标，见 §6） | 健全性不受影响。P1-6 提供了一个**代理推理证明**（`pop-infer`，确定性 MLP 前向）来演示组合机制，但那是 stand-in，**不是**"某真实 LLM 跑过"的证据（L6.2） |
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

### L6 组合义务（P1-6）—— 归约到 A1 + A2

> 代理推理证明（`pop-infer`）是 **stand-in**，验收的是**组合机制**而非成本结构 ——
> 见 §L6.3 与 [`../bench/results/compose.md`](../bench/results/compose.md)。

**命题**：设 `C` 是验证方接受的组合证书，其两半各自通过验证、绑到**同一条**送达
`T′`、且来自**不同**的 vkey。若 `C.parts[policy].outcome.passed = true` 且
`delegated` 为空，则

```
T′ ⊨ π        且        M_infer(T′) = 证书承诺的输出
```

其中 `M_infer` **不是**「存在某个模型」，而是 `vkey_infer` 所承诺的**那一个**程序 ——
代理域里权重由编译期常量种子生成、编进 guest（§2.5c），所以模型身份由 vkey 决定，
证明者选不了。

**论证**（在 A1、A2 下）：组合证书的每一半都是 zkVM 的确定性执行输出（A1），
所以每一半的公开值**唯一**等于对应 guest 程序在对应输入上的执行结果。于是：

1. **策略那一半**给出 `T′ ⊨ π` —— 论证与主定理逐字相同（策略半的公开值里
   `response_binding` 由 `(nonce, T′)` 决定，而验证方的第 6 步*现场重算*它，
   故被证明的那条串**就是**送达的 `T′`，不是证明者另选的串）。
2. **推理那一半**给出「图内前向确实是这么算的」：`input_binding` 是
   `SHA256(domain ‖ "input_binding" ‖ nonce ‖ 各输入分量)`，而验证方第 7 步
   由 `T′` **重新导出输入、重算绑定**；`model_hash` 同理由本仓库那份模型规格重算。
   要在此基础上换成别的模型 / 别的输入，需要 A2 下的 SHA256 碰撞。

**为什么键分离是命题的一部分，而不是工程细节**：若两半可以由**同一个**程序产生，
则「这份证明属于哪一半」在验证方无判据 —— 攻击者可以拿一份策略证明充当推理半
（或反之）而通过全部逐 half 的检查。`verify_composite` 第 4 步显式要求
`vkey_policy ≠ vkey_inference`；每个 guest 入口各自断言 `job_domain == DOMAIN_*`
（`pop-program` 只收 Public/Private，`pop-infer` 只收 Infer），把这条要求钉进
**电路**而不是只写在 Python 里。给了 `expected_vkeys` 时还额外核「它们就是你信任的
那两个程序」——没给时 `detail` **如实注明**「未提供期望 vkey」，不假装核过了。

**替换任一子证明为什么被拒**：第 2 步把证明文件字节的 SHA-256 与证书承诺比对
（换文件即失败）；第 3 步跑验证器，并把**解出的 outcome 与原样转述的 outcome**
逐字段比对、vkey 逐字节比对（换证明即失败）；第 6 步要求四方 `response_binding`
一致，其中一方是**现场重算**（两半绑不同 `T`、或送达 `T′` 与证明不符，都失败）。

**代码落点**：`policydsl/compose.py::verify_composite`（8 步）、
`circuits/types::job_domain`、`circuits/program` 与 `circuits/infer-program` 的入口断言、
`scripts/compose_proof.py`、`tests/test_compose.py`。

#### L6.1 覆盖率：结论形式与主定理不同

组合层的 `satisfied` **额外要求 `delegated` 为空**。`delegated` 非空意味着策略里有规则
**没被这份证明判定**（P2-9 的语义规则）—— 此时组合层**不下合规结论**，而不是
"当作过了"。少了这一条，组合证书会成为「把没判的规则当判过了」的新通道，
正是 P0-1 的形态；且这属于 `合规 = PASS` 那一侧（L7），不属于主定理的和式。

#### L6.2 不保证

* **推理那一半是代理**：`pop-infer` 里是一个 16→32→4 的定点 MLP，权重由编译期常量
  种子生成、**编进程序**（因此被 vkey 承诺 —— 比 P2-9 的 ezkl 委托更强）。它是
  结构同构的 stand-in，**不是 zkAgent**（D1：zkAgent 源码不可得）。
* **不保证模型质量**：与 L7 第 ② 条同源。这一半证的是「**这张**图在**这条**响应上
  确实算出**这个**输出」，与「这张图好不好」无关；没有数据训练过它。
* **不保证成本结论**：见下。

#### L6.3 实验能证什么、不能证什么（如实标注）

计划里的假设是「**组合成本 ≈ 两者之和，且由推理证明主导**」。本机实测的结论是
**前半成立、后半不成立**：合成与联合验证不引入额外证明（合成 5.0 ms，联合验证
53.8 s —— 主导项是两次 vkey setup，不是比对），出证时间确实是两半之和
（127.3 + 110.8 = 238.1 s）；但代理模型太小 —— 推理半 **8.3 万**周期，
反而**低于**策略半的 **64.4 万**周期 —— 两半都被 zkVM 的**固定开销**
（setup 与证明器启动）主导，「推理主导」在代理规模下**观察不到**。真实 zkAgent
推理证明的规模与这里差若干数量级（`bench/comparison_zkagent.md`）。

**所以这份实验验证的是组合机制，不是成本结构。** 换上真 prover 后组合层开销仍是
毫秒级 —— 它不随子证明规模变化。数字见 `bench/results/compose.md`。

**反例（`tests/test_compose.py`）**：①换证明文件 / 缺失文件 ②同 vkey / 非期望 vkey
③换模型 / 换输入 ④两半绑不同 `T` / 送达 `T′` 与绑定不符 ⑤形状/模式/域/policy_hash
重编译不符 —— 全部必须被拒。

### L7 语义委托健全性（P2-9）—— 归约到 A2 + A6

> 全文见 [`design-semantic-rules.md`](design-semantic-rules.md)（含三个信任边界条件、
> 与 zkML 的关系、以及"不保证"清单）。

**命题**：设 `π = π_in ∧ π_sem`（`π_in` 入电路、`π_sem` 被委托给 ezkl）。
若 `Verify` 接受且 `verify_cert.py` 报出 **`合规: PASS`**，则 `T′ ⊨ π`。

**论证**（在 A1、A6 下）：`π_in` 部分同主定理。`π_sem` 部分要求验证方对每条被委托的
规则跑通 `semantic.verify_companion` 的六步 —— 第 2 步把证书声明的
`{vk_sha256, onnx_sha256, threshold_bp, direction}` 逐字段钉在**电路公开值**里；
第 3 步把证明字节钉在证书承诺的哈希上；第 4 步核本地 `vk` 哈希并跑 ezkl 验证器；
第 5 步要求公开实例的输入部分 `== encode(T′)`；第 6 步才比阈值。任一步失败即
`ok=False`，且 `verify_cert.py` 对 `delegated` 非空却找不到陪伴证明的情形
**默认 FAIL**（fail closed）。故 `T′ ⊭ π_sem` 时不可能得到 `合规: PASS`。∎

**为什么必须"分开呈报"**：`RESULT`（证书真伪）与 `合规`（策略是否满足）是两件事 ——
一张如实记录违规的证书同样是**真**证书（`--expect violate` 的演示依赖这一点）。
而 `outcome.passed` **只覆盖电路判得了的部分**，`π_sem` 不在其中。少了 `合规` 行，
一张 `passed=true` 而语义规则没过的证书会被读成合规，那正是 P0-1 的形态。

**代码落点**：`policydsl/semantic.py::verify_companion`、
`circuits/types/src/lib.rs::DelegatedConstraint`、`scripts/verify_cert.py` 检查 3e、
`tests/test_semantic.py`（29）。

**不保证**：① **响应内容保密** —— ezkl 的公开实例含 `encode(T)`，而 `encode` 对收录
字符**单射**（反查 `VOCAB` 即可恢复原文），故含语义规则的策略**只支持公开模式**，
私有模式在电路内 panic；② 模型质量（训练数据/分布外/投毒）—— 密码学不判断模型好不好；
③ 定点近似的决策边界（`|P-θ| < 1/128` 处可能与浮点参考不符）；
④ v1 只有单一模型，N 条规则共用同一份 `proof.json`。

### L8 跨证书一致性（P2-10）—— 归约到 A1 + A2（Merkle 的抗第二原像）

**命题**：设 `P` 是一份**被接受**的会话聚合证明，公开值含
`(policy_hash, cert_count, merkle_root, session_binding, trace_root, sealed_count, seal_keyid)`，
交付的证书集为 `E = (e₀ … e_{n-1})`。若 `verify_session_proof` 返回 `ok=True`
（给了 `proof` 时还要求密码学验证通过、且公开值解出的 outcome 与交付 outcome 逐字段一致），则：

1. `E` 中每张证书的 `policy_hash` 相同，且（给了策略包/策略时）等于验证方**现场重编译**
   得到的那个 —— 这组证书确实都出自同一策略，而那策略就是验证方手上这个；
2. `eᵢ` 的 `chain.index = i` 且 `chain.prev = leaf(eᵢ₋₁)`（`leaf(e₀) = genesis`）——
   交付的顺序与链上的顺序一致、**中间没有缺口**；
3. `n = cert_count`，且由这 n 个叶子算出的 Merkle 根 `= merkle_root` ——
   于是**交付集就是被证明的那一组，不多不少**。

**论证**（在 A1、A2 下）：(1)(2) 是电路内的 `assert!`，产不出证明即失败（A1 保证
公开值唯一等于 guest 的确定性执行结果，证明者选不了）。(3) 的第一半由公开值
`cert_count` 与交付集长度比对得到；第二半由「验证方用**交付的**证书重算根」与承诺比对
得到 —— 若交付集 ≠ 被证明集，则两者的根必须相同，即找到 Merkle 的一个第二原像，
与 A2 矛盾。∎

**为什么第 (3) 条非有不可**（已实测的两端行为）：`[0..k]` 这样的**前缀**仍然满足
`index` 连续、`prev` 相连、策略全同、seal 齐全 —— **电路本身接受一个被砍掉尾巴的证书集**
（这正是 L3/§5.3 的截尾问题在会话层的形态）。拦住它的唯一一步就是根比对。反过来，
**挖中间 / 换序 / 换一张**则在电路内就断（`index`/`prev` 对不上），出不了证明 ——
两类攻击由两个不同的机制拦下，不能合并陈述。

**代码落点**：`circuits/session-program/`（guest③，vkey 与另两域不同）、
`circuits/types/src/lib.rs::run_session`、`policydsl/session.py::verify_session_proof`、
`scripts/prove_session.py`、`tests/test_session.py`（38）。

**不保证 / 诚实边界**：

- **不验网关签名**。`SealView` 里没有 `sig` —— zkVM 内没有网关公钥。电路内只断言
  「每张证书都带 seal」+「`keyid` 全同」，公开的 `(sealed_count, trace_root)` 是链尾证书
  **自报**的承诺；**它的真伪由链下 `trace.verify_seal` 判**（L3 / §5.3）。因此
  `verify_session_proof` 不给 `keyring`/`receipts` 时会**如实注明「seal 签名未验」**，
  那一行不该被读成「已核过」。
- **覆盖范围只有一个 run、且只有链上证书**。没有 `streaming.chain` 的证书（含一个 run 的
  权威 `on_llm_end`）不属于任何 run —— 整条会话的核对（锚定、工具回执、权威证书）
  仍然是 `verify_session.py` 的职责，本引理不覆盖。
- **`ok` 与 `satisfied` 必须分开读**：`ok` = 「这次聚合是真的」，`satisfied` = 「被覆盖的
  证书全都 `passed`」。一张如实记录违规的聚合证明**同样是真**的 —— 与 L7 同一条口径。
  另注：`satisfied=true` 只说**被聚合的那批**证书合规，**不等于**整条会话合规
  （见上一条：链外证书不在其中）。

### L9 多证明者责任划分（P2-11）—— 归约到 A1 + A2 + A3（签名不可伪造）

**命题**：设 `M` 是一张**被接受**的多证明者证书（`verify_multiparty` 返回 `ok=True`，
且给了 `keyring`、`verify_proofs=True`），其 `plan` 把策略 `π` 切成三个角色切片
`π_model ∪ π_gateway ∪ π_deployer = π`（两两不交）。则：

1. **每一段都真的被证过**：非空切片 `π_r` 携带的证明的公开值解出的 `policy_hash`
   `= slice_sha256(π_r)`，且密码学验证通过 —— 证明的内容就是**它自称那一段**，
   不是别的段、也不是整条策略；空切片必须**不带**证明（多带一份即拒）；
2. **三段都出自同一个 guest**：所有切片的 vkey 相同（给了 `expected_vkey` 时还要求等于它），
   且证明模式为 `public`（切片证明不接受私有模式）；
3. **同一条响应、同一条轨迹**：三段的 `response_binding` 相同，且与验证方由**送达的 T′**
   现场重算的一致；三段的 `trace_root` 相同（回执链**全量**发给每个切片，否则这条没法核）；
4. **每个角色都签了自己那一段**：`part` 的自报字段（`rules` / `slice_sha256` / 证明引用 /
   `plan_digest` / `policy_hash` / `response_binding`）被该角色的 Ed25519 签名覆盖，
   且三个 role 的 keyid **两两不同**；
5. **（给了 `policy`/`policy_pack` 时）划分就是验证方手上那条策略的划分**：现场
   `compile_policy` 得到的哈希与证书的 `policy_hash` 相等，且 `plan_of(policy)` 与证书里的
   `plan` **逐字段相等**。

**论证**：(1) 的密码学部分诉诸 A1（公开值唯一等于 guest 的确定性执行结果）+
zkVM 可靠性；「证明段 == 自称段」那一步是**验证方自己**重算 `slice_sha256` 后与
公开值比对 —— 它核的是两个**声明**之间的一致性，不需要密码学，因此**离线预检**
（`verify_proofs=False`）里也照样生效。(2) 是 vkey 与 `.meta.json` 的逐字段比对。
(3) 由 `verify_response_binding` 的多来源比对（≥2 来源）与 `trace_root` 的相等得到。
(4) 诉诸 A3（Ed25519 EUF-CMA）：`part` 的签名原像是 `part.claim()` 的规范 JSON，
多带或漏掉一个字段都会让原像变，签名即失效；role 与 keyid 的**两两不同**保证了
「这一段是谁证的」可判定。(5) 是验证方现场重编译并与交付的 `plan` 比对 —— 与
P0-1「空策略证明 + 真策略哈希」攻击的同一条防线。∎

**为什么「单角色切片被换」有三个不同的拦点，而不是一个**（验收②的展开）：

| # | 攻击 | 被谁拦下 |
|---|---|---|
| ① | 该角色把 `rules`/`slice_sha256` 换成另一段的（**不改 plan**） | 命题 (4)：`part` 自报与 `plan` 对不上，当场拒 |
| ② | 该角色改 `plan` 以迁就自己伪造的切片 | 命题 (4)：`plan_digest` 进了签名原像，而另外两个角色签的是**改前**的 plan —— 它们的签名立刻失效 |
| ③ | **三方合谋**：三把键一起改 plan、一起重签 | 只剩命题 (5)：不带 `policy_pack` 时签名层**完全自洽**，证书会通过；带上策略包即被拒 |

第 ③ 条是这条引理**必须如实写下来**的边界：**三方合谋在签名层是不可检出的** ——
因为「谁拥有哪几把键」这件事本身就在证书之外。`test_colluding_roles_rewritten_plan_needs_the_pack`
把这条钉成「不带策略包时**会通过**」，免得日后有人把它读成「签名能挡住合谋」。

**代码落点**：`policydsl/multiparty.py::verify_multiparty`（七步）、
`policydsl/compile.py::compile_slice_policy`、
`scripts/prove_multiparty.py`、`tests/test_multiparty.py`（44）。

**不保证 / 诚实边界**：

- **「聚合证明」不是递归聚合**。是 N 份切片证明（共享同一个 vkey）**加**一份把它们拴在
  一起的证书，**验证成本 O(N)** —— 本仓库没有做递归聚合，也不主张做到了。
- **三个角色共享同一个 `pop-program`（同一个 vkey）**。各持一把键只是**责任划分**，
  不是「不同角色用不同的电路」。切片对 guest 而言就是一条普通策略，因此**在盘的旧证明
  继续有效**（换 ELF 会让它们全废）。
- **`ok` 与 `satisfied` 分开读**（同 L7/L8 口径）：`satisfied` = 「每段都 `passed` 且
  `delegated` 为空」。语义切片归部署方，而那段**不判定**它、只把它记进 `delegated`，
  所以**含语义规则的策略永远不会**因为这一段就 `satisfied` —— 合规结论要另外合取
  ezkl 陪伴证明（**L7**）。一张如实记录违规的证书**同样是真**的。
- **本模块不产生陪伴证明**，也不做「整条会话」的核对（那是 L8 / `verify_session.py` 的事）。

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
**覆盖范围**：`keyword_block` / `normalized_keyword_block` / `length_bound` / `pattern_block` /
`format_check` / `tool_arg_guard` / `budget_bound` 七类**均已入电路**（`pop-types::evaluate`，
与 Python golden 交叉验证 **host 19/19 · prove 19/19**）。
其中 `normalized_keyword_block`（P2-9b）的**折叠表是约束的一部分**（`fold` 字段进规范字节、
进 `policy_hash`）：证明者既不能把表换成「不折叠」，也不能让电路按别的表判 —— 换表就是换策略，
指纹会变。电路另有一道结构校验（未知版本/表过大/替换值非 ASCII ⇒ panic），
它防的是**手写** `ProofRequest` 绕过编译期检查的那种输入（见 `05` §2.3）。
**另有一类不在上式的和里**：`semantic_bound`（P2-9）**不由本电路判定**，而是被
**委托**给 ezkl 并由验证方合取 —— 它有自己的引理 **L7**，结论形式是
`合规 = PASS`（**不是** `outcome.passed`）。把 L7 混进上式会掩盖它真正的失败形态：
不是"证明被攻破"，而是"**漏判却看起来全绿**"。
**未覆盖**：`budget_bound(tokens)` 的分词语义（见 §5 末条与 `01-policy-dsl.md` §2 的口径说明）。

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
| **语义规则的隐私** | 含 `semantic_bound` 的策略**只支持公开模式**：ezkl 公开实例含 `encode(T)`，而 `encode` 对收录字符**单射**（可反查 `VOCAB` 恢复原文）—— 这是格式的必然，不是疏漏（L7 的"不保证 ①"） |
| **模型质量** | L7 只证「用的是**这张**图、输入是**这条**响应、分数满足阈值」，**不证「这张图是好的」** —— 训练数据偏置、分布外文本、投毒模型一律不管；阈值是策略作者的判断，不是安全参数 |
| **非目标** | 不证明「模型推理本身」的**通用**命题。P1-6 覆盖的是**代理模型**（`pop-infer` 里那张定点 MLP）的前向完整性 —— 换成真 LLM 的推理证明属于另一件事（D1）；不覆盖训练数据/模型卡（EU AI Act Art.11 等） |

---

## 6. 代码落点对照表

| 引理 / 性质 | 实现 | 测试 |
|---|---|---|
| 判定函数（golden ⇄ 电路） | `policydsl/evaluate.py` ⇄ `circuits/types/src/lib.rs::evaluate` | `tests/test_rules_incircuit.py`（13）、`cross_validate` **host 19/19 · prove 19/19**（2026-09-12 整批重跑） |
| **L1** 策略绑定 | `circuits/program`（guest 内算）、`policydsl/verifier.py::check_policy_binding` | `tests/test_policy_binding.py`（22） |
| **L2** 响应绑定 | `policydsl/commit.py::response_binding`、`policydsl/challenge.py` | `tests/test_binding.py`（19） |
| **L3** 轨迹绑定 | `policydsl/trace.py`、`circuits/types::verify_receipt_chain`、`verify_cert.py` 3c | `tests/test_trace.py`（39） |
| **L4** 脱敏健全性 | `policydsl/commit.py`、`circuits` 内 `mask_covered` | `tests/test_commit.py`（12） |
| **L5** 账本 + 锚定 | `policydsl/anchor.py`、`contracts/Anchor.sol` | `tests/test_anchor.py`（4）、`test_anchor_chain.py`（22） |
| 证书签名（A3/A7） | `policydsl/cert.py::Ed25519Signer`、`policydsl/keys.py` | `tests/test_cert.py`（19） |
| 证明模式诚实标注 | `cert.PROOF_MODE_HIDING`、`verifier.artifact_proof_modes` | `tests/test_verifier_only.py`（8） |
| **L7** 语义委托（P2-9） | `policydsl/semantic.py`、`scripts/ezkl_prove.py`、`circuits/types::DelegatedConstraint`、`verify_cert.py` 3e | `tests/test_semantic.py`（29，含 6 条反例；真·端到端由 `POP_TEST_EZKL=1` 打开） |
| **L6** 组合义务（P1-6） | `policydsl/compose.py`、`circuits/infer-program`（guest②）、`circuits/types::job_domain`、`scripts/compose_proof.py` | `tests/test_compose.py`（48，含 5 组反例 + 4 条驱动接线回归；真·端到端由 `POP_TEST_COMPOSE=1` 打开） |
| **L8** 跨证书一致性（P2-10） | `circuits/session-program`（guest③）、`circuits/types::run_session`、`policydsl/session.py::verify_session_proof`、`scripts/prove_session.py` | `tests/test_session.py`（38，含两种挖法的反例；真·端到端由 `POP_TEST_SESSION=1` 打开） |
| **L9** 多证明者责任划分（P2-11） | `policydsl/multiparty.py::verify_multiparty`、`policydsl/compile.py::compile_slice_policy`、`scripts/prove_multiparty.py` | `tests/test_multiparty.py`（44，含两条验收判据与「三方合谋」边界；真·端到端由 `POP_TEST_MULTIPARTY=1` 打开） |

**回归总盘**：`python3 -m unittest discover -s tests -t .` → **554 passed / 15 skipped**（2026-09-13 复跑；
skip 均为设计内，含 P2-9 那例要真出 ezkl 证明的端到端 —— 由 `POP_TEST_EZKL=1` 打开；P1-6 那 5 例
要真出两份 SP1 证明 —— 由 `POP_TEST_COMPOSE=1` 打开；P2-10 那例要真出一份会话聚合证明 ——
由 `POP_TEST_SESSION=1` 打开。三组均已单独实测通过；另有 3 例由 `POP_TEST_PROOF=1` 打开
（2 例证明层 + 1 例证明服务的真 vkey 出证，**三例均实测通过**）。最后那 1 例在本机
11.7 GiB 上是**勉强过**：与别的进程并跑时被 OOM killer 杀在 9.7 GiB 常驻，腾空后重跑
通过（171.1 s，`MemAvailable` 一度只剩 0.15 GiB）—— SP1 core 证明的固定地板是
~10.15 GiB（见 `bench/results/proofs.md`）。服务侧已把这种失败翻成一句
「多半是内存不足 + 怎么核实」（`policydsl/service.py::failure_reason`）。

---

## 7. 实验对照（可复现）

| 定义/引理 | 对应实验 |
|---|---|
| Completeness | `scripts/prove_policy.py`、`cross_validate.py` **host 19/19 · prove 19/19**（2026-09-12 整批重跑） |
| **G_Sound** | 违规向量出证得到 `passed=false`；「空策略证明 + 真策略哈希」攻击回归必须失败 |
| **G_Bind_pol** | `verify_cert.py` 的 `policy_hash` 卡；`test_policy_binding.py`（含证明层 opt-in） |
| **G_Bind_resp** | `verify_cert.py --response T′`（3b）；换 `T′`/换 `n`/域分离/空 nonce 四组反例 |
| **G_Bind_trace** | `verify_cert.py --receipts [--gateway-key]`（3c）；删/换/重排/伪造链尾四组反例；`verify_cert.py --gateway-key`（3d）**截尾必须被拒**（原 seal+截断链 / 伪造 seal / 不带 seal 三路，§5.3） |
| **G_Priv** | Leak 实验（`private_demo`、`test_private_output_no_leak`）；上界论证见 §5.2 |
| **G_Redact** | `TestMaskCoverage`（伪造 span → `mask_covered=false`） |
| **G_Ledger** | `TestAnchorLedger`（链篡改检出）、`TestAnvilEndToEnd`（真链读回） |
| **L7 语义委托** | 六条反例：换 ONNX、换 vk、改阈值、翻转方向、换证明文件/换响应、图外自算特征 —— 全部必须被拒；反向对照（良性文本 `合规: PASS`、同形异义文本 `合规: FAIL` 而 `RESULT: PASS`）见 `design-semantic-rules.md` §7 |
| **L6 组合义务** | 五组反例：换证明文件/缺失、同 vkey/非期望 vkey、换模型/换输入、两半绑不同 T/送达 T′ 不符、形状/模式/域/policy_hash 重编译 —— 全部必须被拒（`tests/test_compose.py`）；成本与「推理是否主导」的实测见 `bench/results/compose.md` |
| **L8 跨证书一致性** | 混入异策略证书 / 挖中间 / 换序 / 尾截断（**电路接受、只有根比对拦得住**）/ 伪造根 —— 全部必须被拒（`tests/test_session.py`） |
| **L9 多证明者** | 验收①：缺任一角色签名（或空签名表 / 缺 part / 重复 part）必须被拒；验收②：单角色切片被换（该角色拿自己键重签 / 谎报切片为空 / 单独改 plan / 改 `plan_digest`）必须被拒；**三方合谋改 plan 在不给策略包时会通过、给了即被拒**（如实钉住） |
| 端到端 | `scripts/verify_session.py` 全 PASS（含真实 SP1 证明） |
