# 定理 D 与定理 G 的证明底稿（论文附录 A 候选）

> **状态**：T3 证明底稿，2026-11-01，基于提交 `4988ee2`。
>
> **边界**：本文件只写证明，不改
> [`../certificate-binding-framework.md`](../certificate-binding-framework.md) 的定理陈述、
> 不改代码、不改 [`../../paper/`](../../paper/)。框架文档冻结的是定理 A–F；
> **定理 G 不在框架文档里**，本文按 T3 任务书与
> [`../../paper/proof-of-policy.md`](../../paper/proof-of-policy.md) §4.2 的 NFA 契约给出陈述，
> 供论文 owner（P）合并时统一编号。
>
> **口径**：本文把“标准构造”和“本框架新增的组合”分开标注。Thompson 构造、
> Pike VM、随机预言机下的隐藏论证、猜测熵界都是标准的；本框架的新意只在
> “把策略侧接进同一套 D-privacy 游戏、给出带盐承诺的实例化、并把两个泄露通道
> 分开陈述”。论文正文不要把标准界包装成新定理（框架文档 §14 的纪律）。
>
> **标记约定**：
> - **[纸面证明]**：本文给出完整论证。
> - **[假设]**：证明依赖、但本文不证明的前提。
> - **[实验证据]**：由测试/差分模糊提供的经验证据，不能替代证明。
> - **[证明债]**：当前无法严格证明、必须写进论文限制的部分。

---

## 0. 结论摘要

### 0.1 定理 D

定理 D 的充分条件是三条：

1. 除承诺外的公开值只通过披露函数 `D(π)` 依赖 `π`；
2. 证明系统 witness-hiding；
3. 策略绑定是对 `D(π)` 的隐藏承诺。

三条合起来给出 D-privacy。证明是一个五步混合论证（§5）：把真实证明换成模拟器、
把真实公开值换成模拟器、利用承诺隐藏性把 `π₀` 的承诺换成 `π₁` 的承诺，再反向
走两步回到 `π₁` 的真实视图。

带盐承诺把条件 3 落到代码：

```
h_π = SHA256( canonical_json( π 的约束 ∪ {policy_nonce: s} ) )
```

盐进规范字节、进 `policy_hash`；不进证书载荷的 `policy.id/version`；权威在 P-PP
登记 `h_π`，审计时开示 `(π,s)`。但它**只关闭公开值通道**。`core` 证明工件仍可能
泄露 `spec_canonical` 与 `response`（因而同时泄露 `π` 和 `s`），必须靠
`groth16/plonk` 的 witness-hiding；披露层级（`PrivateViolation.rule/kind`、
`delegated`）是第三条通道，必须由 `D(π)` 显式覆盖或抑制。

### 0.2 定理 G

定理 G 分三部分：

- **(a) 语言保持**：解析器 + Thompson 构造满足 `L(NFA(p)) = L_re(p)`；
- **(b) 搜索语义**：Pike VM 的 unanchored 状态并集恰好实现“存在子串匹配”；
- **(c) 跨层一致**：Python 参考匹配器与 Rust 电路匹配器在同一份 NFA spec 上
  互为精化（bisimulation），因而 `pattern_block` 的判定一致。

(a)(b) 是纸面证明；(c) 的算法层是纸面 bisimulation，**实际 Rust 代码**的逐行
正确性仍是实验债：任务书里的 E12（差分模糊测试）对应仓库计划中的 P2-03，
截至本底稿 `tests/test_fuzz_*.py` **尚未落盘**，所以 E12 只能列为“待完成的实验
证据”，不能当作已覆盖。

### 0.3 必须先说清的五处限制

1. **D5 的 `T₀,T₁` 字面读法不成立**：`b = B(n,T)` 是公开值，`T₀ ≠ T₁` 时
   `b` 直接区分两份证书。定理 D 的游戏必须固定同一条工件 `T`（或至少固定
   public T-view）。§2.2 给出修正读法。
2. **当前公开输出不满足条件 1**：公开模式的 `violations[].rule/kind/evidence`
   与 `delegated` 依赖策略结构。只有 L2 披露层级（或把这些字段纳入 `D(π)`）
   才满足条件 1；见 §7。
3. **`core` 不满足条件 2**：它不是 witness-hiding；见 §7.2 与
   [`../sp1-zk-audit.md`](../sp1-zk-audit.md)。
4. **枚举界 `|Π_c|/2^{λ+128}` 的指数需要核对**：定性结论（盐把工作量乘以
   `2^128`）成立，但精确的聚合上界是 `|Π_c|/2^{λ-128}`（穷举盐）或
   `q_s/2^128 + |Π_c|q_s/2^λ`（每个候选猜 `q_s` 个盐）；见 §8.4。
5. **空字符类有实现级缺口**：`[^\d\D]` 被解析成 `Lit([])`，而 `Lit([])` 同时被
   用作“空连接 = ε”，于是 NFA 判 `true`，Python `re.search` 判 `false`。
   这是定理 G 的一个必须写进证明债的边界；见 §12.3 与 §19。

---

# 第一部分：定理 D（策略隐私与带盐承诺）

## 1. 记号与代码锚点

沿用框架文档 §2 的记号，并补上证明需要的几个：

| 记号 | 含义 | 代码锚点 |
|---|---|---|
| `λ` | 安全参数；本文 `λ = 256`（SHA-256 输出） | — |
| `Π` | DSL 可表达的策略包全集 | `Policy`，[`model.py`](../../policydsl/core/model.py) |
| `π` | 一条策略包（witness） | `policy_packs/*.json` |
| `D: Π → 𝔻` | 披露函数（验证者被允许知道的策略部分） | 本文定义；L0/L1/L2 见 §7.3 |
| `M` | 工件空间（响应文本等） | `ProofRequest.response` |
| `R(π,T) ∈ {0,1}` | 判定关系；`R=1` 表示通过 | `evaluate.check` / `types::evaluate` |
| `N` | 挑战空间（`n` 公开） | `ProofRequest.nonce` |
| `B(n,T)` | 公开绑定函数 | `response_binding` |
| `s` | `policy_nonce`，128 bit 盐 | [`policy_commit.py`](../../policydsl/privacy/policy_commit.py) |
| `h_π` | 带盐策略承诺 = `policy_hash` | `compile_policy()["sha256"]` |
| `L_pub` | 证书公开值（不含证明工件） | `Outcome` / 证书 payload |
| `L_proof` | 证明工件对见证的泄露 | `core` 的 trace / opened values |
| `L_side` | 对手侧信息 `Z` | prompt、模型、部署上下文 |
| `Negl` | 可忽略函数 | — |

**代码数据流（本文反复引用）**：

```
Policy(policy_nonce=s)
  └─ compile._assemble                  # stable["policy_nonce"] = s.lower()
      └─ canonical_spec_bytes           # 键排序 + 紧凑 JSON + UTF-8
          └─ SHA256 → spec["sha256"]    # 即 h_π
              ├─ cert.build_payload     # payload["policy_hash"] = h_π
              │                         # payload["policy"] 只含 id/version
              └─ SP1 Job.spec_canonical # 私有输入；run_job 从同一段字节
                                        # 再算 policy_hash，并解析约束
```

关键事实：

- `spec_canonical` 是 **Job 的私有输入**（[`circuits/program/src/main.rs`](../../circuits/program/src/main.rs)
  的 `io::read()`），不是公开值；
- 公开值 `Outcome` 只含 `policy_hash`（以及 `response_binding`、`passed`、
  `violations`、`delegated` 等，见 [`types/lib.rs`](../../circuits/types/src/lib.rs) 的
  `ProofOutput`）；
- 证书 payload 只写 `policy.id/version` 与 `policy_hash`，**不写 `policy_nonce`**
  （[`cert.py`](../../policydsl/evidence/cert.py) 的 `build_payload`）。

## 2. 定理 D 的陈述与读法

### 2.1 框架 D5 的原文

> 方案是 `D-private` 的，若对任意 `π₀,π₁` 满足 `D(π₀)=D(π₁)`、任意同判定
> `T₀,T₁`、任意 `n`，两份证书的验证者视图计算不可区分。

本文把它细化为下面的游戏。细化不改变“策略侧不可区分”的意图，只把
“同判定”中隐含的公开绑定条件写清楚。

### 2.2 修正读法：工件必须固定，或 public T-view 必须相同

证书公开值里有 `b = B(n,T)`（以及私有模式的 `response_commitment`）。如果
`T₀ ≠ T₁`，验证者只要算一次 `B(n,T₀)` 与 `B(n,T₁)` 就能区分，**这与策略隐私
无关**，是响应侧 T1 的已知泄露。因此：

> **D-privacy 游戏固定同一条工件 `T` 与同一个挑战 `n`**；两个世界只在
> `π₀ / π₁` 上不同。等价地，允许 `T₀,T₁` 不同，但要求它们的 public T-view
> （`b`、`response_commitment`、`trace_root` 等所有公开的 T 派生值）相同。

论文里应把 D5 的“任意同判定 `T₀,T₁`”改写为“任意 public T-view 相同的
`(T₀,T₁)`”，并在脚注说明：不同 `T` 的区分由 T1 负责，不属于 D-privacy。
这是**读法澄清**，不是改定理意图。

### 2.3 对手是谁

D-privacy 的对手是**验证者 `V`**（公众、竞品、终端用户），不是运营方 `O`。
运营方持有 `π` 与 `s`（它要出证），对运营方没有策略隐私可言；P-PP 的规范方
`R` 持有 `π` 与签发记录，也不在隐私对手之列。这与
[`../security-model.md`](../security-model.md) §4.6.2 的三方模型一致。

## 3. D-privacy indistinguishability 游戏

### 3.1 游戏参数

固定：

- 证书方案 `CS = (Setup, Prove, Verify, Com)`，其中 `Com` 是策略承诺
  （本文实例化为带盐 SHA-256）；
- 披露函数 `D: Π → 𝔻`；
- 工件空间 `M`、挑战空间 `N`、判定关系 `R`；
- 泄漏剖面 `L = (L_pub, L_proof, L_side)`（框架 D4）。

记 `View_b = (L_pub(π_b,T,n), L_proof(π_b,T,n), L_side)`。

### 3.2 挑战者与对手

```
游戏 Priv_{CS,D}(λ):
  1. 【建立】挑战者 C 运行 pp ← Setup(1^λ)，把 pp 交给对手 A。
  2. 【预处理】A 输出 (π₀, π₁, T, n, aux)：
       - π₀, π₁ ∈ Π；
       - D(π₀) = D(π₁)；
       - T ∈ M，n ∈ N；
       - R(π₀,T) = R(π₁,T)（同一条 T，判定相同）；
       - aux 是 A 的辅助输入（部署上下文、候选策略库等）。
     若任一条件不满足，C 中止并输出 ⊥（该查询不计入优势）。
  3. 【挑战】C 采样 b ← {0,1}，运行 c ← Prove(pp, π_b, T, n)，
     把 View_b 交给 A。
     （View_b 含 L_pub、L_proof；L_side 由 A 自己持有。）
  4. 【猜测】A 输出 b' ∈ {0,1}。
  5. 【获胜】b' = b 则 A 获胜。
```

**优势**：

```
Adv_{CS,D}(A,λ) = | Pr[b'=1 | b=0] - Pr[b'=1 | b=1] |
                = | 2·Pr[A 获胜] - 1 |.
```

**定义（D-private）**：若对任意 PPT 对手 `A`，`Adv_{CS,D}(A,λ) ≤ negl(λ)`，
则 `CS` 是 `D-private` 的。

### 3.3 多证书与多挑战（备注）

上面的游戏是单实例的。真实系统会对同一策略发多张证书、对不同 `T`/`n` 各发一张。
若单实例优势为 `ε`，则 `q` 张证书的混合论证给出 `q·ε` 的上界（标准的
hybrid/union bound）。本文只证单实例；多实例的组合作为证明债列在 §10。

## 4. 充分条件

把公开值拆成

```
L_pub(π,T,n) = ( h_π , L_rest(π,T,n) ),
```

其中 `h_π` 是策略承诺（本文的 `policy_hash`），`L_rest` 是其余公开值
（`policy.id/version`、`passed`、`response_binding`、`violations`、`delegated`、
`ts`、证明摘要等）。三条充分条件如下。

### C1（公开值模拟）

存在 PPT 模拟器 `S_rest`，使得对任意满足游戏条件的 `(π,T,n)`：

```
( h_π , S_rest(pp, h_π, D(π), pub_T, n) )  ≈_c  L_pub(π,T,n),
```

其中 `pub_T` 是 `T` 的公开派生值（`y=R(π,T)`、`b=B(n,T)`、私有模式下的
`response_commitment`、`trace_root` 等）。**直观**：除承诺外，公开值只通过
`D(π)` 依赖 `π`；对 `T` 的依赖只通过公开的 `pub_T`，而 `pub_T` 在两个世界里
相同。

> 若公开值里有任何字段依赖 `π` 的未披露部分（例如 `violations[].rule` 的规则名、
> `delegated` 的结构），C1 失败。当前实现确实有这两个字段，见 §7.3。

### C2（witness-hiding）

存在 PPT 模拟器 `S_proof`，使得对任意满足游戏条件的 `(π,T,n)`：

```
S_proof(pp, Stmt(π,T,n))  ≈_c  L_proof(π,T,n),
```

其中 `Stmt = (h_π, L_rest)` 是完整公开陈述（模拟器**不**接受 `π` 或 `T` 的
未公开部分）。**直观**：证明工件不泄露见证。

### C3（D-hiding commitment）

对任意 `π₀,π₁` 满足 `D(π₀)=D(π₁)`：

```
(pp, h_{π₀})  ≈_c  (pp, h_{π₁}).
```

**直观**：承诺不泄露 `D(π)` 之外的东西；本文的带盐构造实际上对任意
`π₀ ≠ π₁` 都隐藏（比 C3 更强，见 §6.4）。

### C4（承诺正确性与绑定性，问责用）

- **正确性**：`h = Com(π,s)` 时 `VerifyCom(π,s,h)=1`；
- **绑定性**：PPT 找不到 `(π,s) ≠ (π',s')` 使 `Com(π,s)=Com(π',s')`，
  除 `negl(λ)` 外。

C4 不参与 D-privacy 的证明，但 P-PP 的“审计时能核对当时执行的确实是签发的
策略”需要它。绑定性归约到 SHA-256 抗碰撞（A2）。

## 5. 定理 D.1 与混合论证

> **定理 D.1**：若 `CS` 满足 C1、C2、C3，则 `CS` 是 `D-private` 的。
>
> 更定量地：若 C1/C2 的模拟误差为 `ε_pub, ε_wh`，C3 的隐藏优势为 `ε_com`，
> 则对任意 PPT `A`：
>
> ```
> Adv_{CS,D}(A,λ) ≤ O(ε_pub + ε_wh + ε_com).
> ```
>
> 下面的混合展开给出常数 `≤ 5`（5 个主混合 + 2 个子混合）；具体常数不影响
> 可忽略性。

**证明**。固定 `A` 输出的一组 `(π₀,π₁,T,n)`（若非法则游戏中止，优势为 0）。
记：

- `h_i = h_{π_i}`；
- `R_i = L_rest(π_i,T,n)`；
- `P_i = L_proof(π_i,T,n)`；
- `Stmt_i = (h_i, R_i)`。

构造五个混合游戏（`H0` 是 `b=0` 的真实视图，`H5` 是 `b=1` 的真实视图）：

```
H0 = ( h₀ , R₀ , P₀ )                                   # 真实，π₀
H1 = ( h₀ , R₀ , S_proof(Stmt₀) )
H2 = ( h₀ , S_rest(h₀,D,pub_T,n) , S_proof(Stmt₀) )
H3 = ( h₁ , S_rest(h₁,D,pub_T,n) , S_proof(Stmt₁) )
H4 = ( h₁ , R₁ , S_proof(Stmt₁) )
H5 = ( h₁ , R₁ , P₁ )                                   # 真实，π₁
```

其中 `D = D(π₀) = D(π₁)`。

**H0 ≈ H1**：只把 `P₀` 换成模拟器输出。由 C2，两者计算不可区分，优势
`≤ ε_wh`。

**H1 ≈ H2**：只把 `R₀` 换成 `S_rest` 输出。由 C1，优势 `≤ ε_pub`。

**H2 ≈ H3**：这一步同时换承诺和证明。写成三个子混合更清楚：

```
H2  = ( h₀ , S_rest(h₀,D,pub_T,n) , S_proof(Stmt₀) )
H2a = ( h₁ , S_rest(h₁,D,pub_T,n) , S_proof(Stmt₀) )
H2b = ( h₁ , S_rest(h₁,D,pub_T,n) , S_proof(Stmt₁) )
H3  = H2b
```

- **H2 ≈ H2a**：只把前两个分量里的 `h₀` 换成 `h₁`，证明分量固定为
  `S_proof(Stmt₀)`。由 C3，`h₀ ≈_c h₁`；`h ↦ (h, S_rest(h,D,pub_T,n))`
  是 PPT 可计算函数，计算不可区分性对 PPT 函数封闭，故优势 `≤ ε_com`。
- **H2a ≈ H2b**：只把证明从 `S_proof(Stmt₀)` 换成 `S_proof(Stmt₁)`。
  这里需要 `Stmt₀ = (h₀,R₀) ≈_c (h₁,R₁) = Stmt₁`：
  - `h₀ ≈_c h₁`（C3）；
  - `R₀ ≈_c R₁`（C1 分别给出 `R₀ ≈_c S_rest(D)`、`R₁ ≈_c S_rest(D)`，
    由三角不等式）。
  两个分量的联合不可区分由标准的 product hybrid 给出；再对 `Stmt` 应用
  PPT 模拟器 `S_proof`，得到 `S_proof(Stmt₀) ≈_c S_proof(Stmt₁)`。
  这一步的优势不额外引入新的计算假设（仍是 C1 + C3 的误差，已计入
  `ε_pub + ε_com`）。

> 注意：`R_i` 是真实的 `L_rest`，可能通过 `D` 之外的无关随机量（时间戳、
> 证明摘要）不同；C1 保证它们都可由同一个 `S_rest(D)` 模拟。不要写成
> “`R_i` 只通过 `h_i` 不同”——那句话不准确。

**H3 ≈ H4**：C1 的反向应用（`π₁` 一侧），优势 `≤ ε_pub`。

**H4 ≈ H5**：C2 的反向应用，优势 `≤ ε_wh`。

把 H2→H3 展开成上面的两个子步后，三角不等式为：

```
|Pr[A(H0)=1] - Pr[A(H5)=1]|
  ≤ ε_wh + ε_pub + ε_com + (2ε_pub + ε_com) + ε_pub + ε_wh
  = 4ε_pub + 2ε_wh + 2ε_com
  = O(ε_pub + ε_wh + ε_com).
```

（`H2a → H2b` 的 `2ε_pub` 来自 `R₀ ≈ R₁` 的两次 C1 三角不等式；这一步同时
用 C3，已计入 `ε_com`。）若三项都是 `negl(λ)`，则 `A` 的优势可忽略。`∎`

**读法**：

- 这个证明是标准的“模拟器 + 承诺隐藏”混合，不依赖 SHA-256 的具体结构；
  具体实例化只影响 `ε_com` 的取值。
- C1/C2 是**方案级**条件，不是密码学假设。当前实现是否满足它们，是 §7 的
  内容；不要因为证明了 D.1 就声称“当前系统已 D-private”。

## 6. 带盐承诺：构造、字段与证明

### 6.1 构造

权威 `R`（P-PP 的规范方）为每个策略包 `π` 生成独立盐：

```
s ← {0,1}^128            # secrets.token_hex(16)，32 个小写十六进制字符
```

承诺的精确字节串是（不是简单的“拼接”，而是规范 JSON 的一个字段）：

```
stable(π,s) = {
    "constraints":   C(π),          # 逐规则编译后的约束列表
    "policy_id":     π.id,
    "policy_nonce":  s,             # 仅当 s ≠ "" 时出现
    "policy_version":π.version,
    "semantic":      π.semantic,
    "spec_version":  "v1"
}
canonical(π,s) = UTF8(json.dumps(stable, sort_keys=True,
                                 separators=(",", ":"), ensure_ascii=True))
h_π            = hex(SHA256(canonical(π,s)))
```

- `s = ""` 时 `policy_nonce` 字段完全不出现在规范字节里；这是旧行为，现有
  无盐策略包的 `policy_hash` 逐字节不变。
- `s` 非空时先小写化（`Policy.from_dict` 与 `_assemble` 都做一次），因此
  `"AB..."` 与 `"ab..."` 得到同一个承诺。
- `s` 的最短长度是 32 个十六进制字符（128 bit）；更长允许。
- `attach_nonce` 对策略包做**深拷贝**再挂盐，不修改入参；多证明者切片
  （[`multiparty.py`](../../policydsl/proofs/multiparty.py)）让每个切片携带父策略的
  同一个 `policy_nonce`。

> **与框架文档 §7.2 的记号差异**：框架写的是
> `h_π = SHA256(canonical(π) ‖ policy_nonce)`。代码的实际构造是把盐作为
> 规范 JSON 的 `policy_nonce` 字段（键排序后位于 `policy_id` 与
> `policy_version` 之间），再对整段字节求 SHA-256。两者在“盐进哈希输入”这一点
> 上一致；论文附录应使用代码的精确字节串，避免审稿人按字面拼接复现时对不上。

### 6.2 字段对应表

| 框架/证明记号 | 代码字段 | 位置 |
|---|---|---|
| `π` | `Policy`（`id/version/semantic/rules`） | [`model.py`](../../policydsl/core/model.py) |
| `s` | `Policy.policy_nonce` | `model.py:316`（校验 `:324-333`） |
| 生成 `s` | `new_policy_nonce(16)` → `secrets.token_hex(16)` | [`policy_commit.py`](../../policydsl/privacy/policy_commit.py) `:55-59` |
| 附带 `s` | `attach_nonce(pack, nonce)`（深拷贝） | `policy_commit.py:62-70` |
| `canonical(π,s)` | `_assemble` 写入 `stable["policy_nonce"]`，再 `canonical_spec_bytes` | [`compile.py`](../../policydsl/core/compile.py) `:284-301`、`:43-62` |
| `h_π` | `spec["sha256"]` = `SHA256(canonical_spec_bytes(stable))` | `compile.py:300` |
| 证书公开值 | `payload["policy_hash"] = spec["sha256"]` | [`cert.py`](../../policydsl/evidence/cert.py) `:249` |
| **不进**证书载荷 | `payload["policy"]` 只写 `{id, version}` | `cert.py:248` |
| 电路公开值 | `ProofOutput.policy_hash` | [`types/lib.rs`](../../circuits/types/src/lib.rs) `:964` |
| 私有输入 | `Job.spec_canonical`（含盐） | `types/lib.rs:424`；`program/main.rs` |
| 审计开示 | `verify_commitment(pack, commitment)`（常量时间） | `policy_commit.py:83-89` |
| 规范字节调试 | `commitment_bytes(pack)` | `policy_commit.py:92-96` |
| 域分隔变体 | `commitment_digest(pack)`（**不是**证书的 `policy_hash`） | `policy_commit.py:99-114` |

### 6.3 引理 D.2（正确性与绑定性）

> **引理 D.2**：对任意 `π` 与任意 `s`，
> `verify_commitment(attach_nonce(π,s), policy_commitment(attach_nonce(π,s))) = 1`。
> 反之，若 PPT `A` 输出 `(π',s')` 使 `Com(π',s') = Com(π,s)` 且
> `(π',s') ≠ (π,s)`，则 `A` 找到了 SHA-256 的一个碰撞；在 A2（抗碰撞）下，
> 该事件概率 `≤ negl(λ)`。

**证明**。正确性：`attach_nonce` 复制策略包并写入小写盐；`policy_commitment`
走 `Policy.from_dict → validate → compile_policy`；`verify_commitment` 用
`hmac.compare_digest` 比较同一个十六进制串。确定性来自 `compile_policy` 的
纯函数性与 `json.dumps(sort_keys=True)`。绑定性：两个不同的 `(π,s)` 产生同一
`h_π` 即 SHA-256 碰撞；`(π,s)` 到规范字节的映射是单射（规范 JSON 的键唯一、
字符串转义无歧义、盐是合法十六进制），所以碰撞只能来自哈希。`∎`

**实验锚点**：[`tests/test_policy_commit.py`](../../tests/test_policy_commit.py) 的
`test_verify_commitment_roundtrip_and_tamper`、`test_nonce_changes_hash_and_appears_in_canonical`、
`test_no_nonce_absent_from_canonical_bytes`。

### 6.4 引理 D.3（随机预言机下的隐藏性）

设 `H: {0,1}^* → {0,1}^λ` 按随机预言机建模（`λ=256`），
`I(π,s)` 是 §6.1 的规范字节。假设 `s` 在 `{0,1}^128` 上均匀、独立于 `π`，
且 `I` 对 `s` 是单射（同一 `π` 下不同 `s` 给出不同字节）。

> **引理 D.3**：对任意 `π₀ ≠ π₁`、任意做至多 `q` 次 `H` 查询的 PPT 对手 `A`：
>
> ```
> Adv_hide(A) ≤ 2q/2^128 + 2q/2^λ.
> ```

**证明**。挑战者采样 `b`、`s_b ← {0,1}^128`，给 `A` 的是
`h_b = H(I(π_b,s_b))` 与 `H` 的查询接口。令 `E_b` 为“`A` 查询了
`I(π_b,s_b)` 这个输入”的事件。

- 若 `E_0 ∪ E_1` 不发生，则 `h_b` 是 `H` 在一个**未被查询过的**输入上的输出；
  在 ROM 里它与 `b` 独立、均匀分布在 `{0,1}^λ`。因此 `A` 的优势为 0
  （至多加上 `A` 猜中一个碰撞的 `2q/2^λ`）。
- `Pr[E_b] ≤ q/2^128`：`s_b` 有 `2^128` 种等可能取值，每次查询至多命中一个；
  对 `b=0,1` 取并集得 `2q/2^128`。

合并得 `Adv_hide ≤ 2q/2^128 + 2q/2^λ`。`∎`

**说明**：

- 这里假设 `A` 知道 `π₀,π₁`（D-privacy 游戏里它自己选的）。如果 `A` 不知道
  `π`，界只会更好（每个候选多一个 `2^-128` 的盐猜测）。
- `q` 是**哈希查询次数**，不是时间；与框架定理 A 的 `q` 口径一致。
- 对 `q ≤ poly(λ)`，`2q/2^128` 已经是可忽略量级；`2q/2^256` 更小。
- 若盐被复用（同一个 `s` 用于多个策略），多目标攻击会让界变差；盐应每个策略
  独立生成。见 §10。

### 6.5 推论 D.4（带盐构造满足 C3，进而在 C1/C2 下 D-private）

> **推论 D.4**：若 `D` 是 L2 披露（只公开 `policy.id/version` 与承诺，不加
> 规则名/类别/`delegated`），且证明系统满足 C2，则带盐承诺方案满足 C1、C3，
> 从而是 `D-private` 的。

**证明**。

- C3：由引理 D.3，`h_{π₀} ≈_c h_{π₁}`（甚至不需要 `D(π₀)=D(π₁)`）。
- C1：L2 下 `L_rest` 只含 `policy.id/version`（属于 `D`）、`passed`、`b`、
  模式、`ts`、证明摘要等；其中 `passed = R(π,T)` 与 `b = B(n,T)` 是 `pub_T`
  的一部分，`ts` 可采样，证明摘要由 `S_proof`/承诺派生。因此存在一个只依赖
  `(D,pub_T,n)` 的模拟器 `S_rest`。
- `D-private`：由定理 D.1。`∎`

> **不要把 D.4 读成“当前系统已 D-private”**：C2 当前不成立（`core`），C1 在
> 当前公开输出下也不成立（`violations/delegated`）。D.4 是“在 L2 + 正确证明档
> 下成立”的条件性结论，见 §7。

### 6.6 P-PP：登记、开示与信任

P-PP（[`security-model.md`](../security-model.md) §4.6.1、§4.6.2）要求规范方 `R`：

1. 生成并保管 `s`；
2. 编译 `π`、计算 `h_π`，把 `h_π` 登记在第三方可读的签发记录里；
3. 把 `(π,s)` 交给运营方 `O`（`O` 才能出证）；
4. 审计时（或 `O` 自愿开示时）把 `(π,s)` 交给审计者 `V*`；`V*` 调
   `verify_commitment` 重算 `h_π`，与证书里的 `policy_hash` 比对。

**信任边界**：

- `R` 的诚实性是 P-PP 的前提：它必须签发真实的 `π`、不把 `s` 公开、不帮 `O`
  伪造登记。
- `O` 不可信（对完整性而言），但它**想要**对 `V` 隐藏 `π`，所以它会配合保密；
  如果 `O` 主动把 `s` 给 `V`，那是自愿披露，不是密码学被攻破（§9）。
- `V` 只看到 `h_π` 与签发记录里的 `h_π`；它不能枚举（除非猜中 `s`）。
- `V*` 只在 `O`/`R` 开示后才拿到 `(π,s)`；本模式不提供“强制开示”。

**代码现状**：`policy_commit.py`、`model.py`、`compile.py`、`cert.py` 已落地
“生成/附带/校验/进哈希”；**签发记录本身尚未实现**（框架 §13 的透明日志一行
仍标待落地，P-PP 的登记流程也没有对应模块）。所以 P-PP 的“登记”在本文是
**假设/流程**，不是代码事实；实验 E4 也不能替代它。

## 7. 两个通道与当前实现的缺口

框架 §7.3 把泄露分成几个通道。这里用 C1/C2 的语言重述，并逐条对应代码。

### 7.1 公开值通道（加盐关闭）

| 项 | 加盐前 | 加盐后 | 证明条件 |
|---|---|---|---|
| `policy_hash = SHA256(canonical(π))` | 可离线枚举候选 `π` 并比对 | 需同时猜 `s`（128 bit） | C3 |
| 证书 payload 的 `policy.id/version` | 可能暴露策略身份 | 不变（属于 `D`） | C1（`D` 必须包含） |
| `passed` / `response_binding` | 只依赖 `T`/判定 | 不变 | `pub_T` |

**结论**：加盐关闭的是“`policy_hash` 作为 `π` 的公开可重算函数”这一通道。
它**不**关闭任何依赖 `T` 的公开值，也不关闭 `policy.id/version` 的身份泄露。

### 7.2 证明工件通道（`core` 仍泄露，需 `groth16/plonk`）

SP1 的 `core` / `compressed` 证明工件不隐藏见证：execution trace、内存读写、
`opened_values` 等可能包含 `Job` 的私有输入，而 `Job` 里有
`spec_canonical`（**含 `s`**）与 `response`。因此：

- `policy_nonce` 虽然不进证书 payload，但它在 `spec_canonical` 里；`core` 工件
  一旦泄露私有输入，`s` 与 `π` **同时**泄露，枚举攻击立刻恢复（§9）；
- 这不是“盐不够长”，是 C2 失败。只有 `groth16`/`plonk` 的 witness-hiding
  才能关闭（[`../sp1-zk-audit.md`](../sp1-zk-audit.md) §2–§3，实验 E1）。

> **论文必须写**：定理 D 的条件 2 在当前 `core` 档**不成立**。加盐原型只证明
> “公开值通道可关闭”，不证明“当前系统的策略隐私”。

### 7.3 披露层级通道（规则名 / `delegated`）

当前公开输出里的两类字段依赖 `π` 的未披露结构：

| 泄露口 | 字段 | 位置 | 漏什么 |
|---|---|---|---|
| ③ | `PrivateViolation{rule, kind, evidence_commitment}` | `types/lib.rs` | 违规时验证者学到**规则名**；3–8 条规则时基本等于策略目录 |
| ⑤ | `delegated: Vec<DelegatedConstraint>` | `types/lib.rs` | 非空即暴露“有语义规则、本轮未判”，条目序还泄露结构 |

在公开模式下，`Violation{rule, kind, evidence}` 的 `evidence` 还会直接给出命中
的明文（例如关键词/模式串）。因此：

- 若 `D` = L2（仅承诺 + `id/version`），当前实现的 C1 **失败**；
- 若 `D` = L0/L1（把规则名/类别/数量纳入披露），C1 可以成立，但披露函数本身
  泄露更多；
- 正确做法是 E4 的披露层级：要么把这些字段抑制到类别级/承诺级，要么把它们
  显式写进 `D(π)`。

> 这一条与盐无关。即使 `policy_hash` 完全隐藏，`rule` 名仍然泄露策略目录。
> 论文里不能把“加盐”写成“策略隐私已解决”（框架 §7.3 的原话）。

### 7.4 重执行 / 部署上下文通道

盐只保护**哈希**，不保护**行为**。如果对手知道 prompt、模型、解码参数、
部署上下文与策略库，它可以从输出行为推断策略（`k_π` 可能很低）。这是
`L_side`，与证明系统无关；对应框架定理 B 的 `L_side` regime 与实验 E4 的
推断攻击量化。定理 D 的 C1/C2 都不覆盖它。

### 7.5 小结表

| 通道 | 加盐是否关闭 | 对应条件 | 当前状态 | 关闭手段 |
|---|---|---|---|---|
| 公开值 `policy_hash` | ✅ | C3 | 已落地（本原型） | `policy_nonce` |
| 证明工件 `core` | ❌ | C2 | **不满足** | `groth16/plonk`（E1，`[CLOUD]`） |
| `violations.rule/kind` | ❌ | C1 | **不满足**（除非 `D` 覆盖） | E4 的 L0/L1/L2 |
| `delegated` | ❌ | C1 | **不满足**（除非 `D` 覆盖） | E4 / fail-closed |
| 重执行/上下文 | ❌ | 不在 C1/C2 | 不在本定理范围 | E4 推断量化 |

## 8. 无盐与有盐枚举：量级讨论

### 8.1 枚举攻击游戏

```
游戏 Enum_{Com}(λ):
  1. 挑战者采样 π* ← Π，s* ← {0,1}^128（无盐构造取 s* = ε）。
  2. 计算 h* = Com(π*,s*)，把 h* 与候选集 Π_c ⊆ Π 交给 A。
  3. A 输出 (π̂, ŝ)。
  4. A 获胜当且仅当 Com(π̂,ŝ) = h*。
```

`Π_c` 是对手根据部署上下文、策略库、规则模板构造的候选集；它通常**包含**
真实策略（对手不是随机猜，而是结构化枚举）。这一点是本节所有界的读法前提。

### 8.2 无盐（`s = ε`）

```
h* = SHA256(canonical(π*)).
```

- 若 `π* ∈ Π_c`：对手对每个候选算一次哈希，命中概率 1（忽略碰撞）。
- 若 `π* ∉ Π_c`：每个候选的错误命中概率 `≤ 2^{-λ}`，故
  `Pr[误报] ≤ |Π_c|/2^λ`。

所以框架 §12 第 5 条的 `|Π_c|/2^λ` 是**误报上界**，不是“恢复真实策略的上界”。
真实策略在候选集里时，任何哈希都无法隐藏它；这正是
[`tests/test_policy_commit.py`](../../tests/test_policy_commit.py) 的
`test_unsalted_is_recoverable` 演示的事实。无盐策略的安全性完全取决于
`k_π`（候选集的有效熵），而不是 SHA-256 的输出长度。

### 8.3 有盐（`s ← {0,1}^128`）

对手不知道 `s*`。设它对每个候选尝试 `q_s` 个盐猜测（共 `|Π_c|·q_s` 次哈希）：

```
Pr[恢复] ≤ q_s/2^128              # 猜中真实盐
          + |Π_c|·q_s/2^λ         # 其余组合的哈希碰撞/误报
```

- `q_s = 1`：`≤ 2^{-128} + |Π_c|/2^{256}`。对现实 `|Π_c| ≤ 2^40`，主项是
  `2^{-128}`。
- `q_s = 2^64`：`≤ 2^{-64} + |Π_c|/2^{192}`。工作量 `|Π_c|·2^64` 次哈希，
  仍然不可行（对 `|Π_c| ≤ 2^40` 是 `2^104` 次）。
- `q_s = 2^128`（穷举盐）：第一项为 1。即**穷举整个盐空间一定恢复**；盐是
  工作量屏障，不是信息论隐藏。工作量 `|Π_c|·2^128` 次哈希。

### 8.4 与框架 §12 第 5 条的 `|Π_c|/2^{λ+128}` 核对

框架写的上界是：

```
无盐：|Π_c|/2^λ
有盐：|Π_c|/2^{λ+128}
```

**定性结论成立**：盐把每个候选的猜测空间乘以 `2^128`，因而把攻击工作量乘以
`2^128`。**精确指数需要修正**：

- 若“有盐枚举”指“对每个候选穷举所有 `2^128` 个盐”，聚合误报项是
  `|Π_c|·2^128/2^λ = |Π_c|/2^{λ-128}`，不是 `/2^{λ+128}`。
- 若指“每个候选只猜一个盐”，误报项是 `|Π_c|/2^λ`，另加盐猜中项 `2^{-128}`；
  也不是 `/2^{λ+128}`。
- `|Π_c|/2^{λ+128}` 对应的是“承诺输出有 `λ+128` 位、每个候选只需一次猜测”的
  情形；SHA-256 的输出只有 `λ=256` 位，盐不增加输出长度。

**论文写法建议**：

> 无盐时，真实策略在候选集内即可被恢复；不在候选集内时误报率
> `≤ |Π_c|/2^λ`。有盐时，攻击者必须额外猜中 128 bit 盐；在 `q_s` 次盐猜测
> 下恢复概率 `≤ q_s/2^128 + |Π_c|q_s/2^λ`，等价地把工作量乘以 `2^128`。
> 对 `λ=256`、`|Π_c| ≤ 2^40`、`q_s ≤ 2^20`，两项分别 `≤ 2^{-108}` 与
> `≤ 2^{-196}`；即使把 `q_s` 放宽到 `2^40`，第一项也只有 `2^{-88}`。

这样既保留框架的“量级”结论，又不会在附录里写出一个差 `2^256` 的指数。

### 8.5 结构化枚举才是真攻击

`|Π_c|` 在真实部署里不是 `2^256`；它是由 8 类规则、有限参数、3–8 条规则
组合出的**结构化候选集**。对手不需要穷举 `2^256`：

- 它按规则模板生成候选；
- 用部署上下文剪枝；
- 对每个候选只做一次编译 + 哈希。

所以：

- **无盐**：只要真实策略在结构化候选集里，恢复是确定性的；
- **有盐**：对手还缺 `s`；结构化枚举无法替代 128 bit 盐猜测（除非盐从
  其他通道泄露，见 §7.2、§9）。

### 8.6 实验对应

- [`tests/test_policy_commit.py`](../../tests/test_policy_commit.py) 的
  `TestEnumerationAttack` 是 E4a 的单测版：无盐恢复、有盐（错误盐）不恢复、
  盐泄露后恢复。
- [`bench/bench_policy_leak.py`](../../bench/bench_policy_leak.py) 是 E4a 的
  基准脚本（候选集规模更大、报告恢复率/耗时）。
- 这些实验证明的是**攻击形状**，不是 §8.3 的概率界；论文里要分开写。

## 9. 盐泄露 ⇒ 恢复：自愿披露 / 权威被攻破

### 9.1 游戏

```
游戏 SaltLeak_{Com}(λ):
  1. 挑战者采样 π*、s*，计算 h* = Com(π*,s*)。
  2. 把 (h*, s*) 与候选集 Π_c 交给 A。
  3. A 输出 π̂。
  4. A 获胜当且仅当 π̂ = π*。
```

若 `π* ∈ Π_c`，A 对每个候选计算 `Com(π,s*)` 并比对 `h*`，获胜概率 1（忽略
碰撞）。所以**盐泄露把有盐构造退化成无盐构造**，没有任何密码学屏障。

### 9.2 这不是密码学破解

盐泄露的两种来源：

1. **自愿披露**：运营方 `O` 为了审计/自证，把 `(π,s)` 交给审计者；或 `O`
   故意把 `s` 给竞争对手。这是 P-PP 流程的一部分（审计）或运营方的选择，
   不是 SHA-256 被攻破。
2. **权威被攻破**：规范方 `R` 的盐保管被攻破，或 `R` 不诚实。这是 P-PP 的
   信任假设失败，不是承诺原语的缺陷。

论文要写清：

> D-privacy 的隐藏性以“盐只被 `R`/`O` 持有、`O` 不主动泄露、`R` 诚实保管”
> 为前提。盐泄露后的恢复是**自愿披露或权威被攻破**的结果，不构成对
> SHA-256 或承诺方案的密码学攻击。

### 9.3 其它与盐有关的边界

- **旧策略包无盐**：现有 7 个随包策略（框架 §7.2 的说法；仓库当前
  `policy_packs/` 下有 13 个 JSON）在 `policy_nonce=""` 时哈希逐字节不变，
  因而**仍然可枚举**。加盐是 opt-in，不会追溯保护旧包；要保护必须重新签发
  带盐的 `h_π`。这是向后兼容的代价，论文要如实写。
- **盐重用**：同一 `s` 用于多个策略不会立刻泄露 `π`，但多目标攻击与
  “同一盐下候选集交叉比对”会降低安全性；应每个策略独立生成。
- **运营方是对手时**：`O` 知道 `π` 与 `s`，对 `O` 没有隐私；D-privacy 的
  对手是 `V`（§2.3）。
- **RNG**：`secrets.token_hex` 依赖 OS 随机源；若 OS RNG 被攻破，盐可预测，
  隐藏性失败。这是标准假设。

## 10. 定理 D 的证明债

| # | 债 | 为什么要写进论文 | 需要的假设/实验 |
|---|---|---|---|
| D-1 | ROM heuristic | 引理 D.3 把 SHA-256 当随机预言机；标准模型下没有这个界 | 明确写“heuristic”，或换标准模型承诺 |
| D-2 | D5 的 `T₀,T₁` 读法 | 不同 `T` 时 `b=B(n,T)` 直接区分 | 固定同一 `T`/public T-view（§2.2） |
| D-3 | C1 不成立 | `violations.rule/kind`、`delegated` 泄露策略结构 | L2 披露或把字段纳入 `D`；E4 |
| D-4 | C2 不成立 | `core` 证明工件不隐藏见证；且会泄露 `spec_canonical` 里的盐 | `groth16/plonk`（E1，`[CLOUD]`） |
| D-5 | P-PP 登记未实现 | 签发记录/登记流程在代码里还没有 | 流程假设；B1/P1-13 的透明日志 |
| D-6 | 旧包无盐 | 向后兼容使旧 `policy_hash` 仍可枚举 | 重新签发带盐承诺 |
| D-7 | 域分隔 | 证书的 `policy_hash` 是 `SHA256(canonical)`，没有 `pop-policy-commit-v1` 前缀；`commitment_digest` 有前缀但未用于证书 | 跨协议域分离；论文说明或统一 |
| D-8 | 规范字节假设 | 绑定性依赖规范 JSON 单射与 SHA-256 抗碰撞 | A2；`canonical_spec_bytes` 的实现锁定 |
| D-9 | 盐保管 | 隐藏性依赖 `R`/`O` 不泄露盐 | P-PP 信任假设；盐泄露游戏（§9） |
| D-10 | 多证书 | 本文只证单实例；`q` 张证书的 hybrid 未展开 | 标准 hybrid，`q·ε`；论文可一行带过 |
| D-11 | 盐唯一性 | 盐重用会削弱多目标安全 | 每策略独立盐；代码/流程约束 |
| D-12 | 元数据关联 | `ts`、`public_values_sha256`、`proof_sha256` 可能让多张证书可关联 | 这是 linkability，不是 D-privacy；单列 |
| D-13 | 空盐的哈希不变 | 现有策略包的 `policy_hash` 不变是特性也是风险 | 论文明确“opt-in” |
| D-14 | `ConstraintSpec` 的 Rust 侧忽略 `policy_nonce` | 盐被哈希承诺但 Rust 结构体丢弃；当前只靠 `spec_canonical` 原始字节 | 契约脆弱性；未来重新序列化不得丢盐 |

---

# 第二部分：定理 G（NFA 编译器正确性）

## 11. 范围与陈述

> **编号说明**：框架文档冻结的是定理 A–F；G 不在其中。本节的陈述来自 T3
> 任务书与 [`../../paper/proof-of-policy.md`](../../paper/proof-of-policy.md) §4.2
> 的 NFA 契约，供 P 合并时统一编号。若与论文最终编号冲突，以 P 为准。

> **定理 G（策略编译器正确性，三部分）**：
>
> 设 `P` 是 [`nfa.py`](../../policydsl/core/nfa.py) 支持的语法子集，
> `Comp = Thompson ∘ Parse`，`L(·)` 是语言，`L_re(·)` 是 Python `re` 在
> ASCII 文本上的语言。
>
> **(a) 语言保持**：`∀p ∈ P`，`L(NFA(p)) = L_re(p)`。
>
> **(b) 搜索语义**：`∀p ∈ P`、`∀text`，
> `match_search(NFA(p), text)=1` 当且仅当存在 `0 ≤ i ≤ j ≤ |text|` 使
> `text[i:j] ∈ L_re(p)`。
>
> **(c) 跨层一致**：`∀` 策略 `π`、`∀text`，Python 参考评估器与 Rust 电路评估器
> 对 `pattern_block` 的判定相同（含“命中第几条 pattern”的证据），前提是二者
> 消费同一份 `Compile(π)` 且假设 A-G1–A-G5 成立。

**证据类型**：

- (a) 的 Thompson 部分：**[纸面证明]**（§14 的归纳）；
- (a) 的解析器部分：**纸面证明草图 + [证明债]**（§13）；
- (b)：**[纸面证明]**（§15 的不变式）；
- (c) 的算法层：**[纸面证明]**（§17 的 bisimulation）；
- (c) 的实际 Rust 代码：**[实验证据待补]**（E12/P2-03，§18）。

## 12. 语法子集与语义

### 12.1 语法

```
alt     ::= concat ( "|" concat )*
concat  ::= rep*                         # 空连接 ⇒ ε
rep     ::= atom quant?
quant   ::= "*" | "+" | "?" | "{" m "}" | "{" m "," "}" | "{" m "," n "}"
atom    ::= "(" alt ")"                  # 分组
          | "[" class "]"                # 字符类，含 ^ 取反与区间
          | "."                          # 除 \n 外任意字符
          | "\" esc                      # \d \w \s \D \W \S \n \r \t \f \v
                                         # 或标点的恒等转义
          | c                            # 普通字符
```

`c` 不能是 `| ) * + ? { ^ $`、`\`、`.`、`[`、`(`；这些位置出现元字符时
`_parse_atom` 直接抛 `RegexSyntaxError`。不支持：锚点 `^ $`、反向引用、
环视、懒惰/贪婪区分、`\b`。

**ASCII 语义**（与 Python `re` 在 ASCII 文本上一致）：

```
\d = [0-9]
\w = [A-Za-z0-9_]
\s = [ \t\n\r\f\v]
.  = [0,9] ∪ [11,0x10FFFF]      # 不匹配 \n
```

### 12.2 语言

```
L(Lit R)      = { [c] | c ∈ R }                （R ≠ ∅）
L(Eps)        = { ε }                          （空连接）
L(Concat A₁…A_k) = L(A₁)·…·L(A_k)              （空连接为 {ε}）
L(Alt A₁…A_k) = ⋃ L(A_i)
L(Repeat(A,m,n)) = ⋃_{k=m}^{n} L(A)^k          （n=∞ 时 k ≥ m）
```

### 12.3 空字符类的实现缺口（必须写进证明债）

`Lit([])` 在代码里同时表示两件事：

- `_parse_concat` 的空连接 → **ε**（`nfa.py:258-260`）；
- `_parse_char_class` 的取反结果为空集 → 也被构造为 `Lit([])`
  （`nfa.py:53-63`、`:145-148`）。

后者是错的：空字符类的语言应是 **∅**，不是 `{ε}`。可复现的例子：

```
pattern = r"[^\d\D]"      # 取反后区间为空
nfa.match_search(spec, "")   == True   # 代码走 Lit([]) 的 ε 边
re.search(r"[^\d\D]", "")    == None   # Python：空语言
```

本文的定理 G 在：

- **假设 A-G0**：所有字符类的区间集合非空（即不出现空字符类）下成立；
- 或者，若要让定理对全部语法子集成立，必须把 AST 的“ε”与“空语言”分开
  （例如引入 `Eps` 与 `Empty` 两个构造，或让 `Lit([])` 只表示 `Empty`，
  空连接用单独的节点）。这是代码修复项，不在本文范围内。

§19 把这条列为 G-1。

## 13. 解析器正确性（引理 G.1）

> **引理 G.1（解析器健全性，在 A-G0 下）**：`parse(p)` 返回 AST `A` 且
> `L(A) = L(p)`；若 `p` 超出子集，`parse` 抛 `RegexSyntaxError`，不返回一个
> 语义不同的 AST。

**证明草图**。对文法做结构归纳：

- `_parse_atom`：分组递归调用 `_parse_alt` 并要求 `)`；字符类调用
  `_parse_char_class`；`.` 返回 `ANY_EXCEPT_NL`；转义按 `\d\w\s` 类、
  控制转义、标点恒等转义分别处理；普通字符返回单字符 `Lit`。每个分支返回
  的 AST 的语言与对应词法单元一致。
- `_parse_quantifier`：`* + ? {m} {m,} {m,n}` 映射到 `Repeat` 的
  `(min,max)`；`{m,n}` 解析失败/`n<m` 抛错。无显式量词返回 `(1,1)`，
  `_parse_repeat` 因此直接返回原子。
- `_parse_concat`：循环调用 `_parse_repeat` 直到 `)`/`|`；空循环返回空连接
  `Lit([])`（在 A-G0 下它只表示 ε）；否则 `Concat`。
- `_parse_alt`：以 `|` 分割，多个分支返回 `Alt`；单个分支直接返回。
- `parse` 要求解析器消费整个串，否则抛错。

每个函数都“返回 `(node, i)` 且 `i` 恰好是已消费位置之后的下标”，因此组合
是良定义的。**未形式化的部分**：解析器的错误类型/异常路径（例如
`a{x}` 会在 `int("x")` 抛 `ValueError` 而不是 `RegexSyntaxError`）、空字符类
（§12.3）、字符类内的边缘语法（`[]`、`[^]`、嵌套类）；这些列在 §19。`∎`

## 14. Thompson 构造保持语言（定理 G(a) 的主体）

### 14.1 片段与不变量

构造器 `_Builder.build(node)` 返回 `(s,t)`，并在 `states` 里追加状态。
把 `(s,t)` 及其可达子图记为片段 `F`，定义

```
L(F) = { w ∈ Σ* | s --w--> t }.
```

**片段不变量**（对每次 `build` 返回的 `(s,t)` 成立）：

1. `s ≠ t`；
2. 没有边进入 `s`；
3. 没有边离开 `t`；
4. `s` 可达片段内所有状态，且所有状态可达 `t`；
5. 片段内所有边的两个端点都在片段内（片段对边封闭）。

四条保证片段可以像“带两个端子的黑盒”一样串联/并联，不会与外部路径串扰。
构造器每次 `new_state()` 都创建全新状态，因此不同片段的内部状态不相交。

### 14.2 逐构造引理

> **引理 G.2**：对任意 AST 节点 `A`，`build(A)` 返回的片段 `F` 满足
> `L(F) = L(A)`。

**证明**（对 `A` 的结构归纳）。

**情形 1：`A = Lit(R)`，`R ≠ ∅`。** 构造两个新状态 `s,t`，加边
`s --R--> t`。从 `s` 到 `t` 的路径只有这一条（`s` 无入边、`t` 无出边），
标签恰为 `R` 中一个字符；故 `L(F) = { [c] | c∈R } = L(A)`。

**情形 2：`A = Eps`（空连接，代码表示为 `Lit([])`）。** 构造
`s --ε--> t`；唯一路径标签为 `ε`；`L(F)={ε}=L(A)`。

**情形 3：`A = Concat(A₁,…,A_k)`。** 递归得到不相交片段
`F_i=(s_i,t_i)`。用 `ε` 边把 `t_i` 接到 `s_{i+1}`（`i=1..k-1`）。返回
`(s₁,t_k)`。

- **⊆**：任取从 `s₁` 到 `t_k` 的路径。由不变量 2/3，路径离开 `F_i` 的唯一
  出口是 `t_i`，进入 `F_{i+1}` 的唯一入口是 `s_{i+1}`；因此路径在
  `F₁,…,F_k` 上依次分解为 `w₁…w_k`，且 `w_i ∈ L(F_i)`。归纳假设给出
  `w_i ∈ L(A_i)`，故 `w ∈ L(A)`。
- **⊇**：任取 `w = w₁…w_k`，`w_i ∈ L(A_i)`。由归纳假设有 `s_i --w_i--> t_i`；
  用 `ε` 桥接得到 `s₁ --w--> t_k`。

**情形 4：`A = Alt(A₁,…,A_k)`。** 新建 `s,t`；对每个 `F_i` 加
`s --ε--> s_i` 与 `t_i --ε--> t`。任一路径必先选一个分支，再在 `F_i` 内走，
故 `L(F) = ⋃ L(F_i) = L(A)`。

**情形 5：`A = Repeat(B,m,n)`。** 分两种构造：

- **有上界**：构造 `m` 个必选副本 + `n-m` 个可选副本（`_build_optional`），
  用 `_chain` 串联。每个副本的语言是 `L(B)`，可选副本的语言是
  `L(B) ∪ {ε}`。由情形 3 的串联引理：
  ```
  L(F) = L(B)^m · (L(B) ∪ {ε})^{n-m}
       = ⋃_{k=m}^{n} L(B)^k = L(A).
  ```
- **无上界**：构造 `m` 个必选副本 + 一个星号片段（`_build_star`），串联。
  星号片段 `F*` 有 `s* --ε--> s_c`、`s* --ε--> t*`、`t_c --ε--> s_c`、
  `t_c --ε--> t*`；从 `s*` 到 `t*` 的路径要么直接 `ε`，要么在 `F_c` 内走
  若干圈（每圈一个 `L(B)` 词）后退出，故 `L(F*) = L(B)^*`。于是
  ```
  L(F) = L(B)^m · L(B)^* = ⋃_{k≥m} L(B)^k = L(A).
  ```

**ε-环**：当 `B` 可匹配 `ε` 时（如 `(a?)*`），星号片段有 ε-环。NFA 的
路径语义按“存在一条有限路径”定义；`_build_closure_table` 用 visited 集合
求最小闭包，正好对应这个语义。引理 G.2 的路径分解仍然成立（环可以走 0 次
或多次，每次都贡献 `L(B)` 中的一个词；若 `ε∈L(B)`，走任意多次仍得 `ε`，
不影响并集）。

**情形 6：其它 AST 节点**：构造器抛 `RegexSyntaxError`，不会进入证明。`∎`

> **定理 G(a) 的 Thompson 部分**：由引理 G.2，`build(parse(p))` 的片段
> `L(F)=L(parse(p))`；`compile_pattern` 把 `accept` 设为片段的 `t`，故
> `L(NFA(p)) = L(parse(p)) = L_re(p)`（最后一个等号由引理 G.1 与 §16 的
> `re` 语义对应给出）。

## 15. Pike VM 的无锚点搜索（定理 G(b)）

### 15.1 定义

对 spec 的 NFA，记：

```
closure(S)  = 包含 S、并对 ε 边封闭的最小状态集合
move(S,c)   = { t | ∃ s∈S, 边 s --R--> t 且 c∈R }
Δ(S, ε)     = closure(S)
Δ(S, wc)    = closure(move(Δ(S,w), c))
```

`match_search` 的循环恰好是：

```
cur₀ = closure({start})
cur_{i+1} = closure({start}) ∪ closure(move(cur_i, text[i]))
```

（代码里 `nxt` 先放 `start_closure`，再把每条命中边的目标闭包并进来；
`closure(start) ∪ closure(move(cur,c))` 与它逐元素相同。）

### 15.2 不变式

> **引理 G.3**：对每个 `i ∈ [0, |text|]`，
>
> ```
> cur_i = ⋃_{j=0}^{i} Δ({start}, text[j:i]).
> ```

**证明**（对 `i` 归纳）。

- **基**：`cur₀ = closure({start}) = Δ({start}, ε)`，右边 `j=0` 一项。
- **步**：设 `cur_i` 满足不变式。则
  ```
  cur_{i+1}
    = closure({start}) ∪ closure(move(cur_i, text[i]))
    = Δ({start}, ε) ∪ closure(move(⋃_j Δ({start},text[j:i]), text[i]))
    = Δ({start}, ε) ∪ ⋃_j closure(move(Δ({start},text[j:i]), text[i]))
    = Δ({start}, ε) ∪ ⋃_j Δ({start}, text[j:i+1])
    = ⋃_{j=0}^{i+1} Δ({start}, text[j:i+1]).
  ```
  第二步用了 `move` 对并集分配、`closure` 对并集分配；第三步用定义。`∎`

### 15.3 接受条件

- `i=0`：`cur₀ ∩ accept ≠ ∅` 当且仅当 `ε ∈ L(NFA)`；代码在循环前检查，
  因此空模式/可空模式在空文本上也返回 true。
- `i≥1`：循环末尾检查 `cur_i ∩ accept ≠ ∅`。由引理 G.3，这等价于
  ```
  ∃ j ∈ [0,i] : Δ({start}, text[j:i]) ∩ accept ≠ ∅
  ⇔ ∃ j : text[j:i] ∈ L(NFA).
  ```

因此：

> **定理 G(b)**：`match_search(spec,text)=1` 当且仅当存在子串
> `text[i:j] ∈ L(spec)`（含 `i=j` 的空子串，若 `ε ∈ L(spec)`）。`∎`

**朴素匹配器的推论**：`match_search_naive` 对每个起点 `start` 做锚定运行，
`_anchored_end` 返回“存在接受路径”的最长结束点；任一 `start` 接受即返回
true。按定义，这等价于“存在子串匹配”，故与 `match_search` 同语义。Rust
的 `nfa_match_naive` 逐起点重跑，同样如此；[`tests/test_ablation.py`](../../tests/test_ablation.py)
的 `test_pike_equals_naive` 是该推论的实验对拍。

## 16. 与 Python `re.search` 的等价（定理 G(a) 的语义桥）

> **引理 G.4**：在以下假设下，对任意 `p ∈ P` 与 ASCII 文本 `text`：
>
> ```
> L(NFA(p)) = L_re(p) ，
> match_search(NFA(p),text) = 1 ⇔ re.search(p,text) is not None.
> ```

**假设**：

- **A-G1（ASCII）**：`text` 只含 ASCII 字符，且 Python `re` 的
  `\d \w \s` 按 ASCII 解释（或用 `re.ASCII`）。

**论证**：

- 语法子集的每个构造在 `re` 里的语义与 §12.2 的定义一致：
  - 字面量/标点恒等转义：同一个字符；
  - `.`：Python 默认 `re.DOTALL=False`，不匹配 `\n`，与 `ANY_EXCEPT_NL` 一致；
  - 字符类/区间/取反：Python 的 `[...]` 与 `_complement`/`_merge` 在码点集上
    一致；
  - `\d \w \s` 在 ASCII 文本上分别是 `[0-9]`、`[A-Za-z0-9_]`、
    `[ \t\n\r\f\v]`；
  - 分组/分支/量词：标准正则语言构造；
  - 锚点/反向引用/环视被解析器拒绝，不会进入比较。
- 由引理 G.1/G.2，`L(NFA(p))=L(p)`；由正则语言的标准语义，
  `L(p)=L_re(p)`（在 A-G1 下）。
- `re.search` 是“存在子串匹配”的判定；由定理 G(b)，`match_search` 也是。
  两者对布尔值一致。`re.search` 的 leftmost-first 选择不影响布尔结果。

**已知差异（不覆盖）**：

- 非 ASCII 字母：Python 的 `\w`/`\d`/`\s` 是 Unicode 语义，我们的实现是
  ASCII；这是**文档化差异**（`nfa.py` 开头），目标场景是 ASCII 响应。
- 孤立代理项（lone surrogate）：Python `str` 可以有，Rust `char` 不能；
  见 §17。
- `re` 的版本/Unicode 数据漂移：本证明不依赖具体版本，因为假设 A-G1 把
  输入限制在 ASCII。

**实验锚点**：[`tests/test_nfa.py`](../../tests/test_nfa.py) 的
`test_corpus_agrees_with_re_search` 用 12 个 pattern × 23 个 text = 276 个组合
对拍 Python NFA 与 `re.search`；[`../dev-plan.md`](../dev-plan.md) 记录了
“264 项语料全一致”（历史语料规模；当前文件已扩到 276 项）。这是经验证据，
不是引理 G.4 的替代。

## 17. 跨层一致性：Python 参考 vs Rust 电路（定理 G(c)）

### 17.1 数据流

1. [`compile.py`](../../policydsl/core/compile.py) 的 `compile_constraints` 对
   每条 `pattern_block` 调 `nfa.compile_pattern(p)`，把返回的 spec 放进
   `constraints[i]["nfa"]["compiled"]`；
2. `compile_policy` 把整个 `ConstraintSpec` 序列化为 `spec_canonical`
   （规范 JSON），`policy_hash = SHA256(spec_canonical)`；
3. Rust 侧 `Job.spec_canonical` 是**私有输入**；`run_job → parse_spec` 从
   **同一段字节**解析 `ConstraintSpec` 并计算 `policy_hash`；
4. Rust `evaluate` 对 `SpecConstraint::PatternBlock` 遍历 `nfa.compiled`，
   调 `nfa_match(spec, response)`；
5. Python 参考评估器 `evaluate.check` 对 `rule.params["patterns"]` 调
   `nfa.compile_pattern`，再调 `match_search(spec, tx.response)`。

因为 `compile_pattern` 是纯函数（`lru_cache` 只缓存、不改变结果；由
[`tests/test_nfa_cache.py`](../../tests/test_nfa_cache.py) 钉住逐字节确定性），
两边消费的 NFA spec 是同一份。

### 17.2 状态集 bisimulation

定义关系

```
ℛ = { (S, b) | S ⊆ Q, b ∈ {0,1}^|Q|, ∀q∈Q: b[q]=1 ⇔ q∈S }.
```

> **引理 G.5**：Python 的 `match_search` 与 Rust 的 `nfa_match` 在每一步维持
> `ℛ`；因此对任意 spec/text，两者输出相同。

**证明**（对输入长度归纳）。

- **初始**：Python `cur = closure(start)`；Rust `cur = eps_closure(start)`。
  两者的 `closure` 定义相同（含自身、对 `eps` 传递闭包），故 `ℛ` 成立。
- **步**：设 `(S,b) ∈ ℛ`。Python 的 `nxt` 先放 `closure(start)`，再对
  `S` 中每个状态、每条边，若 `cp ∈ ranges` 则并入目标的闭包；Rust 的 `nxt`
  同样先放 `eps_closure(start)`，再对 `b[s]=1` 的每个状态、每条边做同样的事。
  两边 `ranges` 的成员判定相同（见 17.3），因此并入的目标集合相同；两边的
  `closure` 相同。故 `(S',b') ∈ ℛ`。
- **接受**：Python 检查 `cur ∩ accept`；Rust 检查 `accept` 中是否存在
  `b[a]=1`。由 `ℛ`，两者同真同假。

输出只在接受检查处产生，故逐字符归纳得到相同布尔值。`∎`

### 17.3 逐个实现差异的交代

| 差异 | Python | Rust | 为什么等价 |
|---|---|---|---|
| ε-闭包 | `_closure_table` 记忆化 | 每步 `eps_closure` 重算 | 同一个最小闭包定义；记忆化是纯派生量 |
| 状态集 | `set` | `Vec<bool>` | 关系 `ℛ` 逐元素对应 |
| 区间成员 | 快分支 `bisect_right`；否则 `_point_in_ranges` | `in_ranges` 线性扫描 | 在“ranges 已排序且两两不交”的契约下，三者对 `cp` 的成员判定相同（见假设 A-G2） |
| 字符迭代 | `for ch in text: ord(ch)` | `text.chars()` | 对合法 UTF-8 文本，Unicode 标量序列相同（A-G3） |
| 转移表缓存 | `_CompiledPattern.trans_memo` | 无 | 纯派生量；不影响语义 |
| pattern 顺序 | `rule.params["patterns"]` 顺序 | `nfa.compiled` 顺序 | `compile_constraints` 保序；两边都“命中第一条即 break”，证据串相同 |
| naive 模式 | `match_search_naive` | `nfa_match_naive` | 都是逐起点锚定；由定理 G(b) 的推论同语义 |

**假设**：

- **A-G2（区间契约）**：`ConstraintSpec` 里的每条 `edges[].ranges` 已按 `lo`
  升序、且两两不交。`_merge` 与 `_complement` 保证编译产物满足；手搓的
  `spec_canonical` 若不满足，Rust 的 `in_ranges`（“遇到第一条 `cp ≤ hi` 就
  返回 `cp ≥ lo`”）可能与 Python 的逐条二分不同。这是输入校验债（§19 G-3）。
- **A-G3（Unicode 标量）**：两边处理的文本/模式不含孤立代理项；Rust `char`
  只能是 Unicode 标量，serde 解析非法 UTF-8 会失败。Python `str` 允许孤立
  代理项，所以这是跨层差异的边界。
- **A-G4（索引）**：NFA 状态数 `< 2^32`，文本长度可放入 Rust 的索引/循环
  变量；实际策略远小于此。
- **A-G5（同一策略）**：两边的 `spec_canonical` 来自同一次编译；`policy_hash`
  绑定这段字节，若 Python 用了不同的策略，哈希比对会拒绝。

### 17.4 组合层（`pattern_block` 的判定）

`pattern_block` 的语义是“响应命中任一 pattern 即违规”：

- Python `evaluate.check`：按 `patterns` 顺序逐条 `match_search`，命中即
  `violations.append(Violation(rule,"pattern",pat))` 并 `break`；
- Rust `evaluate`：按 `nfa.compiled` 顺序逐条 `nfa_match`，命中即
  `violations.push(Violation{rule, kind:"pattern_block", evidence:patterns[i]})`
  并 `break`。

由引理 G.5，两边对每条 pattern 的布尔值相同；顺序相同、命中即停，因此
`passed` 相同，`violations` 的 `rule/kind/evidence` 也相同。`mode="naive"`
时两边都走 naive；同样由定理 G(b) 的推论一致。

> **定理 G(c)**：在 A-G0–A-G5 下，Python 参考评估器与 Rust 电路评估器对
> `pattern_block` 的判定一致。`∎`

## 18. E12 差分模糊测试的覆盖边界

### 18.1 名称与现状

- 任务书称 **E12**；仓库计划中的同一项是 **P2-03 差分模糊测试**（V1 owner，
  产出 `tests/test_fuzz_*.py`，判据“Python↔Rust 0 mismatch；覆盖率”）。
- 截至本底稿（`4988ee2`），仓库里**没有** `tests/test_fuzz_*.py`；
  [`tests/test_nfa.py`](../../tests/test_nfa.py) 只做 Python NFA vs Python `re`，
  [`tests/test_ablation.py`](../../tests/test_ablation.py) 只做 Python
  pike vs naive、以及（二进制存在时）Rust pike vs Rust naive。
- 因此：**E12 是尚未完成的实验债，不能当作定理 G(c) 的已覆盖证据**。

### 18.2 E12 应该覆盖什么

| 维度 | 生成器/判据 | 对应主张 |
|---|---|---|
| 合法 pattern | 文法随机生成：字面量、转义、`.`、字符类、分组、分支、量词、嵌套 | G(a)(b) |
| 非法 pattern | 锚点、反向引用、环视、未闭合分组/类、坏区间、坏量词 | 解析器 fail-fast |
| 文本 | ASCII、非 ASCII、空串、边界码点（0、0x10FFFF、区间端点）、长文本 | G(a)(b) |
| 空匹配 | `a*`、`(a|)`、可空嵌套 | G(b) 的 `i=j` 分支 |
| 多 pattern | 随机条数、命中/不命中混合、顺序 | G(c) 的证据归因 |
| 规范字节 | 随机策略 → `canonical_spec_bytes` → JSON 往返 → 再哈希 | A-G5 / 序列化 |
| 跨层 | Python `match_search` vs Rust `nfa_match`（`pop-script --check`） | G(c) |
| 对照 | Python `match_search` vs `re.search` | G(a)(b) 的语义桥 |
| 消融 | Python pike vs naive；Rust pike vs naive | G(b) 推论 |

**判据**：0 mismatch；覆盖率按（语法构造 × 文本类别）报告；失败样例必须
最小化并落盘。

### 18.3 哪些部分由纸面证明、哪些由 E12 覆盖

| 主张 | 纸面证明 | 现有测试 | E12 能补什么 |
|---|---|---|---|
| 解析器健全性 | 引理 G.1（草图） | `test_nfa.py::TestFailFast` | 随机语法/非法输入的 fail-fast |
| Thompson 语言保持 | 引理 G.2（完整归纳） | 无（测试不能证明全称） | 不能替代；只能抽样回归 |
| Pike 搜索语义 | 引理 G.3（完整不变式） | `test_nfa.py` 276 组合 | 随机语料的抽样验证 |
| Python vs `re` | 引理 G.4（A-G1 下） | 276 组合 | 更大语料、边界码点 |
| Python vs Rust 算法 | 引理 G.5（bisimulation） | **无直接对拍** | 核心覆盖：0 mismatch |
| 实际 Rust 代码 | 不在纸面证明内 | Rust pike vs naive（条件运行） | 端到端差分 |
| 序列化契约 | §17.1 的数据流 | `test_serialize.py`、`test_nfa_cache.py` | JSON 往返/规范字节 |
| 空字符类 | **不成立**（§12.3） | 无 | 必须修代码后才能覆盖 |

**结论**：

- (a) 的 Thompson 部分、(b) 的搜索语义、(c) 的算法层是**纸面证明**；
- 实际 Rust 实现的逐行正确性、序列化/反序列化的字节一致性、边界码点行为
  是**实验覆盖**；
- E12 不能证明全称正确性，只能提高“没有发现反例”的置信度。论文里应写成
  “纸面证明 + 差分模糊证据”，不能写成“已形式化验证”。

## 19. 定理 G 的证明债

| # | 债 | 影响 | 需要的假设/修复 |
|---|---|---|---|
| G-1 | 空字符类 `[^\d\D]` 被当成 ε | 定理 G(a)(b) 在空类上**不成立** | 引入 `Empty` 与 `Eps` 区分，或解析器拒绝空类（A-G0） |
| G-2 | 解析器错误类型不一致 | `a{x}` 抛 `ValueError` 而非 `RegexSyntaxError`，`compile.py` 只捕获后者 | 统一异常类型；fail-fast 测试覆盖 |
| G-3 | Rust `in_ranges` 假设 ranges 已排序/不交 | 手搓不合契约的 spec 可能跨层不一致 | 电路内校验 ranges 有序/不交，或拒绝 |
| G-4 | 孤立代理项 | Python 可表示，Rust 不可 | A-G3：输入/策略为合法 UTF-8 |
| G-5 | 非 ASCII 的 `\w\d\s` | Python Unicode 语义 vs 实现 ASCII | A-G1：目标场景 ASCII，或文档化差异 |
| G-6 | 无 E12 | 实际 Rust 代码没有 Python↔Rust 差分证据 | 落地 `tests/test_fuzz_*.py`（P2-03） |
| G-7 | Rust 无形式化验证 | bisimulation 是算法层，不是代码行 | 论文写“算法证明 + 差分实验” |
| G-8 | 缓存对象可变 | 共享 spec 若被就地修改，跨层字节漂移 | 只读契约；`test_nfa_cache.py` 已钉住 |
| G-9 | `{m,n}` 展开/递归深度 | 大 `n` 导致状态爆炸/递归超限；是资源问题，不是语义问题 | 资源上限；论文不声称复杂度 |
| G-10 | `find_spans` / `_anchored_end` 的“最长”语义 | 用于脱敏掩码；Python `re.search` 是 leftmost-first，不是 longest | 掩码正确性由 `mask_covered`/`anchored_full_match` 承担，不并入定理 G |
| G-11 | `re` 版本/Unicode 数据 | 非 ASCII 语义可能随 Python 版本漂移 | A-G1 限定 ASCII |
| G-12 | 空连接与空语言的 AST 表示 | 与 G-1 同源；影响 Thompson 的 `Lit([])` 分支 | 修复 AST 表示 |

---

## 20. 证明债总表（D + G）

### 20.1 定理 D

| 债 | 论文必须写的限制 | 关闭条件 |
|---|---|---|
| D-1 | ROM heuristic | 标准模型承诺 / 明确 heuristic |
| D-2 | 同一 `T` / public T-view | 游戏定义修正 |
| D-3 | `violations/delegated` 泄露 | L2 披露 / 纳入 `D`（E4） |
| D-4 | `core` 不隐藏见证 | `groth16/plonk`（E1） |
| D-5 | P-PP 登记未落地 | 透明日志/签发记录（P1-13） |
| D-6 | 旧包无盐 | 重新签发 |
| D-7 | 域分隔 | 统一前缀或说明 |
| D-8–D-14 | 见 §10 | 见 §10 |

### 20.2 定理 G

| 债 | 论文必须写的限制 | 关闭条件 |
|---|---|---|
| G-1 | 空字符类边界 | 修 AST/解析器 |
| G-2 | 异常类型 | 统一 `RegexSyntaxError` |
| G-3 | ranges 契约 | 电路校验 |
| G-4 | 孤立代理项 | 合法 UTF-8 假设 |
| G-5 | 非 ASCII 语义 | ASCII 假设/文档 |
| G-6 | E12 未落地 | P2-03 |
| G-7 | Rust 未形式化 | 差分实验 + 措辞 |
| G-8–G-12 | 见 §19 | 见 §19 |

---

## 21. 论文附录的写作建议（给 P）

1. **定理 D 的陈述**用 §2.2 的修正读法；不要原样照抄 D5 的“任意同判定
   `T₀,T₁`”，否则审稿人会用 `b=B(n,T)` 一行反驳。
2. **条件 2 必须点名 `core` 不满足**。把“加盐”写成“策略隐私已解决”会被
   E1 的 trace 探针直接打脸（框架 §7.3 的原话）。
3. **枚举界**用 §8.4 的修正公式；保留“工作量 ×2^128”的定性结论，不要写
   `/2^{λ+128}` 的精确指数。
4. **定理 G 的编号**与 P 统一；(a)(b) 写成 Proposition/Theorem，(c) 的
   实际 Rust 代码部分写成“算法证明 + 差分实验”，不要写成“已验证”。
5. **引用标准件**：Thompson NFA、Pike VM、ROM 隐藏、猜测熵界；
   不要把标准构造包装成新定理（框架 §14）。
6. **证明债**按 §20 的表格原样进附录的限制节；这是论文诚实性的一部分。

---

## 附录 A：本文引用的代码位置速查

| 主题 | 文件 | 关键位置 |
|---|---|---|
| 策略模型/盐字段 | [`policydsl/core/model.py`](../../policydsl/core/model.py) | `policy_nonce` 字段 `:316`；校验 `:324-333`；`from_dict` `:391` |
| 规范字节/哈希 | [`policydsl/core/compile.py`](../../policydsl/core/compile.py) | `canonical_spec_bytes` `:43-62`；`_assemble` `:284-301`；`compile_policy` `:304-312` |
| 带盐承诺原语 | [`policydsl/privacy/policy_commit.py`](../../policydsl/privacy/policy_commit.py) | 盐长度 `:46`；生成 `:55-59`；附带 `:62-70`；提交 `:73-80`；开示 `:83-89`；规范字节 `:92-96`；域分隔 `:99-114` |
| 证书载荷 | [`policydsl/evidence/cert.py`](../../policydsl/evidence/cert.py) | `build_payload` `:246-257`；`policy` `:248`；`policy_hash` `:249` |
| 多证明者切片 | [`policydsl/proofs/multiparty.py`](../../policydsl/proofs/multiparty.py) | `policy_nonce` 传递 `:208` |
| 策略隐私测试 | [`tests/test_policy_commit.py`](../../tests/test_policy_commit.py) | 三组枚举攻击 `:131-163`；向后兼容 `:56-69` |
| 枚举基准 | [`bench/bench_policy_leak.py`](../../bench/bench_policy_leak.py) | E4a |
| NFA 解析/构造 | [`policydsl/core/nfa.py`](../../policydsl/core/nfa.py) | 解析器 `:131-284`；Thompson `:298-375`；Pike `:543-576`；naive `:686-695` |
| pattern_block 编译 | [`policydsl/core/compile.py`](../../policydsl/core/compile.py) | `:212-233` |
| 参考判定 | [`policydsl/core/evaluate.py`](../../policydsl/core/evaluate.py) | `pattern_block` `:191-202` |
| Rust NFA | [`circuits/types/src/lib.rs`](../../circuits/types/src/lib.rs) | `NfaSpec` `:199-219`；`nfa_match` `:567-597`；`nfa_match_naive` `:528-563`；`PatternBlock` 判定 `:807-823` |
| Rust 输入/公开值 | [`circuits/types/src/lib.rs`](../../circuits/types/src/lib.rs) | `ConstraintSpec` `:393-400`；`spec_canonical` `:424`；`parse_spec` `:1765`；`run_job` `:1784-1795` |
| SP1 guest | [`circuits/program/src/main.rs`](../../circuits/program/src/main.rs) | 私有 `Job` 读入、`Outcome` 提交 |
| Python vs `re` 测试 | [`tests/test_nfa.py`](../../tests/test_nfa.py) | `test_corpus_agrees_with_re_search` |
| pike vs naive 测试 | [`tests/test_ablation.py`](../../tests/test_ablation.py) | `TestMatcherParity`；Rust 条件测试 `TestRustNaivePath` |
| 转移表等价测试 | [`tests/test_nfa_transition_table.py`](../../tests/test_nfa_transition_table.py) | 旧实现/naive 对拍 |
| 规范字节测试 | [`tests/test_serialize.py`](../../tests/test_serialize.py) | `test_pattern_block_carries_compiled_nfa` |
| 缓存只读测试 | [`tests/test_nfa_cache.py`](../../tests/test_nfa_cache.py) | 缓存对象逐字节一致 |
| 框架 D 陈述 | [`../certificate-binding-framework.md`](../certificate-binding-framework.md) | D5、§7 |
| 三方模型 | [`../security-model.md`](../security-model.md) | §4.6 |
| 证明工件泄露 | [`../sp1-zk-audit.md`](../sp1-zk-audit.md) | §2–§3 |
| NFA 契约叙述 | [`../../paper/proof-of-policy.md`](../../paper/proof-of-policy.md) | §4.2、§5.2 |
| 并行分工 | [`../plan-parallel.md`](../plan-parallel.md) | T3、V1/P2-03 |
