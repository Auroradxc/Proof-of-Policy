# 05 · ZK 电路层（SP1 / Rust）

> 覆盖 `circuits/` 整个 workspace：`types`、`program`、`infer-program`、`script`、`verifier`、`patches/`。
> 这一板块回答：**Python 侧编译出的契约，怎么在 zkVM 里跑出同一个结论，并变成一份可验证的证明。**
>
> **三个 guest 程序**（P1-6 起两个，P2-10 起三个）：`pop-program` 判策略合规，
> `pop-infer` 证代理推理的前向完整性，`pop-session` 证**一组证书**的跨证书一致性。
> 它们**必须**是三个程序 —— 见 §3.0 的键分离论证。

---

## 1. 职责与 workspace 布局

```
circuits/
├── Cargo.toml          # workspace：members = types / program / infer-program / session-program
│                       #   / script / verifier + [patch.crates-io] tempfile（见 §6）
├── types/    pop-types  # 共享判定逻辑（no_std + alloc）：审计对象、NFA、evaluate、evaluate_private
│                        #   + 代理推理域（P1-6）：infer_forward / infer_input / infer_model_hash…
│                        #   + 会话域（P2-10）：merkle_root / run_session / CertView…
├── program/  pop-program# zkVM guest①：只收策略任务（Public/Private）→ run_job → commit(Outcome)
├── infer-program/ pop-infer # zkVM guest②：只收推理任务（P1-6）→ 断言域 → run_infer → commit
├── session-program/ pop-session # zkVM guest③：只收会话任务（P2-10）→ 断言域 → run_session → commit
├── script/   pop-script # 宿主驱动：--check / --execute / 出证 / --verify，--job policy|infer|session
├── verifier/ pop-verify # 仅验证器二进制（compressed/groth16/plonk）
└── patches/tempfile     # 上游补丁（sp1-prover 6.7.0 需要 TempDir::keep()）
```

设计核心：**guest 只做三件事**（读输入、**断言域**、调用 `pop-types`、提交输出），
全部判定逻辑放在 `types` 里，因此同一份代码既能编进 RISC-V guest，也能编进宿主驱动
（`pop-script --check` 就是直接在宿主机上跑 `run_job`，不生成证明）。

```rust
// program/src/main.rs —— 就是这几步
sp1_zkvm::entrypoint!(main);
pub fn main() {
    let job: Job = io::read();       // 私密输入：不进入公开值
    assert_eq!(job_domain(&job), DOMAIN_POLICY,
        "pop-program 只接受策略合规任务（Public/Private）；推理任务请交给 pop-infer");
    let out: Outcome = run_job(&job); // 共享判定逻辑
    io::commit(&out);                // 公开值：验证者可读
}
```

`infer-program/src/main.rs` 与 `session-program/src/main.rs` 形状相同，只把断言换成
`== DOMAIN_INFER` / `== DOMAIN_SESSION`。**这一行断言是键分离的落点**：它让
「这个程序能出哪一域的证明」成为 **vkey 层面的既成事实**，而不是宿主驱动里的一句约定
—— 见 §3.0。

---

## 2. `pop-types`：共享类型与判定（`types/src/lib.rs`，1752 行）

### 2.1 类型清单

| 类型 | 说明 |
|---|---|
| `ToolReceipt { seq, tool, args: BTreeMap<String,String>, result_digest, ts, prev, keyid }` | **网关签发的工具回执**（P1-5；链的元素）。`sig` **不在**结构体里 —— 电路内不验签，字段被 serde 忽略 |
| `FormatKind { Json, Int, Float }` | `format_check` 的格式（snake_case 序列化） |
| `BudgetUnit { Calls, Tokens }` | `budget_bound` 的计量单位 |
| `NfaSpec { start, accept, states }` / `NfaState { eps, edges }` / `NfaEdge { to, ranges }` | **可序列化 NFA 契约**（由 `policydsl.nfa` 产出） |
| `PatternMode { Pike, Naive }` | 匹配模式（默认 `Pike`） |
| `Constraint` | 七种变体的枚举（见下表） |
| `BoundDirection { Le, Ge }` | `semantic_bound` 的判定方向（P2-9）。两值枚举而非布尔/带符号阈值 |
| `DelegatedConstraint { name, system, model_vkey, onnx_sha256, threshold_bp, direction }` | **被委托给外部证明系统的约束**（P2-9）。`system` 为 `ezkl-halo2`（`SEMANTIC_SYSTEM_EZKL`） |
| `ProofRequest { response, constraints, nonce, receipts }` | 公开模式输入（`nonce` 为 P0-2 挑战值，`serde(default)`；`receipts` 为 P1-5 回执链）。**`deny_unknown_fields`** |
| `Violation { rule, kind, evidence }` | 违规（证据为**字符串**） |
| `ProofOutput { policy_hash, response_binding, trace_root, passed, violations, delegated }` | 公开模式输出（提交为公开值；`trace_root` 为链尾摘要，空链为 `"genesis"`；`delegated` 为本次判定中被委托出去的约束，空 = 这份证明自足） |
| `PrivateViolation { rule, kind, evidence_commitment }` | 私有模式的违规（只有承诺） |
| `RedactionProof { redacted_commitment, mask_count, redaction_ok, mask_covered }` | 脱敏证明 |
| `PrivateRequest { response, constraints, nonce, mask, redacted, spans, receipts }` | 私有模式输入（`nonce` 同上）。**`deny_unknown_fields`** |
| `PrivateOutput { policy_hash, response_binding, response_commitment, trace_root, passed, violations, redaction }` | 私有模式输出 |
| `Job { Public(ProofRequest), Private(PrivateRequest), Infer(InferRequest), Session(SessionRequest) }` | 调度枚举。前两态属**策略域**、`Infer` 属**推理域**（P1-6）、`Session` 属**会话域**（P2-10）；三个 guest 各只收自己那一域 |
| `Outcome { Public(ProofOutput), Private(PrivateOutput), Infer(InferOutput), Session(SessionOutput) }` | 顶层承诺结果 |
| `InferRequest { response, nonce }` | 推理任务的输入（P1-6）。**没有**「输入向量」字段 —— 输入由图内从 `response` 导出，见 §2.5c |
| `InferOutput { model_hash, response_binding, input_binding, output }` | 推理任务的公开值（`output` 是 `OUT_DIM` 个定点数） |
| `SessionRequest { certs: Vec<String>, nonce }` / `CertView` / `SessionOutput` | **会话域**（P2-10）：输入是每张证书规范载荷的**文本**，输出是 Merkle 聚合与三条义务的结论。见 §2.6 |

`Constraint` 的七个变体与字段（**与 `01` 的规则一一对应**）：

```rust
KeywordBlock  { name, keywords }
LengthBound   { name, min, max }
PatternBlock  { name, patterns, specs: Vec<NfaSpec>, mode: PatternMode }
FormatCheck   { name, format: FormatKind }
ToolArgGuard  { name, tools, forbidden_fields }
BudgetBound   { name, budget, unit: BudgetUnit }
SemanticBound { name, model_vkey, onnx_sha256, threshold_bp, direction }   // P2-9：委托
```

前六个是电路**自己判定**的；第七个 `SemanticBound`（P2-9）**不判定**，
只登记进公开值 —— 见 §2.3b。

序列化为 serde 的**内部标签**枚举（`#[serde(tag = "kind", rename_all = "snake_case")]`，
即 `{"kind": "keyword_block", ...}`）—— 直接吃 `policydsl/compile.py` 产出的形状，
**没有中间映射层**。

### 2.1a 策略怎么进来：规范字节，而不是结构化字段

guest 读到的 `spec_canonical` 是一段**规范 JSON 字节**（`compile.canonical_spec_bytes`：
键排序 + 紧凑分隔符；纯 ASCII）。从这**同一段字节**同时得到两样东西：

1. `policy_hash = SHA256(字节)` → 进公开值（`ProofOutput`/`PrivateOutput`）；
2. 反序列化出的 `SpecConstraint` 列表 → 实际参与判定。

二者同源、不可分离。这是 P0-1 的核心：若策略以「独立的结构化字段」传入而公开值里
不含其哈希，证明者就能用空策略（恒通过）判定、再在证书里声称哈希对应真实策略 ——
证明的义务会退化成「存在某个策略通过」，而非「策略 π 通过」。
回归测试见 `tests/test_policy_binding.py`。

### 2.2 NFA 匹配（`nfa_match` / `nfa_match_naive`）

两个函数**语义相同**，都实现「无锚点的存在性搜索」（对齐 `re.search`）：

| 函数 | 复杂度 | 用途 |
|---|---|---|
| `nfa_match` | **O(n·states)** | Pike VM：单趟扫描，状态集合并行推进；每个字符位置都重新允许从 `start` 出发 |
| `nfa_match_naive` | **O(n²·states)** | 消融对照：每个起点重新锚定跑一遍 |

- `eps_closure(spec, seeds) -> Vec<bool>` 计算 ε-闭包（布尔向量，比集合更快）。
- `in_ranges(cp, ranges)` 依赖区间**按 lo 升序**做线性扫描（`policydsl.nfa` 保证了这一点）。
- 二者的等价性是消融实验有意义的前提，由 `tests/test_ablation.py` 与
  `tests/test_ablation.py::TestRustNaivePath` 保证。

### 2.3 判定 `evaluate(req) -> ProofOutput`

逐约束执行，**镜像 `policydsl.evaluate.check`**：

| 变体 | 判定 | 证据字符串 |
|---|---|---|
| `KeywordBlock` | `ascii_lower(response).contains(kw)`，取第一个命中 | 命中的关键词 |
| `NormalizedKeywordBlock` | **先折叠**（`folded_text`，表来自约束）再 `ascii_lower(..).contains(kw)`；先做 `validate_folding_spec` 结构校验（未知版本/表过大/非 ASCII 替换值 ⇒ panic，fail-closed） | 命中的关键词（**折叠后**的形式） |
| `LengthBound` | `response.chars().count()` 是否在 `[min,max]` | `"len=<N>"` |
| `PatternBlock` | 按 `specs` 顺序匹配，命中即记并 `break` | 命中的模式串 |
| `FormatCheck` | `parse_json_ok` / `parse_int_ok` / `parse_float_ok` | 格式名 |
| `ToolArgGuard` | **先验链结构**（`verify_receipt_chain`）：不自洽 → `trace_unbound` 并 `continue`；否则 `tools` 非空时限定范围，命中被禁字段即记（每个回执至多一条） | `"<tool>:<field>"` |
| `BudgetBound` | `calls` → 同上先验链，然后 `receipts.len()`；`tokens` → `token_count(response)`（电路内自算，见 §2.3a） | `"<unit>=<total>/<budget>"` |

`passed = violations.is_empty()`。此外输出里总带一条 `response_binding`（见 §2.5a）与 `trace_root`（§2.5b）。
若链结构不自洽而**没有任何工具规则**兜住它（策略里没有工具类规则），末尾会补一条
`rule="<trace>"`、`kind="trace_unbound"` 的合成违规 —— 保证「链坏了」这件事**永远**不会因为策略恰好不查工具
而被静默放过（fail-closed）。

### 2.3a `verify_receipt_chain` 与 `token_count`（P1-5）

```rust
verify_receipt_chain(rs) -> Result<(), String>
// 逐条：seq 必须 == 下标；prev 必须 == 前一条的 receipt_digest（首条 == "genesis"）
// 失败原因字符串与 Python trace.chain_ok 逐字符相同："receipt {i}: seq={seq} != {i}" / "receipt {i}: prev mismatch"
```

`receipt_digest = SHA256(canonical_receipt_bytes(r))`，编码为
`TRACE_DOMAIN(b"pop-trace-v1") ‖ u32_be(seq) ‖ lp(tool) ‖ u32_be(len(args)) ‖ [lp(k)‖lp(v)]_按键升序 ‖
lp(result_digest) ‖ lp(ts) ‖ lp(prev) ‖ lp(keyid)`（`lp` = `u32_be(len)‖data`，长度前缀消除拼接歧义）。
与 `policydsl.trace.canonical_receipt_bytes` **逐字节一致**，由 `tests/test_trace.py::test_full_chain_parity`
实测核对（`trace_root` 是这串字节的哈希，任何编码差异都会让它对不上）。

`token_count(text)`：把 UTF-8 字节按固定空白集 `{0x20, 0x09, 0x0a, 0x0b, 0x0c, 0x0d}` 切分，数非空白
run 的个数。**不用** Unicode White_Space（随 Unicode 版本漂移），也**不是**任何真实分词器。

> ⚠️ 电路内**不验签名**（zkVM 内 Ed25519 代价高）：结构校验只保证链自洽，不保证回执由网关签发。
> 后者由链下 `trace.verify_chain` 与公开值里的 `trace_root` 共同承担，见 `docs/security-model.md`。

**规范子集解析器**（必须与 Python 侧逐字节一致，见 `01` §4）：

```rust
parse_int_ok(s)   // trim → 可选 +/- → 1..=19 位 ASCII 数字
parse_float_ok(s) // trim → 非空、无 '_'、不含 nan/inf（忽略大小写）→ f64 解析
parse_json_ok(s)  // serde_json::from_str::<Value>（拒绝 NaN/Infinity）
```

### 2.3b 语义规则的**委托** `SemanticBound`（P2-9）

`semantic_bound`（「回复的语义有害概率不得高于阈值」这类规则）**无法在 SP1 里判定** ——
判定要跑一遍 ONNX 前向，那是 ezkl/halo2 的地盘。所以电路对它的处理是**登记而非判定**：

```rust
SpecConstraint::SemanticBound { name, model_vkey, onnx_sha256, threshold_bp, direction } => {
    delegated.push(DelegatedConstraint {
        name: name.clone(), system: SEMANTIC_SYSTEM_EZKL.into(),
        model_vkey: model_vkey.clone(), onnx_sha256: onnx_sha256.clone(),
        threshold_bp: *threshold_bp, direction: *direction,
    });
}
```

三处刻意的设计：

1. **不 push `violation`**。用「未判定」表达这条规则，会让 `passed` 变 `false`，
   而 `passed = false` 的语义是「策略被**违反**」—— 那不是事实（我们并不知道它是否被违反）。
   `delegated` 是一个**独立**字段，专门表达「未判定」。
2. **字段全量重复一遍**（`model_vkey` / `onnx_sha256` / `threshold_bp` / `direction`
   在约束和公开值里各出现一次）。公开值因此**自足**：验证方不必从别处取值来比对，
   否则「比对」就退化成「信任另一处声明」。
3. **进公开值而不是只写在证书里**。证书是出证方写的，公开值是电路算的。只有后者能让
   第三方**独立**看出「这份证明需要陪伴」。「遇到了就跳过」的做法下，一个只跑 `pop-verify`
   的第三方会把这份证明当成一条**完整**的合规证明 —— 而策略哈希承诺的是整份规范字节
   （含语义规则），所以验证方拿策略包就知道 π 里有语义规则，「跳过」不会掉包 π，
   但足以让**只验 SP1 的人**得出错误结论。

`delegated` 非空时的语义（`types/src/lib.rs` 的 doc comment 原文口径）：

> `passed` 只反映**电路内可判定的**那部分约束。一份 `passed = true` 且 `delegated` 非空
> 的证明，**不等于**策略被满足 —— 它等于「电路内那部分满足了，剩下的几条请去核陪伴证明」。
> 验证方必须对 `delegated` 里每一条都找到匹配的陪伴证明并验证，否则必须拒绝（fail closed）。

怎么合取、陪伴证明长什么样、失败形态有哪些，见
[`../design-semantic-rules.md`](../design-semantic-rules.md) 与 [`07`](07-cli-scripts.md) §2.5。

### 2.4 私有模式 `evaluate_private(req) -> PrivateOutput`

**v1 边界（P2-9）：含语义规则的策略只支持公开模式。** 函数第一件事就是把这类请求
**panic 掉**（guest panic ⇒ 产不出证明，fail closed）：

```rust
if let Some(SpecConstraint::SemanticBound { name, .. }) =
    constraints.iter().find(|c| matches!(c, SpecConstraint::SemanticBound { .. }))
{
    panic!("语义规则 '{}' 需要公开模式：ezkl 陪伴证明必须把 encode(T) 放进公开实例，\
            否则验证方无法把证明绑到响应上（信任边界 ③）。…", name);
}
```

理由是一个不相容对：陪伴证明的公开实例里**必须**有 `encode(T)`（否则验证方只能相信
出证方转述的一个分数，那正是 P0-1 的形态），而私有模式承诺的正是「响应不进公开值」。
两条同时满足不可能，所以拒绝 —— 而不是**悄悄略过**语义约束，后者会产出一份
`passed = true` 却没有判定语义规则的私密证书，看上去完全正常。

> ⚠️ 这同时是一条**隐私**边界，且与上面的论证是同一条：`features.encode` 在词表上**单射**，
> 所以公开实例里的 `encode(T)` 可被反查词表还原出原文（同形异义正是**不**同的码点，
> 折叠不了）。语义规则因此**只有公开模式**这一种形态。详见
> [`../design-semantic-rules.md`](../design-semantic-rules.md) §3。

编译期还有一道同样的检查（`policydsl/compile.py`，报错更友好）；电路内这道是兜底 ——
手写的 `PrivateRequest` 绕不过编译期检查。回归见 `tests/test_semantic.py`。

~~解决路径（未做）~~：`P2-9b 同形异义折叠`**已交付**（2026-09-11）——
`normalized_keyword_block` 把同形异义字/零宽字符/全角折叠成 ASCII 后再做子串判定，
**折叠表随约束走**（`fold` 字段进规范字节、进 `policy_hash`），且全电路内、零依赖。
设计见 [`../design-semantic-rules.md`](../design-semantic-rules.md) §1–§3 与 §10，代码见
`policydsl/normalize.py`（表构造）+ `pop-types::folded_text` / `SpecConstraint::NormalizedKeywordBlock`
（`circuits/types/src/lib.rs`，执行）；验收在 `tests/test_semantic.py` 与
`cross_validate` 的 `norm_*` 向量（host 19/19 · prove 19/19）。

再往下是正常流程：复用 `evaluate` 算出公开结论，再**只保留承诺**：

```rust
violations = public.violations.map(|v| PrivateViolation {
    rule: v.rule, kind: v.kind,
    evidence_commitment: sha256_hex(&v.evidence),   // 证据明文不出电路
});
response_commitment = sha256_hex(&req.response);    // 只说明「存在某条 T」，不说「哪条」
```

`policy_hash` / `response_binding` / `passed` 三项直接从 `public` 克隆 —— **两种模式承诺的
同名字段必须逐字节相同**，否则同一份证明换个模式就能得出不同结论。

脱敏证明（仅当提供了 `redacted`）：

```rust
covered = spans_valid(&constraints, &chars, &spans)   // 每个 span 都是真实完整匹配
       && mask_within_spans(&mask, &spans);           // mask ⊆ spans
RedactionProof { redacted_commitment: sha256_hex(red),
                 mask_count: mask.len(),
                 redaction_ok: redaction_ok(response, red, &mask),
                 mask_covered: covered }
```

`redaction_ok` 与 `anchored_full_match` 分别镜像 `commit.redaction_ok` 与 `nfa.anchored_full_match`
（等长、掩码位为 `*`、其余不变；两端锚定且至少消耗 1 字符）。详见 [`02-privacy-commitment.md`](02-privacy-commitment.md)。

### 2.5a 挑战-响应绑定 `response_binding`

```rust
pub const BIND_DOMAIN: &[u8] = b"pop-bind-v1";

pub fn response_binding(nonce: &[u8], response: &str) -> String {
    let mut h = Sha256::new();
    h.update(BIND_DOMAIN);
    h.update((nonce.len() as u32).to_be_bytes());   // ← 长度前缀，见下
    h.update(nonce);
    h.update(response.as_bytes());
    hex(&h.finalize())
}
```

公开值与私有值里都有它，值一样。它与 `response_commitment` 解决**两个不同问题**：

| 字段 | 公式 | 回答的问题 |
|---|---|---|
| `response_commitment` | `SHA256(T)` | 「**存在**某条响应通过了吗」 |
| `response_binding` | `SHA256(domain ‖ len ‖ nonce ‖ T)` | 「通过的**是这一条** T 吗」（会话绑定） |

两者都需要：只留后者，验证者无法在需要时**单独开示**「是这条 T」而不泄露 nonce 之外的
会话结构；只留前者，就是 P0-2 之前的漏洞状态 —— 证明的 T 与送达的 T′ 毫无联系。

`nonce.len()` 的 4 字节大端前缀不是装饰：没有它，
`(nonce=b"ab", T="cd")` 与 `(nonce=b"abcd", T="")` 会哈希成同一个值，
`(nonce, T) → 字节串` 就不是单射。加了前缀，任意长度组合都无歧义。

域前缀 `BIND_DOMAIN` 同样必要：P1-5 的工具轨迹用的正是**同一套原语 + 另一段前缀**
（`TRACE_DOMAIN = b"pop-trace-v1"`），域前缀保证了两个域的哈希**永不碰撞** ——
否则同一条字符串在两边可能算出同一个承诺，绑定就串了域。

`nonce` 是 `#[serde(default)]` 的，所以旧向量（没有该字段）照样能解析，只是绑定退化成
「空挑战的承诺」。Python 侧对应实现是 `commit.response_binding`；
逐字节一致性由 `tests/test_binding.py::TestPythonRustParity` 真跑 `pop-script --check` 钉死
（多种 nonce 长度，公开 + 私有两条路径）。

### 2.5b 轨迹绑定 `trace_root`

`trace_root` = **链尾那条回执的 `receipt_digest`**（空链为字面量 `"genesis"`），公开值与私有值里都有它，
值一样。它与 `response_binding` 的作用**完全对称**：

| 字段 | 绑定的是 | 验证方怎么核对 |
|---|---|---|
| `response_binding` | 被判定**响应** T（+ 挑战值） | 拿送达的 T′ 与 nonce 重算 |
| `trace_root` | 工具**回执链**的链尾 | 拿**网关侧收到的回执**重算最后一条的摘要 |

链长了也不需要把链塞进公开值：验证方本来就持有网关发给它的回执，重算链尾即可比对，
这与「不公开整条响应、只公开承诺」是同一个思路。链尾（而不是整条链的 Merkle 根）够用，是因为
`prev` 已把整条链串成一条哈希链 —— 链尾摘要**已经**承诺了它之前的所有内容。

### 2.5c 代理推理域 `Infer`（P1-6）

`pop-types` 里另有一小块**与策略判定完全无关**的逻辑：一个**确定性定点 MLP 前向**。
它回答的不是「T 符不符合 π」，而是「（某张图）在 T 上算出的输出是不是这个」——
组合义务 `Compose = (推理完整性 ∧ 策略合规)` 的**后一半**。

| 常量 / 函数 | 说明 |
|---|---|
| `INFER_DOMAIN = b"pop-infer-v1"` | 推理域的域分隔前缀（与 `BIND_DOMAIN`/`TRACE_DOMAIN` 同思路，保证跨域哈希永不碰撞） |
| `INFER_FRAC_BITS = 16`，`INFER_{IN,HID,OUT} = 16/32/4` | **Q16 定点**，全整数运算 —— 没有浮点，宿主/guest、Rust/Python 三方才能逐位一致 |
| `INFER_MODEL_SEED`，`INFER_MODEL_SPEC` | 权重种子与模型规范串。**权重不来自输入**，由编译期常量经 `splitmix64` 生成 |
| `infer_model_hash()` | `SHA256(domain ‖ "model" ‖ MODEL_SPEC)` —— 模型指纹 |
| `infer_input(response)` | 由图内从 `response` 导出 `IN_DIM` 个 Q16 输入 |
| `infer_forward(x)` | `x → ReLU(x·W₁) → (·W₂)`，全部定点 |
| `infer_input_binding(nonce, x)` | 输入的承诺（含 nonce） |
| `run_infer(req)` | 组装成 `InferOutput` |

**两个设计点是刻意的**（也就是 L6 的三条信任边界条件的落地）：

1. **权重编进程序** ⇒ 模型身份由 **vkey** 承诺。出证方没有「我用的其实是另一张图」的余地
   —— 对比 P2-9 的 ezkl 委托（那里靠 `onnx_sha256` + vk 指纹承诺模型权重），
   这是**更强**的形式。
2. **输入由图内从 `response` 导出**，不是证明者自填的向量。否则「输出被承诺」
   只说明「存在某个输入得到这个输出」—— 与 P1-5 之前那条自述式 `tool_calls`
   是同一类毛病。

**它同时携带与策略半共用的 `response_binding`**（同一套 `commit.response_binding` 公式、
同一个 nonce）—— 这就是两半能组合的锚点：「说的是同一条 T」由验证方**现场重算**核对，
而不是靠证书自述。

**边界（如实标注）**：这是一个 16→32→4 的小 MLP，是**stand-in**，不是 zkAgent（D1）。
它证明的是「**这张**图在**这条**响应上确实算出**这个**输出」，**不保证模型质量**
（没有数据训练过它）。成本结论的限度见 `bench/results/compose.md`。
Python 参考实现是 `policydsl/infer.py`，逐位一致性由 `tests/test_compose.py::TestInferParity`
真跑 `pop-script --check --job infer` 钉死。

### 2.5 `sha256_hex`

手写十六进制输出，**与 `hashlib.sha256().hexdigest()` 字节级一致**（小写、无前缀）——
这是 Python 与 Rust 承诺能对上的前提。

### 2.6 会话域 `Session`（P2-10）：一组证书 → 一次证明

| 项 | 说明 |
|---|---|
| `DOMAIN_SESSION = "session"` | 第四域的名字（`Job::Session` 的域标签） |
| `MERKLE_NODE_DOMAIN = b"pop-session-node-v1"` | Merkle **内部节点**的域前缀；叶子**不加**前缀（叶子就是证书摘要本身） |
| `merkle_root(leaves)` | 内部节点 `SHA256(前缀 ‖ left32 ‖ right32)`；**奇数末位提升、绝不复制** —— 复制会让 `[a,b,c]` 与 `[a,b,c,c]` 同根，等于给「删掉链尾」开一条伪造路径 |
| `SessionRequest { certs: Vec<String>, nonce }` | 输入是每张证书 `cert.canonical(payload)` 的**文本**（不是结构体） |
| `CertView { policy_hash, streaming, trace_seal }` | guest 侧只解析**判定义务所需**的三个字段 |
| `run_session(req)` | 三条义务的判定本体（下面） |
| `SessionOutput` | 公开值：`policy_hash` / `cert_count` / `merkle_root` / `session_binding` / `trace_root` / `sealed_count` / `seal_keyid` |

**三条义务**（任一不成立即 `assert!` ⇒ 出不了证明）：

1. **同一策略**：每张证书的 `policy_hash` 等于第 0 张的（空/缺 → 拒绝）；
2. **无缺口**：第 i 张的 `chain.index == i` 且 `chain.prev ==` 第 i-1 张的**叶子摘要**
   （第 0 张为字面量 `"genesis"`）—— 挖中间/换序/换一张都在这里断掉；
3. **末端承诺**：每张证书都带 `trace_seal`，且 `keyid` 全同（同一条会话）。

**为什么叶子是「文本的 sha256」**：guest 收到的是规范 JSON 的**字节**，直接求哈希，
所以 Rust 侧不需要任何 JSON 规范化 —— 与 `spec_canonical` → `policy_hash` 是同一招，
跨语言漂移在结构上不可能（只有一种「字节」）。`CertView` 因此刻意**不做**
`deny_unknown_fields`：载荷还有几十个别的字段，而叶子摘要已经把**整份文本**承诺住了
（多余字段早已进哈希），在这里再拒一次只会误伤合法证书。

**⚠️ 尾截断只有 Merkle 根拦得住**（本域最重要的一条，已实测）：`[0..k]` 前缀的
`chain.index`/`prev` **依然连续**，义务 ①②③ 全部成立 —— **电路本身接受一个被砍掉
尾巴的证书集**（这正是 P1-5b 的截尾问题在会话层的形态）。拦住它的是验证方那一步：
「证明承诺的 `merkle_root` vs 由**交付的**证书集重算的根」。所以 `verify_session_proof`
的根比对**不是冗余检查**，它是这条义务的唯一检测点。

**⚠️ 电路不验网关签名**：`SealView` 里**没有** `sig` 字段 —— zkVM 里没有网关公钥。
电路内只做「带了 seal」+「`keyid` 全同」，把 `(sealed_count, trace_root)` 公开出去；
**「这条链网关真的签过」由链下的 `policydsl.trace.verify_seal` 判**（`verify_session_proof`
只在给了 `keyring`/`receipts` 时才走那一步，没给会如实注明未验签名）。

---

## 3. 三个 guest：`pop-program`、`pop-infer` 与 `pop-session`

### 3.0 为什么必须是**分开的**程序（键分离）

组合义务要求「推理完整性 ∧ 策略合规」两个子义务各自成立。若两半由**同一个**程序产生，
验证方就没有判据回答「这份证明属于哪一半」—— 攻击者可以拿一份策略证明充当推理半
（或反之）而通过全部逐 half 的检查。所以组合证书的验证（`policydsl/compose.py` 第 4 步）
**显式要求两个 vkey 不同**。

但只在验证方加这条检查是不够的：vkey 是**程序**的指纹，只有把这条要求钉进**电路**
才有意义。做法是每个 guest 入口各断言一次自己的域：

| guest | 入口断言 | 只接受 |
|---|---|---|
| `pop-program` | `job_domain(&job) == DOMAIN_POLICY` | `Job::Public` / `Job::Private` |
| `pop-infer` | `job_domain(&job) == DOMAIN_INFER` | `Job::Infer` |
| `pop-session` | `job_domain(&job) == DOMAIN_SESSION` | `Job::Session`（P2-10） |

于是 `vkey_policy` **只可能**产出 `Public`/`Private` 结果，`vkey_infer` **只可能**产出
`Infer` 结果，`vkey_session` **只可能**产出 `Session` 结果 —— 「这份证明属于哪一域」
成了 vkey 层面的既成事实。把另一域的任务喂给错的程序，`deny_unknown_fields` +
断言双重拦下（`tests/test_compose.py::TestDomainSeparationInGuest`）。

会话域同样用**域前缀**做哈希隔离（`MERKLE_NODE_DOMAIN = b"pop-session-node-v1"`，
与 `BIND_DOMAIN`/`TRACE_DOMAIN`/`INFER_DOMAIN` 同思路）：内部节点的哈希与任何别处的
哈希**永不碰撞**。

### 3.1 共同形状

每个 guest 都是「读输入 → 断言域 → 调用 `pop-types` → 提交输出」：

- `io::read()` 读入的是 **`Job`（私密输入）**，不进入公开值；
- `io::commit(&out)` 提交 `Outcome`，即**公开值**；
- guest 自身不做任何 I/O、不做网络、不做时间读取 —— 判定因此是**确定性**的，
  这正是「健全性」论证的支点（`../security-model.md` §2）。

**代价**：`types` 一改，三个 ELF 都变，三个 vkey 都变，`scripts/examples/out/` 下
已入库的证明工件随之失效（只有 `POP_TEST_PROOF` / `POP_TEST_SESSION` 打开的测试会用到，
默认 skip）。**出证成本**：会话域要读入 N 张证书的完整载荷文本并在 zkVM 里解析 N 次 JSON，
比单条策略证明重 —— 3 张证书的 core 证明实测约 2.5 分钟、峰值约 10 GB。

---

## 4. `pop-script`：宿主驱动（`script/src/main.rs`，394 行）

四种模式（`--check` / `--execute` / 默认出证 / `--verify`），共用一套极简命令行解析。

| 参数 | 说明 |
|---|---|
| `--job policy\|infer\|session` | 选哪一域：`policy` → `pop-program`（策略向量，含 `spec_canonical`），`infer` → `pop-infer`（推理向量，含 `response`/`nonce`），`session` → `pop-session`（会话向量，含 `certs` 文本数组 + `nonce`）。**默认 `policy`**；别的值一律 panic（不静默退回默认域）。⚠️ 旗标是 `infer`，而 part 的 kind 是 `inference` —— 两个名字不同，见 `policydsl/compose.py::JOB_FOR_KIND` |
| `--vectors <f>` | 输入向量文件（`{"vectors":[...]}` 或裸数组），默认 `vectors.json` |
| `--out <f>` | 结果 JSON，默认 `results.json` |
| `--proof-out <f>` | 保存证明（**只支持单向量**）+ 边车 + `.meta.json` |
| `--proof-mode core\|compressed\|groth16\|plonk` | 默认 `core` |
| `--proof <f>` + `--verify` | 独立验证模式 |
| `--verify-reps <n>` | 重复验证次数（把 vkey setup 与纯 verify 分开计时） |
| `--check` / `--execute` | 宿主校验 / 只跑 zkVM 记 cycle 数 |

### 模式细节

- **`--check`**：直接 `run_job`，不构造任何证明器。**快，CI 与交叉验证的主力**。
- **`--execute`**：`client.execute(elf_for(job), stdin)`，在结果里附
  `"cycles": report.total_instruction_count()` —— `bench/bench_cycles.py` 的取样来源。
- **出证（默认）**：`client.setup(elf_for(job))` → 按 `--proof-mode` 选 `core/compressed/groth16/plonk`
  → 出证 → **立即本地 `verify` 一次**（确保证明有效）→ 写结果。
  若给了 `--proof-out`：`proof.save(path)` + `write_verifier_sidecar(...)` + `.meta.json`
  （含 `vkey_hash`、`proof_file`、`proof_mode`、`job`）。
- **`--verify`**：从 `elf_for(job)` 重新 `setup` 推导 vkey → 重复 `client.verify(...)` 计时 →
  读回公开值 `Outcome` → 输出 `{verified, vkey_hash, setup_seconds, verify_times_seconds, outcome}`。
  **不需要任何秘密**，这就是第三方验证的入口（也是 core 证明唯一可用的验证路径）。
  ⚠️ `--verify` **必须**带上出证时同一个 `--job`：vkey 是**程序**的指纹，
  用 `--job policy` 去验一份推理证明会得到 vkey 不符（这正是键分离在起作用）。

> ⚠️ **四种证明模式的安全性不同（P0-4 已查证，见 [`../sp1-zk-audit.md`](../sp1-zk-audit.md)）**：
> `core` / `compressed` 是**非零知识**的 STARK（Succinct 官方安全模型明文承认；
> 源码侧 `ShardProof` 把轨迹 Merkle 根 `main_commitment` 与轨迹开值 `opened_values` 明文放进证明，
> 整个 SLOP 栈无任何盲化）。
> `groth16` / `plonk` 把内部 STARK 证明作为 gnark 电路的**私有见证**、只暴露 5 个公开输入，
> 是唯一可能隐藏见证的模式 —— 但属包装器层面声明、未被审计评估、非后量子，且需 ≥16 GB 内存（本机出不了）。
> **对本项目的影响**：**健全性不受影响**（§8 不变量全部成立）；受影响的只是
> **私有模式能宣称什么** —— 见 [`02-privacy-commitment.md`](02-privacy-commitment.md) 与
> `policydsl/commit.py` 的 `private_output` 文档串。

### `write_verifier_sidecar`：verifier-only 的物料

写出四个文件供 `pop-verify` 使用：

| 文件 | 内容 |
|---|---|
| `<proof>.bytes` | `compressed` → `bincode(SP1Proof)`；`groth16/plonk` → 链上字节 |
| `<proof>.pv` | 原始公开值（public values） |
| `<proof>.vkh` | `bincode(vk.hash_koalabear())`（compressed 用） |
| `<proof>.verify.json` | 边车：`{proof_mode, proof_bytes_file, public_values_file, vkey_hash_file, vkey_hash_str}` |

> ⚠️ **边车对所有模式都会写**（含 `core`）。因此走快路径前必须检查 `proof_mode` ——
> 见 [`04-anchoring-audit.md`](04-anchoring-audit.md) §5 与 `policydsl/verifier.py`。

### `build.rs`

```rust
build_program_with_args("../program", Default::default());
build_program_with_args("../infer-program", Default::default());
```

把**两个** guest 各编译成 zkVM ELF，使 `include_elf!("pop-program")` 与
`include_elf!("pop-infer")` 生效。**改动 `types` 后必须重新构建**（两个都要），
否则宿主驱动内嵌的还是旧 ELF —— 而且 **vkey 会跟着变，两个都变**，
`scripts/examples/out/` 下已入库的证明工件随之失效。

---

## 5. `pop-verify`：仅验证器二进制（`verifier/src/main.rs`，147 行）

```
pop-verify --meta <proof>.verify.json [--out result.json]
```

- 只依赖 `sp1-verifier`（**没有** sp1-sdk / Gnark / 证明器状态），因此内存占用与冷启动都远小于 `pop-script`。
- 读边车 → **先校验模式**（`core` 直接 `exit(3)` 并提示改用 `pop-script --verify`）→
  按模式调用 `SP1CompressedVerifierRaw` / `Groth16Verifier` / `PlonkVerifier`。
- 输出 `{verified, proof_mode, vkey_hash, public_values_sha256, public_values_len, proof_bytes_len}`，
  退出码 `0`（通过）/ `1`（验证失败）/ `3`（模式不支持）。

`public_values_sha256` 是证书 `binding.public_values_sha256` 的比对对象（`03` §2）。

---

## 6. 环境与已知坑（复现前必读）

| 坑 | 表现 | 处理 |
|---|---|---|
| `SP1_PROVER=native` | `unreachable` 崩溃 | 用 `SP1_PROVER=cpu`（合法值：cpu/cuda/mock/light/network） |
| `SP1_PROVER=light` | “light prover cannot prove” | light 只能执行/验证 |
| 内存不足 | 进程被 OOM killer 杀、无输出 | Core 需 ~10 GB（本机上限定 12 GB）；compressed/groth16 需 ≥16 GB |
| **一个进程连出多证** | 前面几个都成功、第 6~7 个被 `SIGKILL 9` 杀，峰值 10.65→10.82 GB | 每个证明后内存**缓慢累加**（不回落），单进程跑不完全部向量（当时 14 条）；`cross_validate.py` 因此默认 `--chunk 4`（每块一个干净进程，结果按原序合并） |
| `no method named keep` | `sp1-prover` 编译失败 | 上游 `tempfile` 3.x 无 `TempDir::keep()` → 保留 `circuits/patches/tempfile` 与 `[patch.crates-io]` |
| 缺 `libsp1gnark.a` | 构建失败 | 需 Go ≥1.24 + `GOPROXY=https://goproxy.cn,direct` |
| 缺 `protoc` | 构建失败 | `sudo apt-get install -y protobuf-compiler` |
| 网络限流 | `cargo fetch` 卡住 | 用 rsproxy sparse 镜像（`~/.cargo/config.toml`） |

**实测数字**（24 核 / 12 GB CPU，2026-09-12）：

| 配置 | 证明时间 | 证明大小 | 峰值内存 | 结论 |
|---|---:|---:|---:|---|
| 200 字符 × 1 规则 | 123.5 s | 2716.4 KiB | 10,389 MB | ✅ |
| 200 字符 × 2 规则 | 118.9 s | 2716.9 KiB | 10,438 MB | ✅ |
| 2,000 字符 × 1 规则 | 138.1 s | 2718.6 KiB | 10,449 MB | ✅ |
| 10,000 字符 × 1 规则 | 172.5 s | 2726.6 KiB | 10,506 MB | ✅ |
| 200 字符 × 3 规则 | — | — | — | ❌ OOM |
| 20,000 字符 × 1 规则 | — | — | — | ❌ OOM |

证明时间由证明器**固定开销主导**，随长度/规则数的边际成本体现在 zkVM 周期数上
（见 `08` 与 `bench/results/`）。

⚠️ **但真正卡住规模的是内存，不是周期数**：峰值常驻有一条 **~10.15 GiB 的固定地板**
（200 字符 × 1 条规则这种最小配置就已 10,389 MB，与 trace 几乎无关），其上只剩很窄的缝。
本机的可行域是**两级台阶**：1 条规则 ≤10k 字符可证、2 条规则约 200 字符可证、
**3 条及以上出不来**（第 3 条恰是 `pattern_block` —— 正则激活另一族 AIR chip）。
周期表能扫到 100k 字符 × 6 规则，是因为那只跑执行不出证。边界表与复现口径见
`bench/results/proofs.md` 与 `08` §3.3。

---

## 7. 构建命令

```bash
cd circuits/script  && cargo build --release -p pop-script   # build.rs 会连三个 guest 一起编
cd circuits/verifier && cargo build --release -p pop-verify  # 可选，审计快路径需要
# 单独编某个 guest（排查 guest 编译错误时）：
cd circuits/program       && cargo prove build   # → pop-program
cd circuits/infer-program && cargo prove build   # → pop-infer（P1-6）
```

产物：`circuits/target/release/pop-script`、`pop-verify`（Python 侧按这个路径定位，见 `07`）。

---

## 8. 不变量与边界

1. **`types` 必须 `no_std`**（仅 `alloc`）—— 任何引入 `std` 的改动都会让 guest 编译失败。
2. **`evaluate` 必须与 `policydsl.evaluate.check` 逐字段一致**（全局不变量 I1）——
   违反它不会立刻报错，只会让 `cross_validate` 变红，所以改任何一侧都要跑交叉验证。
3. **`sha256_hex` 的输出格式（小写、无 `0x`）必须与 Python 一致**，否则证据承诺对不上。
4. **`nfa_match` 与 `nfa_match_naive` 语义必须等价**（只有复杂度不同）。
5. **`--proof-out` 只支持单向量**（多向量直接 panic）——证书的「一证一证明」模型要求如此。
6. **区间必须排序**：`in_ranges` 假设 `ranges` 按 lo 升序；手工构造 `NfaSpec` 时若违反会得到错误结果。
7. **`PatternBlock` 的证据按 `specs` 顺序取第一条命中**，与 Python 侧一致。
8. **`response_binding` 两侧必须逐字节一致**（`pop_types::response_binding` ↔ `commit.response_binding`），
   域前缀与 `len(nonce)` 大端前缀都不可省 —— 前者防跨域碰撞，后者保单射。改任一侧都要跑
   `tests/test_binding.py::TestPythonRustParity`。
9. **类型一改就要重建 guest**：`types`（含新增字段）变了 ⇒ ELF 变 ⇒ vkey 变 ⇒
   `scripts/examples/out/` 下所有旧证明与证书**全部失效**，必须整体重生成。
10. **`delegated` 非空 ⇒ 这份证明单独不构成合规结论**（P2-9）。任何把
    `ProofOutput.passed` 直接当成「策略已满足」的消费方都是错的，必须合取陪伴证明。
    验证侧的落地形式是 `verify_cert.py` 打印的**第二行** `合规:` ——
    第一行 `RESULT:` 只说「这张证书是真的」。
11. **语义规则只支持公开模式**：`evaluate_private` 见到 `SemanticBound` 直接 panic
    （§2.4）。新增任何「把响应明文放进公开实例」的委托系统时，都要复制这道检查。
12. **三个 guest 各只收自己那一域**（P1-6 起两个、P2-10 起三个）：`pop-program` 断言
    `DOMAIN_POLICY`、`pop-infer` 断言 `DOMAIN_INFER`、`pop-session` 断言 `DOMAIN_SESSION`。
    **不要**为了「方便」把它们合成一个 guest —— 合并会让两个 vkey 变成同一个，
    「这份证明属于哪一半」就无从判断，组合义务（L6）随之失效。新增任何一个
    「要组合进同一张证书 / 要与别的域区分开」的证明域，都必须**再开一个 guest 程序**。

---

## 9. 测试对应

| 测试 | 覆盖 |
|---|---|
| `tests/test_rules_incircuit.py` | 各电路内规则在 `--check` 下与 Python golden 逐点对齐（含规范化证据串）；P2-9b 另覆盖「折叠真的发生在电路内」（五种绕过/近邻文本） |
| `tests/test_semantic.py`（P2-9） | `delegated` 的登记与合取：真实语义规则的陪伴证明绑定（换 onnx/vk/阈值/方向一律 FAIL）、私有模式 panic、公开实例与送达响应一致性、缺材料 fail-closed |
| `tests/test_trace.py` | P1-5 四条验收（完整链通过 / 删·换·重排失败 / 伪造回执验签失败 / 旧向量被拒），并实测 `trace_root` 与 Python 逐字节一致 |
| `tests/test_compose.py`（P1-6） | 代理推理的参考实现逐位一致（`--check --job infer`）、组合绑定的 5 组反例、域分离（各 guest 互相拒绝对方的向量）、驱动接线（`job` 旗标 / `mode` 不被剥掉） |
| `tests/test_session.py`（P2-10） | Merkle 纯算术（含**奇数末位提升**）、两层 `run_session` 逐字段对拍（链长 1/2/3/5/8）、三条义务的反例（混异策略/挖中间/换序/缺 chain/缺 seal/两个网关/空集）、验证侧的挖尾与整张换尾 |
| `tests/test_binding.py::TestPythonRustParity` | `response_binding` 在电路内与 Python 逐字节一致（公开 + 私有，多种 nonce 长度） |
| `tests/test_ablation.py::TestRustNaivePath` | Rust 侧 `nfa_match` ≡ `nfa_match_naive` |
| `tests/test_verifier_only.py` | `pop-verify` 的调用与快路径判定 |
| `bench/bench_cycles.py` | `--execute` 的 cycle 数矩阵（长度 × 规则数 × pike/naive） |
| `bench/bench_proofs.py` / `bench_verify.py` | 证明时间/体积/内存；验证的冷启动 vs 纯验证 |
| `scripts/cross_validate.py` | **host 19/19 · prove 19/19**（**I1 的总闸门**，2026-09-12 整批重跑；分块口径见 `08` §5） |

---

## 10. 扩展指引

- **加规则类型**：先按 `01` §7 的六步改 Python 侧，再在这里加 `Constraint` 变体 + `evaluate` 分支，
  且**证据字符串必须逐字节一致**。跑 `cross_validate` 验证。
- **加证明模式**：在 `pop-script` 的 `match proof_mode` 分支与 `write_verifier_sidecar` 里各加一处，
  同时更新 `policydsl.verifier.VERIFIER_ONLY_MODES`（如果新模式支持 verifier-only）。
- **加一个可组合的证明域**（如日后换掉代理推理、接真 zkAgent）：**新开一个 guest 程序**，
  在 `pop-types` 里加对应的 `Job`/`Outcome` 变体与 `job_domain` 分支，入口断言自己的域，
  然后扩 `policydsl/compose.py::KIND_*` 与 `verify_composite`。**不要**往现有 guest 里塞 ——
  见 §8 不变量 12。
- **优化证明开销**：当前瓶颈是证明器固定开销与 O(n·states) 的 NFA 扫描。
  `bench/results/` 里有基线数字，改动后用同一脚本复测再对比。
- **升级 SP1**：`types/program/script/verifier` 四处版本号需一起动，
  并确认 `circuits/patches/tempfile` 是否仍被需要（上游修好后可删）。

---

**相关**：契约怎么来的 → [`01-policy-dsl.md`](01-policy-dsl.md)；
私有模式的承诺语义 → [`02-privacy-commitment.md`](02-privacy-commitment.md)；
数字怎么复现 → [`08-tests-bench.md`](08-tests-bench.md)、[`../reproduce.md`](../reproduce.md)。
