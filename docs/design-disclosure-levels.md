# 电路级披露 coarsening（L0 / L1 / L2）设计

> **状态**：A9 / M4-01 **设计稿**（2026-11-01，分支 `bhv/a9-disclosure`，基线
> `4fe5c41`）。本文只写设计与迁移方案：**不改 `circuits/`、不重建 vkey、不改
> 论文、不动证明**。实现与 vkey 重建要等 X1 的最终 binary 矩阵结束（见
> [`plan-m2-m6.md`](plan-m2-m6.md) §M4-01 与 §2 的排期约束）。
>
> **先读这一句**：现有 L0/L1/L2 是**证书层投影**——guest 仍把 raw `rule` /
> `kind` / `evidence` 写进证明公开值，`policydsl/evidence/disclosure.py` 只是在
> 证书载荷里把它们重新排版。本文设计的是**电路级 coarsening**：让证明公开值
> **本身**只含该级别允许的字段。两者的差别见 §2；现状与缺口见
> [`blockers/C1.md`](blockers/C1.md)。

---

## 0. 一句话

把披露级别变成 `ProofRequest` / `PrivateRequest` 的一个字段，由 guest 在
**commit 之前**就按该级别生成违规形状（L0 = 名字 + 类型 + 证据承诺；L1 =
类别桶 + 计数 + 桶承诺；L2 = 逐条不透明承诺），把级别与 schema 一起写进公开值；
验证方不再「重投影」，而是检查**级别声明 == 公开值里的级别**、公开值形状严格
匹配该级别、证书载荷与解密后的公开值逐字段相等。任何未知级别、未知 schema、
声明与形状不一致、旧证明冒充新级别，一律 fail closed。代价是**策略域 guest
变更 + 新 vkey**。

---

## 1. 目标与非目标

### 1.1 目标（四条不变式）

- **I1（公开值最小化）**：声明为 `Lx` 的证明，其公开值里只出现 `Lx` 允许的
  字段。L1/L2 的公开值中不得出现 `rule` / `kind` / 明文 `evidence`；L0 也不得
  出现明文 `evidence`（只留承诺）。这是与今天证书层最大的区别。
- **I2（级别被承诺）**：级别不只是在证书 JSON 里写一句，而是由 guest 读入、
  写进公开值。证书的级别声明必须与公开值里的级别**相等**。
- **I3（映射确定且封闭）**：类别由**电路内的 `kind` 字面量**穷尽映射得到，
  不来自输入，不靠字符串截断；未知 schema / 级别 / 形状一律拒绝。
- **I4（语义不变）**：披露级别**不进** `ConstraintSpec`、不进 `policy_hash`；
  规则判定、`passed`、`response_binding`、`trace_root` 的语义不变。

### 1.2 非目标（本文明确不做）

- 不改 gate、不改规则判定、不改 `policy_hash` 的算法。
- 不引入新的证明系统、不做 witness-hiding、不把 `core` 换成 `groth16`。
- 不解决证明工件通道（`core` trace 仍泄露规则名）与重执行通道。
- 不提供「强制最低披露级别」的密码学保证——那是签发/验证策略，不是电路义务。
- 不做桶填充（padding）或跨证书不可链接化，见 §10.2。

---

## 2. 证书层 vs 电路级：先把差别钉死

| 维度 | 证书层（C1 已落地） | 电路级（本文设计） |
|---|---|---|
| 形状由谁决定 | Python `project_outcome()`，**事后**投影 | guest，在 `io::commit` **之前** |
| 证明公开值 | 仍是 raw `rule` / `kind` / 明文 `evidence` | 只含该级别允许的字段 |
| 谁能看到 raw | 任何直接读公开值或 `core` 工件的人 | L1/L2 下是见证，只有证明工件通道可能泄露 |
| 验证方做什么 | 用自己的投影函数重投影后比对 | 检查级别相等 + 形状匹配 + 载荷等于公开值 |
| vkey | 不变 | **策略域 vkey 必变**（§8） |
| `delegated` | L1/L2 直接 fail closed | 类别级桶 + 名字承诺（§6） |
| 旧证明 | 继续可用 | 默认拒绝；`--legacy-v1` 只放行 L0（§7.3） |

一句话：证书层是「**排版**」，电路级是「**不出现在公开值里**」。只有后者能让
「读公开值」不再等价于 L0。

---

## 3. 级别如何进入电路

### 3.1 三个候选与取舍

| 方案 | 结论 | 理由 |
|---|---|---|
| **请求字段** `disclosure_level` | **采用** | 级别是**签发选择**，同一条策略可以按不同级别出证；请求是私有输入，电路读取后把级别写进公开值，证明即可自描述 |
| `ConstraintSpec` 字段 | 拒绝 | `policy_hash = SHA256(spec_canonical)`，加字段会让**所有旧证书的哈希失效**；级别也会被错误地冻结成策略语义，且无法按证书调整 |
| 只在证书里声明 | 拒绝 | 证书是出证方写的，公开值是电路算的。只在证书里写，等于让「我声称 L1」不受证明约束；空违规时 L1/L2 形状还可能重合，无法判别 |

**落点**：

```rust
// circuits/types/src/lib.rs（设计，不在本次改动）
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]          // "L0" | "L1" | "L2"，与证书字段同形
pub enum DisclosureLevel { #[default] L0, L1, L2 }

pub struct ProofRequest {
    // ...既有字段...
    #[serde(default)]
    pub disclosure_level: DisclosureLevel,  // 旧 vectors 缺省 L0
}

pub struct PrivateRequest {
    // ...既有字段...
    #[serde(default)]
    pub disclosure_level: DisclosureLevel,
}
```

- 旧 `vectors.json` / 旧工具链不带该字段 → `default = L0`，行为等价于今天的
  L0 证书层路径（但公开值形状按 §4 的 L0 生成，见 §7.3 的兼容说明）。
- 未知枚举值 → serde 反序列化失败 → `pop-script` 在客户端报错，产不出证明
  （fail closed）。这与 P1-5 用 `deny_unknown_fields` 挡旧字段是同一手法。
- 策略包里的 `disclosure_level` 仍可作为**签发配置**由 Python 读取（沿用
  `disclosure.level_from_policy`），但它只决定「这次请求传什么」，**不参与哈希**。
- 若要强制最低级别（例如私有策略模式要求 ≥ L2），应在**签发/验证策略**里检查
  证书声明的级别，而不是让电路替调用方做选择。电路只保证「声明的级别 ==
  公开值的形状」。

### 3.2 公开值里的级别与 schema

`ProofOutput` / `PrivateOutput` 增加两个字段：

```rust
pub const PUBLIC_VALUE_SCHEMA_V2: &str = "pop-pv-v2";

pub struct ProofOutput {
    // ...既有字段...
    pub public_value_schema: String,   // "pop-pv-v2"
    pub disclosure_level: DisclosureLevel,
    pub violations: Vec<DisclosedViolation>,   // §5
    pub delegated: Vec<DelegatedConstraint>,   // L0 非空；L1/L2 恒空
    pub delegated_buckets: Vec<DelegatedBucket>, // L1/L2；L0 恒空
}
```

`outcome_value()`（公开值摊平的唯一真相源）把这四个字段一并输出。证书侧：

```json
"binding": {
  "vkey_hash": "...",
  "proof_sha256": "...",
  "public_values_sha256": "...",
  "proof_mode": "core",
  "public_value_schema": "pop-pv-v2"
},
"disclosure_level": "L1"
```

`binding.public_value_schema` 是证书对「我按哪版公开值契约验」的声明，必须与
公开值里的 `public_value_schema` 相等。旧证书没有这个字段 → `v1`。

> **为什么级别要在两处重复**：公开值里的级别是**电路承诺的事实**，证书顶层的
> 级别是**人可读的声明**。两者相等是验证条件，不是冗余容忍。只留公开值，证书
> 在没附证明时无法自描述；只留证书，级别就不受证明约束。

### 3.3 域分隔与盐

新增一个披露专用域，与 `pop-bind-v1` / `pop-infer-v1` 分开：

```text
DISCLOSURE_DOMAIN = "pop-disclose-v1"   // ASCII 16 字节
TAG_ITEM          = 0x01                // L2 逐条证据承诺
TAG_BUCKET        = 0x02                // L1 类别桶承诺
TAG_NAMES         = 0x03                // delegated 桶的名字集合承诺
TAG_RULE_NAME     = 0x04                // 单条委托规则的名字承诺
```

三类承诺的精确定义见 §5.4 与 §6.2。要点：

1. **类型标签**让「一条证据承诺」不可能被当成「一个类别桶承诺」或「一个响应
   承诺」；换层级、换用途都会改哈希。
2. **以公开值里的 `response_binding`（64 个 ASCII 十六进制字符）作盐**：
   同一段证据在不同响应下得到不同承诺，避免跨证书把「同一条违规」链接起来。
   私有模式下 `T` 不公开，猜测证据的一方没有 `T` 就重算不出承诺。
3. 旧 `policydsl.privacy.commit.evidence_commitment`（裸 `SHA256(evidence)`）
   **不删**，继续服务旧证书与旧证据开示；v2 用新函数，两套不得混用。

---

## 4. 公开值 v2 形状

以下 `…` 表示既有字段原样保留（`policy_hash` / `response_binding` /
`trace_root` / `passed`；私有模式还有 `response_commitment` / `redaction`）。
所有对象都按 `deny_unknown_fields` 的反向检查处理：多一个键即拒绝。

### 4.1 公共骨架

```json
{
  "mode": "public",
  "public_value_schema": "pop-pv-v2",
  "disclosure_level": "L1",
  "policy_hash": "…",
  "response_binding": "…",
  "trace_root": "…",
  "passed": false,
  "violations": [ ... ],
  "violation_count": 2,
  "delegated": [],
  "delegated_buckets": [ ... ]
}
```

- `violation_count` 只在 L1 出现（等于各桶 `count` 之和）。L0/L2 不出现。
- `delegated` 与 `delegated_buckets` **两个字段恒存在**，只是按级别一个非空、
  一个为空。保持形状稳定，避免验证方对「字段缺失」与「空列表」做二义判断。

### 4.2 L0

```json
"violations": [
  {"shape": "raw", "rule": "no-secret", "kind": "keyword_block",
   "evidence_commitment": "…64 hex…"}
],
"delegated": [{"name": "sem-pii", "system": "ezkl-halo2", "model_vkey": "…",
               "onnx_sha256": "…", "threshold_bp": 7000, "direction": "le"}],
"delegated_buckets": []
```

- 明文 `evidence` **不再进公开值**（这是相对今天 `Violation.evidence` 的收紧）。
- `rule` / `kind` 保留；`delegated.name` 保留（L0 明确放弃名字隐藏）。
- 证据承诺按 §5.4 的 `TAG_ITEM` 计算，带 `response_binding` 盐。

### 4.3 L1

```json
"violations": [
  {"shape": "category", "category": "content", "count": 1,
   "evidence_commitment": "…64 hex…"},
  {"shape": "category", "category": "length", "count": 1,
   "evidence_commitment": "…64 hex…"}
],
"violation_count": 2,
"delegated": [],
"delegated_buckets": [
  {"category": "semantic", "system": "ezkl-halo2", "model_vkey": "…",
   "onnx_sha256": "…", "threshold_bp": 7000, "direction": "le",
   "count": 1, "names_commitment": "…64 hex…"}
]
```

- 桶按 `category_id` **升序**输出；零桶不输出；同一类别只出现一次。
- `evidence_commitment` 是**桶承诺**（§5.4），不是逐条承诺。
- `delegated` 名字与条目数被桶替代；绑定字段保留（陪伴证明还要用，见 §6）。

### 4.4 L2

```json
"violations": [
  {"shape": "opaque", "evidence_commitment": "…64 hex…"},
  {"shape": "opaque", "evidence_commitment": "…64 hex…"}
],
"delegated": [],
"delegated_buckets": [ ...同 L1 的桶... ]
```

- 逐条承诺按**字典序升序**输出；允许相等（两条违规证据相同是合法情形），
  不允许乱序（乱序会泄露规则出现顺序）。
- **不输出** `violation_count`、类别、计数。列表长度仍然等于违规条数——
  这条泄露如实写进 §10.2，不假装 L2 隐藏了存在性。
- 桶与 L1 相同：类别恒为 `semantic`，计数与绑定字段仍可见。

### 4.5 私有模式

`PrivateOutput` 的形状与公开模式**逐字段同构**（`mode: "private"` 外加
`response_commitment` / `redaction`），只是：

- `violations` 使用同一 `DisclosedViolation` 枚举（替换今天的
  `PrivateViolation{rule, kind, evidence_commitment}`）；
- `delegated` 恒为 `[]`、`delegated_buckets` 恒为 `[]`。原因是既有电路边界：
  语义规则要求 `encode(T)` 进 ezkl 公开实例，与私有模式的前提不相容，
  `evaluate_private` 已经在入口 panic（`circuits/types/src/lib.rs` 的
  `SemanticBound` 分支）。因此「private × delegated 非空」是**不可达**而不是
  「按级别处理」，测试矩阵里记为拒绝格（§9.1）。

---

## 5. 违规类别 schema

### 5.1 Rust 形状

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    Content,        // content
    Length,         // length
    Format,         // format
    ToolArguments,  // tool_arguments
    Budget,         // budget
    TraceIntegrity, // trace_integrity
    Semantic,       // semantic（只用于 delegated 桶）
    Other,          // 兜底；正常情况下不应出现
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "shape", rename_all = "snake_case", deny_unknown_fields)]
pub enum DisclosedViolation {
    Raw      { rule: String, kind: String, evidence_commitment: String },
    Category { category: RuleCategory, count: u32, evidence_commitment: String },
    Opaque   { evidence_commitment: String },
}
```

`shape` 标签使每条违规**自描述**：验证方不必先信任级别声明再猜形状，可以
「按形状查级别、按级别查形状」双向核对。未知 `shape` 直接 fail closed。

### 5.2 类别表（电路内穷尽映射）

| 类别 | `kind` 字面量 | 含义 | 典型审计动作 |
|---|---|---|---|
| `content` | `keyword_block`、`normalized_keyword_block`、`pattern_block` | 响应内容 | 重写响应 |
| `length` | `length_bound` | 长度 | 调整长度 |
| `format` | `format_check` | 格式 | 重新格式化 |
| `tool_arguments` | `tool_arg_guard`、`retrieval_guard` | 工具参数 | 修工具调用 |
| `budget` | `budget_bound` | 预算 | 减少调用/token |
| `trace_integrity` | `trace_unbound`（含合成规则 `<trace>`） | 回执链不自洽 | 修网关链 |
| `semantic` | （无违规） | 仅用于 `delegated` 桶 | 核陪伴证明 |
| `other` | 未来新 kind | 兜底 | 人工分诊 |

实现建议：把 `Violation.kind: String` 改成 `RuleKind` 枚举（serde 仍序列化成
snake_case 字符串），让类别映射成为**编译期穷尽 match**。这样「新增 kind 忘了
登记类别」会在 `cargo build` 失败，而不是静默落到 `other`。Python 侧
`RULE_CATEGORY` 必须补上 `retrieval_guard`（当前缺这一条，会落到 `other`），并
与 Rust 做 golden 对拍（§9.3）。

> `semantic` 不作为违规类别：`semantic_bound` 只产生 `delegated` 条目，不产生
> `passed=false`。把语义规则记成违规会伪造「已违反」的事实，这是既有代码刻意
> 避免的（见 `SpecConstraint::SemanticBound` 的注释）。

### 5.3 计数与顺序

- **L1**：每个类别一个桶，`count` ≥ 1；`violation_count = Σ count`；桶按
  `category_id`（`Content=0 … Other=7`）升序。顺序是枚举常量，不泄露策略顺序。
- **L2**：逐条条目，按承诺升序；长度为违规条数（存在性与条数泄露，见 §10.2）。
- **L0**：保持电路判定顺序（今天的行为）。L0 已泄露规则顺序，不再额外承诺
  排序；若实现时顺手排序，也只是减少一点泄露，不改变契约。

### 5.4 证据承诺的精确字节

设 `RB` 为公开值里 `response_binding` 的 **64 个 ASCII 字节**；
`E` 为证据串的 UTF-8 字节；`u32be` / `u8` 为大端定长编码；`H = SHA-256`。

```text
item(E)      = H( "pop-disclose-v1" || 0x01 || RB
                  || u32be(len(E)) || E )
bucket(C,n)  = H( "pop-disclose-v1" || 0x02 || RB
                  || u8(category_id(C)) || u32be(n)
                  || concat(sorted_raw32(item(E_1), …, item(E_n))) )
```

- `sorted_raw32` 按 32 字节原始摘要的字典序排序；重复项保留（多重集）。
- 桶承诺把 `count` 写进前像，因此「把两条并成一条」或「改计数」都会改承诺。
- 验证方**不能**从承诺反推证据；它只检查 64 位小写十六进制。证据开示是
  出证方/审计方的旁路：持 `RB` 与 `E` 的一方可重算 `item`，持整个桶（或
  全部 `E_i`）的一方可重算 `bucket`。
- **L1 的审计语义**：要核对某一条被开示的证据属于该桶，必须拿到**该桶全部
  证据**（桶承诺是聚合的）。L2 则可以按单条 `item` 核对。这是 L1「类别+计数」
  换取更少泄露的代价，论文里要如实写。

Python 侧新增 `disclosure.item_commitment_v2(evidence, response_binding)` 与
`disclosure.bucket_commitment_v2(category, items, response_binding)`；Rust 侧
放在 `pop-types`，两侧用固定测试向量对拍（§9.3）。

### 5.5 成本与界

- 每条违规多一次（L1 桶多 `n` 次）SHA-256；SP1 的 SHA 有预编译，成本随证据
  字节数增长，与响应长度无关。
- 桶排序是 8 个固定类别，成本恒定；L2 排序是 `O(n²)` 字符串比较，`n` 为违规
  条数（≤ 约束条数）。建议在 guest 里加 `MAX_VIOLATIONS`（例如 64）并在超限时
  panic（fail closed），把周期上界钉死；这是**证明者自己要付的成本**，不引入
  新的健全性问题。
- 内存地板由 SP1 决定（约 10.15 GiB，见
  [`../circuits/README.md`](../circuits/README.md)），本改动只增加少量 cycle，
  不改变内存档位；实现后需重跑 `bench/bench_cycles.py` 并记录差值。

---

## 6. `delegated` 的类别级表示

### 6.1 问题

今天的 `DelegatedConstraint.name` 就是规则名，`Vec` 长度等于语义规则条数，
条目顺序等于策略顺序。L1/L2 若原样保留，等于用另一个字段泄露同一件事。
但完全隐去又不行：验证方**必须**能对每条委托约束找到并核验陪伴证明。

### 6.2 `DelegatedBucket`

L1/L2 下 `delegated: []`，改用：

```rust
pub struct DelegatedBucket {
    pub category: RuleCategory,   // 当前恒为 Semantic
    pub system: String,           // 例如 "ezkl-halo2"
    pub model_vkey: String,
    pub onnx_sha256: String,
    pub threshold_bp: u32,
    pub direction: BoundDirection,
    pub count: u32,
    pub names_commitment: String, // 见下
}
```

分组规则（电路内，确定性）：

1. 按绑定元组 `(system, model_vkey, onnx_sha256, threshold_bp, direction)`
   分组；同一元组的多条规则合成一个桶，`count` 累加。
2. 桶按元组的规范序列化升序输出。
3. **不输出**任何 `name`。
4. `names_commitment` 绑定该桶内的规则名集合，供日后审计开示：

```text
rule_name(R)  = H( "pop-disclose-v1" || 0x04 || RB
                   || u32be(len(R)) || R )
names(S)      = H( "pop-disclose-v1" || 0x03 || RB
                   || u32be(|S|)
                   || concat(sorted_raw32(rule_name(R) for R in S)) )
```

为什么保留 `system` / `model_vkey` / `onnx_sha256` / `threshold_bp` /
`direction`：它们不是规则名，而是**合取验证的锚点**。没有它们，验证方无法判断
陪伴证明是不是同一个模型、同一个阈值、同一个方向；把它们藏起来会让「合取」退化
成「信任出证方转述」。这三项本来就会出现在 ezkl 陪伴证明的公开实例与
`semantic.companions` 里，隐藏的收益有限、代价是健全性。**藏名字、不藏绑定元组**
是本设计的取舍。

### 6.3 陪伴证明如何匹配

L0：沿用今天的 `verify_cert.py::check_semantic`——按 `delegated.name` 找
`semantic.companions[].rule`，逐字段核验。

L1/L2：`semantic.companions[]` 的 `rule` 字段替换为 `rule_commitment`
（`rule_name(R)`）。验证方：

1. 按绑定元组把 companions 分到各桶；
2. 每个桶要求 companion 条数 **恰好等于** `count`，且 `rule_commitment` 互不相同；
3. 用 companion 的 `rule_commitment` 集合重算 `names_commitment`，必须与桶里
   的值相等；
4. 对每个 companion 调 `verify_companion(bucket, companion, T′)`——除 `name`
   外，函数比对的字段在桶里都有（`system` / `model_vkey` / `onnx_sha256` /
   `threshold_bp` / `direction`），因此签名不变，只把「按名字索引」改成「按桶
   索引」；
5. 任何桶找不到足够 companion、任何 companion 不属于任何桶、任何指纹或
   `proof_sha256` 不符 → FAIL（fail closed）。

这样验证方仍然得到「每条委托约束都有一份被验证的陪伴证明」，而出证方公开的
证书里只有名字承诺。名字只能由持策略的运营方在审计时开示，验证方用
`rule_name` 重算核对——这就是 §10.3 里「P-PP/带盐承诺管哈希，本设计管公开值
字段」的分工。

### 6.4 私有模式

`evaluate_private` 对含 `SemanticBound` 的策略**直接 panic**（既有行为），
因此不存在「private × delegated 非空」的 v2 输出。验证方对 private 输出要求
`delegated` 与 `delegated_buckets` 同时为空，非空即 FAIL（防止未来 guest 改动
悄悄放宽边界）。

---

## 7. 验证方检查（fail closed）

### 7.1 判定顺序

给定证书载荷 `payload`、可选证明验证结果 `proof_result`：

1. **schema**：取 `binding.public_value_schema`。缺省 = `v1`。只认识 `v1` /
   `pop-pv-v2`；其它 → FAIL。
2. **级别来源**：`v2` 从公开值取 `outcome.disclosure_level`，并 normalize
   （大小写不敏感，未知值 FAIL）；证书顶层 `payload.disclosure_level` 必须
   存在且与公开值**按 normalize 后相等**，缺失或不等 → FAIL。`v1` 走 legacy
   路径（§7.3）。
3. **形状**（逐条严格检查，`shape` 标签必须与级别一致）：
   - L0：每条键集 `{shape, rule, kind, evidence_commitment}`；`rule` / `kind`
     非空；承诺 64 hex；`violation_count` 不得出现；`delegated_buckets` 为空。
   - L1：每条键集 `{shape, category, count, evidence_commitment}`；`category`
     在枚举内；`count` ≥ 1 且不是 bool；桶按 `category_id` 严格递增；不得重复
     类别；`violation_count == Σ count`；`delegated` 为空。
   - L2：每条键集 `{shape, evidence_commitment}`；承诺 64 hex；列表按承诺
     **非降序**（允许相等，禁止乱序）；`violation_count` 不得出现；`delegated`
     为空。
   - **递归禁用键扫描**：除 L0 的 `rule` / `kind` 外，任何层级都不允许出现
     `rule` / `kind` / `name` / `evidence` 键（delegated 桶也不允许）。这是
     防「投影了一半」的第二道闸。
4. **delegated**：L0 允许非空 `delegated`，要求 `delegated_buckets` 空；L1/L2
   要求 `delegated` 空、桶的形状符合 §6，且每个桶 `count` ≥ 1。
5. **逐字段相等**：有证明时，把公开值解码成 outcome 后**直接**与
   `payload.outcome` 比较（不再经过投影函数）。任何差异 → FAIL。证书顶层的
   `binding.public_values_sha256` / `vkey_hash` 仍按既有卡片检查。
6. **私有模式**：`delegated` 与 `delegated_buckets` 必须都为空。
7. **旧证明**：公开值没有 `public_value_schema`（v1）而证书声明 `v2` 或
   L1/L2 → FAIL；只有 §7.3 的 legacy 组合例外。

> 与今天最大的流程差异：**不再调用 `project_outcome()` 去把 raw 证明投影成
> 证书形状**。v2 下投影函数在正常路径上应当等于恒等；保留它只会制造「验证方
> 替出证方补做隐藏」的错觉，而那正是本文要消除的证书层行为。

### 7.2 失败判据表

| 情形 | 结果 | 理由 |
|---|---|---|
| 未知级别 / 未知 schema | FAIL | fail closed |
| 证书级别 ≠ 公开值级别 | FAIL | 级别未被证明支持 |
| L1 证书里出现 `rule` / `kind` | FAIL | 形状不匹配 |
| L2 里出现 `category` / `count` / `violation_count` | FAIL | 形状不匹配 |
| L1 的 `violation_count` ≠ 桶和 | FAIL | 计数被篡改 |
| L2 承诺乱序 / 重复到无法排序 | FAIL | 顺序泄露或载荷畸形 |
| 非空 `delegated.name` 出现在 L1/L2 桶 | FAIL | 名字泄露 |
| 桶与 companions 条数 / 指纹 / 名字承诺不符 | FAIL | 委托未被完整判定 |
| 私有输出带非空 delegated 或桶 | FAIL | 电路边界被绕过 |
| 证书载荷 ≠ 解码公开值 | FAIL | 证书不是证明的镜像 |
| 旧证明 + 新级别声明 | FAIL | 旧证明没有电路级形状 |

### 7.3 与旧证明、旧证书的兼容

| 证书 | 证明 | 新验证器行为 |
|---|---|---|
| v1（无 schema、无级别，raw outcome） | v1 旧 vkey | **默认 FAIL**；仅 `--legacy-v1` + 归档旧验证器可用，结果标 `legacy-v1` |
| v1 | v2 | FAIL（证书缺少 schema/级别，无法绑定） |
| v2 | v1 | FAIL（旧公开值是 raw，不能冒充 v2） |
| v2 L0 | v2 L0 | 按 §7.1 通过 |
| v2 Lx | v2 Ly（x≠y） | FAIL |
| v2 Lx | v2 Lx | 形状与 companions 全过则通过 |
| v2 任意 | 未知 schema | FAIL |

**为什么默认拒绝旧证明而不是静默按 L0 收下**：新验证器如果接受旧 vkey 的 raw
公开值，就等于留下一条绕过 coarsening 的旁路——出证方永远可以拿旧证明出 L0
证书，而验证方无法区分「这张证书是旧格式」与「这张证书故意降级」。所以默认
fail closed，legacy 必须显式开关并打标签。旧证书要继续可验，需要按 vkey 归档
旧验证器二进制（§8.3）。

---

## 8. vkey 与迁移

### 8.1 改动分层

| 层 | 文件 | 改什么 | 是否改 vkey |
|---|---|---|---|
| guest / 共享类型 | `circuits/types/src/lib.rs` | `DisclosureLevel`、`RuleCategory`、`DisclosedViolation`、`DelegatedBucket`；`ProofRequest` / `PrivateRequest` 加字段；`evaluate` / `evaluate_private` 按级别产出；承诺、排序、桶；`outcome_value` 加 schema/level/新字段 | **是**（策略域必变） |
| guest 入口 | `circuits/program/src/main.rs` | 无需逻辑改动（`run_job` 在 types），但要重编 | 随 ELF 变化 |
| 宿主驱动 | `circuits/script/src/main.rs` | `VectorIn` 加 `disclosure_level`，构造 `Job` 时传入；结果仍走 `outcome_json` | 否（宿主），但会重编 |
| verifier-only | `circuits/verifier/src/main.rs` | 若它通过 `pop-types::outcome_value` 解码则无需逻辑改动；需确认并重编 | 否（宿主） |
| 其他 guest | `infer-program` / `session-program` | 无逻辑改动；但共享 `pop-types`，**必须重编并重测 vkey** | 可能变，必须实测记录 |
| Python 证书 | `policydsl/evidence/disclosure.py` | 从「投影器」改为「形状校验器 + 承诺助手」；保留旧函数给 legacy | 否 |
| Python 证书 | `policydsl/evidence/cert.py` | `build_payload` 不再投影，改为校验并原样存 outcome；写 `public_value_schema` | 否 |
| 验证脚本 | `scripts/verify/verify_cert.py`、`verify_session.py` | 级别相等、形状检查、v2 相等比较；`--legacy-v1`；语义卡按桶匹配 | 否 |
| 语义陪伴 | `policydsl/proofs/semantic.py` | `companion_entry` 支持 `rule_commitment`；`verify_companion` 接受桶（无 name） | 否 |
| 测试/基准 | `tests/test_disclosure_levels.py`、`bench/bench_policy_infer.py` | 新增 v2 矩阵；推断基准改用真实公开值特征 | 否 |

**关键点**：`pop-types` 是被四个 guest 共享的 crate。即使推理/会话 guest 的
逻辑一行没改，只要 crate 内容变了，编出来的 ELF 与 vkey 就**可能**变。实现时
必须把四个 ELF 都重编、都算 vkey、都在结果表里标注；不要假设「只有策略域变」。

### 8.2 新 vkey 的产生与记录

实现完成后的验收顺序（供 M4-01 执行者）：

1. `cd circuits/program && cargo prove build` 编出策略 guest；
2. 同样编 `infer-program` / `session-program`；
3. 用 `pop-script --check` / `--execute` 记录每个 guest 的 ELF sha256 与
   vkey（现有脚本与 `Core.md` 的记录格式可复用）；
4. 在**新文件** `docs/blockers/M4-01.md` 记录：
   `date | commit | guest | ELF sha256 | vkey | public_value_schema | host`；
5. 同步 `docs/reproduce.md` 的 vkey 标签与结果表头，避免与旧 binary 混表；
6. 在论文实验表里给所有证明数字加 vkey/binary 标签（沿用
   [`plan-m2-m6.md`](plan-m2-m6.md) 的「pre-NFA-fix / 新 vkey 不能混表」纪律）。

**不要**只记录策略域 vkey。组合证明（推理域）与会话聚合的验证方都要按各自
vkey 选验证器，漏记会让「同一份结果表混了两个 binary」这种事故重现。

### 8.3 旧证明 / 旧证书的处置

- **旧证明（v1）**：默认拒绝。理由见 §7.3。若要保留可验性，按 vkey 归档旧
  `pop-verify` / `pop-script` 二进制，并在 `--legacy-v1` 分支里显式调用；结果
  标注 `legacy-v1`，不得与 v2 结果混排。
- **旧证书（v1）**：本身仍是合法的历史记录，但只能由旧验证器在 legacy 模式下
  验证。新签发一律 v2。
- **重出证**：如果某张旧证书必须在生产环境继续可验，最干净的做法是用新 binary
  重新出证（`policy_hash` 不变，因为级别不进 spec；`response_binding` 不变，
  因为 `nonce` 与 `T` 不变），而不是长期维护双验证器。
- **不能做的事**：把旧证明的 raw 公开值「就地投影」成 v2 证书。那等于把证书层
  的旧行为包装成电路级结果，正好是本文要消除的 overclaim。

### 8.4 排期与回归

- M4-01 会改 vkey，**不要**插在 X1 当前矩阵中途（见
  [`plan-m2-m6.md`](plan-m2-m6.md) 的警告）。应在 X1 最终 binary 重跑结束后，
  作为**一个 vkey 批次**统一做：编译、出 vkey、回归、记录、更新论文表。
- 实现后必须重跑：`tests.test_disclosure_levels`、`tests.test_cert`、
  `tests.test_binding`、`tests.test_semantic`、`tests.test_doc_links`，以及
  `bench/bench_policy_infer.py`（数据源换成真实公开值）。
- Python 侧单元测试不能替代电路侧：承诺字节、类别映射、桶顺序至少各有一条
  Rust/宿主对拍。

---

## 9. 测试矩阵

### 9.1 主矩阵：级别 × 模式 × delegated

| # | 级别 | 模式 | delegated | 期望 |
|---|---|---|---|---|
| 1 | L0 | public | 空 | raw 形状；`evidence` 明文不出现；通过 |
| 2 | L1 | public | 空 | 类别桶 + 计数 + 桶承诺；通过 |
| 3 | L2 | public | 空 | 仅逐条承诺；通过 |
| 4 | L0 | public | 非空 | 名字可见；companions 按名字匹配；通过 |
| 5 | L1 | public | 非空 | 桶里无 `name`；companions 按桶 + `rule_commitment` 匹配；通过 |
| 6 | L2 | public | 非空 | 同 5；通过 |
| 7 | L0 | private | 空 | raw 私有形状；通过 |
| 8 | L1 | private | 空 | 类别桶；通过 |
| 9 | L2 | private | 空 | 仅承诺；通过 |
| 10 | L0 | private | 非空 | guest panic（语义规则不支持私有模式） |
| 11 | L1 | private | 非空 | 同 10 |
| 12 | L2 | private | 非空 | 同 10 |

> 第 10–12 格是**拒绝格**，不是「未实现」。测试要断言 `evaluate_private` /
> `run_job` 以清晰的错误失败，而不是产出一份看似正常的证书。

### 9.2 横切用例

- 未知级别字符串（请求枚举、证书 normalize 两条路径）→ 拒绝。
- 证书级别 L1、公开值级别 L0（或反之）→ FAIL。
- L1 载荷塞回 `rule` / `kind` → FAIL；L2 塞回 `category` / `count` → FAIL。
- L1 `violation_count` 与桶和不一致 → FAIL。
- L2 承诺乱序 / 重复处理（允许相等、拒绝乱序）→ 分别断言。
- 桶顺序错乱、同类别重复桶、零 `count` 桶 → FAIL。
- 桶承诺 / 逐条承诺的 Python↔Rust 固定向量对拍（同一 `RB`、同一证据集）。
- 类别映射对拍：9 个当前 kind + `retrieval_guard` + 未知 kind 的 `other` 行为。
- delegated：同绑定元组的两条规则合成一个桶 `count=2`；companions 恰好两条、
  指纹相同、`rule_commitment` 不同；少一条 → FAIL；多一条 → FAIL；
  `names_commitment` 被篡改 → FAIL。
- 私有输出带非空 `delegated` / 桶 → FAIL。
- 旧证明 + 新证书 / 新证明 + 旧证书 / `--legacy-v1` 三种组合 → 按 §7.3。
- 证书载荷与解码公开值任一字段不同 → FAIL。
- 无证明（`proof_mode=unproven`）的 host-check 证书：形状与级别仍检查，但
  结果标 `unproven`，不得声称电路级隐藏。
- 证据开示：用开示的 `E` 与 `RB` 重算 `item`，与 L0/L2 公开值一致；
  L1 需整桶开示才能重算 `bucket`。

### 9.3 跨语言 golden

新增 `tests/vectors/disclosure_v2.json`（或等价 fixture），固定：

- 一组 `response_binding`（含空 nonce 与随机 nonce 两种）；
- 证据集合 `{"secret", "len=250", "dev@example.com", "trace broken"}`；
- 期望的 `item` / `bucket` / `rule_name` / `names` 十六进制。

Python 与 Rust 各跑一遍，逐字节相等才通过。没有这条对拍，两侧的域分隔或排序
差一个字节，验证方就会永远对不上，而单元测试可能各自都绿。

---

## 10. 威胁模型与边界

### 10.1 每一级隐藏了什么

| | L0 | L1 | L2 |
|---|---|---|---|
| 规则名 | **暴露** | 隐藏（桶内名字只有承诺） | 隐藏 |
| `kind` / 规则类型 | **暴露** | 隐藏（只暴露类别） | 隐藏 |
| 明文证据 | 隐藏（只承诺） | 隐藏（桶承诺） | 隐藏（逐条承诺） |
| 规则顺序 / 出现顺序 | 暴露 | 隐藏（类别升序） | 隐藏（承诺升序） |
| 违规存在性 | 暴露 | 暴露（列表/计数） | 暴露（列表长度） |
| 违规条数 | 暴露 | 暴露（`violation_count` + 桶和） | 暴露（列表长度） |
| 类别集合 | 暴露（由 kind 可推） | **暴露** | 隐藏 |
| 每类计数 | 可推 | **暴露** | 隐藏 |
| delegated 规则名 | 暴露 | 隐藏（承诺） | 隐藏（承诺） |
| delegated 绑定元组 | 暴露 | **暴露**（模型/阈值/方向） | **暴露** |
| `passed` / 哈希 / 绑定 | 暴露 | 暴露 | 暴露 |

### 10.2 没有隐藏的东西（必须与论文同时写）

1. **证明工件通道**：`core` / `compressed` 的 STARK 不隐藏见证，trace 里仍有
   raw `rule` / `kind` / `evidence`。L1/L2 只保护**公开值读取者**；拿到证明
   工件的人仍然能看到 L0 的信息。要关这条需要 `groth16` / `plonk` 的
   witness-hiding，见 [`certificate-binding-framework.md`](certificate-binding-framework.md)
   §7.3 与 [`sp1-zk-audit.md`](sp1-zk-audit.md)。这不在本文范围。
2. **重执行通道**：知道部署上下文与响应的一方可以重跑判定，恢复违规结构。
   披露级别不改变行为，只改变公开值。
3. **`policy_hash` 枚举**：没有 `policy_nonce` 时，策略空间小，哈希本身可枚举；
   L1 类别集合与计数只是让枚举更省事的额外特征。带盐承诺关的是哈希通道，
   不是类别通道，见 §10.3。
4. **跨证书结构链接**：同一策略出多张证书时，类别集合、每类计数、delegated
   绑定元组是稳定指纹。证据承诺用 `response_binding` 加盐，避免了**证据级**
   链接，但没有避免**策略结构级**链接。桶填充 / 固定形状 / 合并类别可以缓解，
   代价是审计效用，本文不做。
5. **大小与时间侧信道**：违规条数、证据长度会影响 cycle 数与证明大小；这些
   可观测量不在本设计内。
6. **`passed=false` 的存在性**：只要允许证明违规，就无法隐藏「有违规」这件事；
   能隐藏的是违规的**身份与类别**（L2）。
7. **L1 的审计盲区**：桶承诺是聚合的，只开示一条证据无法核对它属于哪个桶；
   需要整桶开示。论文的审计效用讨论要写清这一点。

### 10.3 与 P-PP、带盐承诺的关系

```text
             隐藏什么                           问责什么
   ┌─────────────────────────────┐   ┌──────────────────────────────┐
   │ 带盐承诺 policy_nonce       │   │ P-PP：权威签发 policy_hash   │
   │ 关「公开值里的哈希可枚举」  │   │ 关「这个哈希是谁背书的」     │
   └─────────────────────────────┘   └──────────────────────────────┘
                  │                                 │
        ┌─────────┴─────────┐                       │
        │ 电路级 coarsening │                       │
        │ 关「公开值里的规则名/│                       │
        │ 类型/证据」        │                       │
        └─────────┬─────────┘                       │
                  └──────── 三条通道，互相不能替代 ──┘
```

- **与带盐承诺**：盐只让 `policy_hash` 不可枚举；如果公开值里仍有 `rule` /
  `kind`，枚举者可以直接从公开值读，盐白加。电路级 coarsening 把第二条通道
  也关到「类别/计数/承诺」，但**不**关 `core` trace；三条通道缺一不可。
- **与 P-PP**：P-PP 签的是策略整体哈希，不改变公开值形状，也不减少类别泄露。
  它保证「哈希有出处」，不是「策略不可推断」。两者正交。
- **与 [`design-policy-pp.md`](design-policy-pp.md) §7 的现有表述**：该文说
  「披露层级仍是证书层的另一件事」——本文落地后，这句话要改成「披露级别由
  电路承诺，P-PP 仍只背书哈希」。
- **与 [`security-model.md`](security-model.md) §4.6.4 的两个泄露口**：③
  `PrivateViolation{rule,kind}` 与 ⑤ `delegated.name` 正是本文关闭的对象。
  关闭后仍要在能力表里保留「类别/计数可推断」与「`core` 工件泄露」两行。

### 10.4 不做的事

- 不改规则判定、gate、`policy_hash`、`response_binding`、`trace_root`。
- 不做 witness-hiding、不换证明系统、不引入 groth16/plonk。
- 不做桶填充、不做跨证书不可链接化、不做差分隐私噪声。
- 不提供强制最低级别；不改变 P-PP；不改变推理/会话域的语义。
- 不把「公开值 coarsening」写成「策略隐私已解决」；论文措辞按 §10.2 的边界写。

---

## 11. 给论文 §4 的输入与页数影响

> 当前 `paper/tdsc-paper.tex` 的 §4 是 *Policy-Private Compliance*，
> 其中 `\subsection{Disclosure levels and the inference they permit}` 是
> 本文要改写的落点。以下按语义插入，章节号调整不影响内容。

### 11.1 可直接改写的要点

1. **定义（取代「certificate-layer projections」那句）**：披露级别是
   `ProofRequest` 的一个参数，由电路在承诺前应用；证明公开值本身只含该级别
   允许的字段，级别与公开值 schema 一并被承诺。验证方检查「证书声明的级别 ==
   公开值里的级别」与「公开值形状严格匹配级别」，而不是把 raw 公开值事后投影。
2. **机制**：L0 = 规则名 + 类型 + 证据承诺；L1 = 类别桶 + 每类计数 + 桶承诺；
   L2 = 逐条不透明承诺（列表长度即条数）。证据承诺以 `response_binding` 加盐并
   做域分隔（`pop-disclose-v1`），避免跨证书链接与类型混淆。
3. **delegated**：L1/L2 用类别桶替代 `name`；保留 `system` / `model_vkey` /
   `onnx_sha256` / `threshold_bp` / `direction` 作为陪伴证明的合取锚点；
   名字用 `rule_commitment` 集合承诺，验证方按桶匹配并核对承诺。
4. **命题（可写成一句可检验的话）**：在 guest 代码与 vkey 固定的前提下，
   验证通过蕴含「证书载荷是证明公开值的逐字段镜像，且公开值只含声明级别允许
   的字段」。**不要**写成「策略对验证者隐藏」；后者还要 `core` 工件的
   witness-hiding 与重执行通道的讨论。
5. **边界（必须同段给出）**：`core` / `compressed` 工件仍泄露 raw 规则名；
   类别与计数仍可推断（L1 尤其）；跨证书结构可链接；重执行不变；L1 的桶承诺
   只支持整桶开示。
6. **状态标注**：本文是设计；当前仓库运行的仍是证书层版本。论文若在实现前
   投稿，必须写「design + certificate-layer prototype」，不能写「已实现」。
   实现并重建 vkey 后，把 §5 推断实验的数字来源从「证书载荷特征」换成「真实
   公开值特征」，并标注新 vkey。

### 11.2 表格改动

- 新增一张小表「公开值形状（L0/L1/L2）」：列 = 级别 / `violations` 形状 /
  `delegated` 形状 / 仍然泄露什么。约 0.3 栏。
- 现有 Table `tab:wp4` 的第 4 行（rule name）与第 6 行（delegated）状态从
  **Open** 改为 **Closed by design (circuit-level v2); implementation pending
  vkey rebuild**。不要把状态写成 Closed（未实现）。
- `tab:policy-infer` 保留，但在标题/脚注明确「certificate-layer prototype」；
  实现后换成 circuit-level 数据（页数不增，替换即可）。

### 11.3 页数影响

- 新增形状表 ≈ 0.18 页；机制 + 边界两段 ≈ 0.2 页；
- 删掉现在散落在 §4 与 §5 的「certificate-layer, not circuit-level」重复免责
  句 ≈ −0.1 页；
- **净增约 0.3–0.5 页**（双栏）。若页数吃紧，把形状表并入 `tab:wp4` 的附加
  行，净增可压到 0.2 页左右；实现后的推断表替换不增加页数。
- 不增加证明/实验页：本文不改证明系统，也不新增实验；只新增设计与迁移说明。

---

## 12. 落地顺序（给 M4-01 执行者）

1. 冻结本设计；确认 X1 矩阵结束、新 binary 已定。
2. 改 `circuits/types`：类型、映射、承诺、桶、`outcome_value`；先跑 Rust 单测
   与 Python↔Rust golden（§9.3），**不出证**。
3. 改 `circuits/script` 的 `VectorIn` 与 `Job` 构造；跑 host-check 的主矩阵
   （9 个通过格 + 3 个拒绝格）。
4. 改 Python 证书/验证/语义陪伴；跑单测与 `tests.test_doc_links`。
5. 编四个 guest，记录 ELF sha256 / vkey（§8.2）；只对策略域做真实出证回归
   （内存约 10.15 GiB 地板，见 `circuits/README.md`）。
6. 重跑 `bench/bench_policy_infer.py`，得到真实公开值上的推断数字；更新论文表。
7. 更新 `blockers/C1.md`（把「电路级未做」改成「已落地，见 M4-01」）、
   `security-model.md` §4.6.4、`design-policy-pp.md` §7、`reproduce.md` 的
   vkey 标签。
8. 最后再改论文；论文与代码/记录同批次冻结，避免「论文说已实现、仓库还是
   certificate-layer」的错位。

---

## 附录 A：实现者必须逐字节对齐的常量

| 名称 | 值 / 公式 | 落在 |
|---|---|---|
| schema 字符串 | `pop-pv-v2` | Rust `PUBLIC_VALUE_SCHEMA_V2`、证书 `binding.public_value_schema` |
| 披露域 | `pop-disclose-v1`（ASCII） | Rust / Python 各一份常量 |
| 类型标签 | item `0x01`、bucket `0x02`、names `0x03`、rule_name `0x04` | 同上 |
| 类别 id | content 0、length 1、format 2、tool_arguments 3、budget 4、trace_integrity 5、semantic 6、other 7 | Rust `RuleCategory` 判别值 / Python 映射表 |
| 证据承诺 | §5.4 `item` / `bucket` | `disclosure.item_commitment_v2` / `bucket_commitment_v2` |
| 委托承诺 | §6.2 `rule_name` / `names` | `disclosure.rule_name_commitment_v2` / `names_commitment_v2` |
| 排序 | L1 桶按类别 id；L2 按承诺非降序；桶按绑定元组规范串 | Rust 唯一实现，Python 只校验 |
| 旧路径 | `SHA256(evidence)`（`privacy.commit.evidence_commitment`） | 仅 legacy，不与 v2 混用 |

> 附录 A 的每一行都应在 `tests/vectors/disclosure_v2.json` 里有固定期望值。
> 少一条对拍，跨语言就可能各绿各的、合起来对不上。
