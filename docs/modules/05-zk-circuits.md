# 05 · ZK 电路层（SP1 / Rust）

> 覆盖 `circuits/` 整个 workspace：`types`、`program`、`script`、`verifier`、`patches/`。
> 这一板块回答：**Python 侧编译出的契约，怎么在 zkVM 里跑出同一个结论，并变成一份可验证的证明。**

---

## 1. 职责与 workspace 布局

```
circuits/
├── Cargo.toml          # workspace：members = types / program / script / verifier
│                       # + [patch.crates-io] tempfile（见 §6）
├── types/    pop-types  # 共享判定逻辑（no_std + alloc）：审计对象、NFA、evaluate、evaluate_private
├── program/  pop-program# zkVM guest：读 Job → run_job → commit(Outcome)
├── script/   pop-script # 宿主驱动：--check / --execute / 出证 / --verify
├── verifier/ pop-verify # 仅验证器二进制（compressed/groth16/plonk）
└── patches/tempfile     # 上游补丁（sp1-prover 6.7.0 需要 TempDir::keep()）
```

设计核心：**`program` 只做三件事**（读输入、调用 `pop-types`、提交输出），
全部判定逻辑放在 `types` 里，因此同一份代码既能编进 RISC-V guest，也能编进宿主驱动
（`pop-script --check` 就是直接在宿主机上跑 `run_job`，不生成证明）。

```rust
// program/src/main.rs —— 全文 26 行，就是这三步
sp1_zkvm::entrypoint!(main);
pub fn main() {
    let job: Job = io::read();       // 私密输入：不进入公开值
    let out: Outcome = run_job(&job); // 共享判定逻辑
    io::commit(&out);                // 公开值：验证者可读
}
```

---

## 2. `pop-types`：共享类型与判定（`types/src/lib.rs`，615 行）

### 2.1 类型清单

| 类型 | 说明 |
|---|---|
| `ToolReceipt { seq, tool, args: BTreeMap<String,String>, result_digest, ts, prev, keyid }` | **网关签发的工具回执**（P1-5；链的元素）。`sig` **不在**结构体里 —— 电路内不验签，字段被 serde 忽略 |
| `FormatKind { Json, Int, Float }` | `format_check` 的格式（snake_case 序列化） |
| `BudgetUnit { Calls, Tokens }` | `budget_bound` 的计量单位 |
| `NfaSpec { start, accept, states }` / `NfaState { eps, edges }` / `NfaEdge { to, ranges }` | **可序列化 NFA 契约**（由 `policydsl.nfa` 产出） |
| `PatternMode { Pike, Naive }` | 匹配模式（默认 `Pike`） |
| `Constraint` | 六种变体的枚举（见下表） |
| `ProofRequest { response, constraints, nonce, receipts }` | 公开模式输入（`nonce` 为 P0-2 挑战值，`serde(default)`；`receipts` 为 P1-5 回执链）。**`deny_unknown_fields`** |
| `Violation { rule, kind, evidence }` | 违规（证据为**字符串**） |
| `PrivateViolation { rule, kind, evidence_commitment }` | 私有模式的违规（只有承诺） |
| `RedactionProof { redacted_commitment, mask_count, redaction_ok, mask_covered }` | 脱敏证明 |
| `PrivateRequest { response, constraints, nonce, mask, redacted, spans, receipts }` | 私有模式输入（`nonce` 同上）。**`deny_unknown_fields`** |
| `PrivateOutput { policy_hash, response_binding, response_commitment, trace_root, passed, violations, redaction }` | 私有模式输出 |
| `Job { Public(ProofRequest), Private(PrivateRequest) }` | 一个 ELF 服务两种模式的调度枚举 |
| `Outcome { Public(ProofOutput), Private(PrivateOutput) }` | 顶层承诺结果 |

`Constraint` 的六个变体与字段（**与 `01` 的六类规则一一对应**）：

```rust
KeywordBlock  { name, keywords }
LengthBound   { name, min, max }
PatternBlock  { name, patterns, specs: Vec<NfaSpec>, mode: PatternMode }
FormatCheck   { name, format: FormatKind }
ToolArgGuard  { name, tools, forbidden_fields }
BudgetBound   { name, budget, unit: BudgetUnit }
```

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

### 2.4 私有模式 `evaluate_private(req) -> PrivateOutput`

先复用 `evaluate` 算出公开结论，再**只保留承诺**：

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

### 2.5 `sha256_hex`

手写十六进制输出，**与 `hashlib.sha256().hexdigest()` 字节级一致**（小写、无前缀）——
这是 Python 与 Rust 承诺能对上的前提。

---

## 3. `pop-program`：zkVM guest

26 行，见 §1 的代码。要点：

- `io::read()` 读入的是 **`Job`（私密输入）**，不进入公开值；
- `io::commit(&out)` 提交 `Outcome`，即**公开值**；
- guest 自身不做任何 I/O、不做网络、不做时间读取 —— 判定因此是**确定性**的，
  这正是「健全性」论证的支点（`../security-model.md` §2）。

---

## 4. `pop-script`：宿主驱动（`script/src/main.rs`，308 行）

四种模式（`--check` / `--execute` / 默认出证 / `--verify`），共用一套极简命令行解析。

| 参数 | 说明 |
|---|---|
| `--vectors <f>` | 输入向量文件（`{"vectors":[...]}` 或裸数组），默认 `vectors.json` |
| `--out <f>` | 结果 JSON，默认 `results.json` |
| `--proof-out <f>` | 保存证明（**只支持单向量**）+ 边车 + `.meta.json` |
| `--proof-mode core\|compressed\|groth16\|plonk` | 默认 `core` |
| `--proof <f>` + `--verify` | 独立验证模式 |
| `--verify-reps <n>` | 重复验证次数（把 vkey setup 与纯 verify 分开计时） |
| `--check` / `--execute` | 宿主校验 / 只跑 zkVM 记 cycle 数 |

### 模式细节

- **`--check`**：直接 `run_job`，不构造任何证明器。**快，CI 与交叉验证的主力**。
- **`--execute`**：`client.execute(POP_ELF, stdin)`，在结果里附
  `"cycles": report.total_instruction_count()` —— `bench/bench_cycles.py` 的取样来源。
- **出证（默认）**：`client.setup(POP_ELF)` → 按 `--proof-mode` 选 `core/compressed/groth16/plonk`
  → 出证 → **立即本地 `verify` 一次**（确保证明有效）→ 写结果。
  若给了 `--proof-out`：`proof.save(path)` + `write_verifier_sidecar(...)` + `.meta.json`
  （含 `vkey_hash`、`proof_file`、`proof_mode`）。
- **`--verify`**：从 ELF 重新 `setup` 推导 vkey → 重复 `client.verify(...)` 计时 →
  读回公开值 `Outcome` → 输出 `{verified, vkey_hash, setup_seconds, verify_times_seconds, outcome}`。
  **不需要任何秘密**，这就是第三方验证的入口（也是 core 证明唯一可用的验证路径）。

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
build_program_with_args("../program", Default::default())
```

把 guest 编译成 zkVM ELF，使 `include_elf!("pop-program")` 生效。**改动 `types` 后必须重新构建**，
否则宿主驱动内嵌的还是旧 ELF（vkey 也会跟着变）。

---

## 5. `pop-verify`：仅验证器二进制（`verifier/src/main.rs`，125 行）

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
| **一个进程连出多证** | 前面几个都成功、第 6~7 个被 `SIGKILL 9` 杀，峰值 10.65→10.82 GB | 每个证明后内存**缓慢累加**（不回落），单进程跑不完 14 条向量；`cross_validate.py` 因此默认 `--chunk 4`（每块一个干净进程，结果按原序合并） |
| `no method named keep` | `sp1-prover` 编译失败 | 上游 `tempfile` 3.x 无 `TempDir::keep()` → 保留 `circuits/patches/tempfile` 与 `[patch.crates-io]` |
| 缺 `libsp1gnark.a` | 构建失败 | 需 Go ≥1.24 + `GOPROXY=https://goproxy.cn,direct` |
| 缺 `protoc` | 构建失败 | `sudo apt-get install -y protobuf-compiler` |
| 网络限流 | `cargo fetch` 卡住 | 用 rsproxy sparse 镜像（`~/.cargo/config.toml`） |

**实测数字**（24 核 / 12 GB CPU）：

| 配置 | 证明时间 | 纯验证 | 证明大小 | 峰值内存 |
|---|---:|---:|---:|---:|
| 200 字符 × 3 规则 | 127.4 s | ~90 ms | 2.72 MiB | 10.76 GiB |
| 200 字符 × 6 规则 | 140.5 s | ~90 ms | 2.72 MiB | 10.86 GiB |
| 1000 字符 × 1 规则 | 98.5 s | ~90 ms | 2.71 MiB | 9.83 GiB |

证明时间由证明器**固定开销主导**（~100 s 量级），随长度/规则数的边际成本体现在 zkVM 周期数上
（见 `08` 与 `bench/results/`）。

---

## 7. 构建命令

```bash
cd circuits/program && cargo prove build                  # 生成 guest ELF
cd circuits/script  && cargo build --release -p pop-script
cd circuits/verifier && cargo build --release -p pop-verify  # 可选，审计快路径需要
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

---

## 9. 测试对应

| 测试 | 覆盖 |
|---|---|
| `tests/test_rules_incircuit.py` | 六类规则在 `--check` 下与 Python golden 逐点对齐（含规范化证据串） |
| `tests/test_trace.py` | P1-5 四条验收（完整链通过 / 删·换·重排失败 / 伪造回执验签失败 / 旧向量被拒），并实测 `trace_root` 与 Python 逐字节一致 |
| `tests/test_binding.py::TestPythonRustParity` | `response_binding` 在电路内与 Python 逐字节一致（公开 + 私有，多种 nonce 长度） |
| `tests/test_ablation.py::TestRustNaivePath` | Rust 侧 `nfa_match` ≡ `nfa_match_naive` |
| `tests/test_verifier_only.py` | `pop-verify` 的调用与快路径判定 |
| `bench/bench_cycles.py` | `--execute` 的 cycle 数矩阵（长度 × 规则数 × pike/naive） |
| `bench/bench_proofs.py` / `bench_verify.py` | 证明时间/体积/内存；验证的冷启动 vs 纯验证 |
| `scripts/cross_validate.py` | host 14/14 + prove 14/14（**I1 的总闸门**） |

---

## 10. 扩展指引

- **加规则类型**：先按 `01` §7 的六步改 Python 侧，再在这里加 `Constraint` 变体 + `evaluate` 分支，
  且**证据字符串必须逐字节一致**。跑 `cross_validate` 验证。
- **加证明模式**：在 `pop-script` 的 `match proof_mode` 分支与 `write_verifier_sidecar` 里各加一处，
  同时更新 `policydsl.verifier.VERIFIER_ONLY_MODES`（如果新模式支持 verifier-only）。
- **优化证明开销**：当前瓶颈是证明器固定开销与 O(n·states) 的 NFA 扫描。
  `bench/results/` 里有基线数字，改动后用同一脚本复测再对比。
- **升级 SP1**：`types/program/script/verifier` 四处版本号需一起动，
  并确认 `circuits/patches/tempfile` 是否仍被需要（上游修好后可删）。

---

**相关**：契约怎么来的 → [`01-policy-dsl.md`](01-policy-dsl.md)；
私有模式的承诺语义 → [`02-privacy-commitment.md`](02-privacy-commitment.md)；
数字怎么复现 → [`08-tests-bench.md`](08-tests-bench.md)、[`../reproduce.md`](../reproduce.md)。
