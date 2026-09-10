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
| `ToolCall { name, args: BTreeMap<String,String> }` | 轨迹里的工具调用 |
| `FormatKind { Json, Int, Float }` | `format_check` 的格式（snake_case 序列化） |
| `BudgetUnit { Calls, Tokens }` | `budget_bound` 的计量单位 |
| `NfaSpec { start, accept, states }` / `NfaState { eps, edges }` / `NfaEdge { to, ranges }` | **可序列化 NFA 契约**（由 `policydsl.nfa` 产出） |
| `PatternMode { Pike, Naive }` | 匹配模式（默认 `Pike`） |
| `Constraint` | 六种变体的枚举（见下表） |
| `ProofRequest { response, constraints, tool_calls, token_count }` | 公开模式输入 |
| `Violation { rule, kind, evidence }` | 违规（证据为**字符串**） |
| `ProofOutput { passed, violations }` | 公开模式输出（提交为公开值） |
| `PrivateViolation { rule, kind, evidence_commitment }` | 私有模式的违规（只有承诺） |
| `RedactionProof { redacted_commitment, mask_count, redaction_ok, mask_covered }` | 脱敏证明 |
| `PrivateRequest { response, constraints, mask, redacted, spans, tool_calls, token_count }` | 私有模式输入 |
| `PrivateOutput { response_commitment, passed, violations, redaction }` | 私有模式输出 |
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

序列化为 serde 的**外部标签**枚举（`{"KeywordBlock": {...}}`），由 `serialize.spec_to_rust_constraints` 生产。

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
| `ToolArgGuard` | `tools` 非空时限定范围；命中被禁字段即记（每个调用至多一条） | `"<tool>:<field>"` |
| `BudgetBound` | `calls` → `tool_calls.len()`；`tokens` → `token_count.unwrap_or(0)` | `"<unit>=<total>/<budget>"` |

`passed = violations.is_empty()`。

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
response_commitment = sha256_hex(&req.response);
```

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

---

## 9. 测试对应

| 测试 | 覆盖 |
|---|---|
| `tests/test_rules_incircuit.py` | 六类规则在 `--check` 下与 Python golden 逐点对齐（含规范化证据串） |
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
