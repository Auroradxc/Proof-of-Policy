# 电路级披露 coarsening（C2 / M4-01 MVP）落地记录

> **状态**：2026-11-01，分支 `bhv/c2-circuit-disclosure`，基线 `1c1fc60`。
> 本文件记录**已实现范围**、公开值 v2 schema、测试矩阵、新 binary/vkey 与
> **未实现项**。设计与威胁模型见
> [`../design-disclosure-levels.md`](../design-disclosure-levels.md)；
> 降级/阻塞见 [`../blockers/C2.md`](../blockers/C2.md)。
>
> **一句话**：披露级别现在是 `ProofRequest` / `PrivateRequest` 的私有输入，
> guest 在 commit 之前按级别生成违规形状；证明公开值本身只含该级别允许的
> 字段，并带 `public_value_schema = "pop-pv-v2"` 与 `disclosure_level`。
> 验证方不再重投影，只检查 schema/级别/形状与「证书载荷 == 解码公开值」。

---

## 1. 实现范围

| 层 | 文件 | 改了什么 |
|---|---|---|
| 共享类型 / guest 逻辑 | `circuits/types/src/lib.rs` | `DisclosureLevel`、`RuleCategory`、`DisclosedViolation`、`DelegatedBucket`；`ProofRequest` / `PrivateRequest` 加 `disclosure_level`（serde 默认 L0）；`evaluate` / `evaluate_private` 在 commit 前 coarsen；`outcome_value` 输出 v2 字段 |
| 宿主驱动 | `circuits/script/src/main.rs` | `VectorIn` 加 `disclosure_level` 并传入 `Job`（否则 vectors 无法选择级别） |
| Python 承诺/校验 | `policydsl/evidence/disclosure.py` | v2 承诺助手（`item_commitment_v2` / `bucket_commitment_v2` / `rule_name_commitment_v2` / `names_commitment_v2`）；`validate_outcome_v2`；`check_outcome_disclosure` 改为不投影；legacy 投影保留给 v1 |
| 证书组装 | `policydsl/evidence/cert.py` | `build_payload` 不再投影；v2 outcome 原样存，写 `binding.public_value_schema` 与顶层 `disclosure_level`；v1 outcome 冒充级别 fail closed |
| 验证脚本 | `scripts/verify/verify_cert.py` | 删除重投影；校验 schema/级别/形状与逐字段相等；`--legacy-v1` 仅放行 L0 |
| 测试 | `tests/test_disclosure_levels.py`、`tests/vectors/disclosure_v2.json` | 主矩阵、跨语言 golden、v1 组合、CLI 端到端 |

**未改**：规则判定、gate、`policy_hash`、`response_binding`、`trace_root`、
`paper/`、云机、其他 agent 的 `bench/results/*`。旧 vkey 结果保持历史。

---

## 2. 公开值 v2 schema

公共骨架（`mode` 在证书载荷里被剥掉，由顶层 `payload.mode` 表示）：

```json
{
  "mode": "public",
  "policy_hash": "…",
  "response_binding": "…64 hex…",
  "trace_root": "…",
  "passed": false,
  "public_value_schema": "pop-pv-v2",
  "disclosure_level": "L1",
  "violations": [ ... ],
  "violation_count": 2,
  "delegated": [],
  "delegated_buckets": []
}
```

| 级别 | `violations` 条目 | 额外字段 |
|---|---|---|
| L0 | `{"shape":"raw","rule","kind","evidence_commitment"}` | 无 `violation_count`；`delegated` 可非空 |
| L1 | `{"shape":"category","category","count","evidence_commitment"}`，按类别 id 升序 | `violation_count = Σ count`；`delegated` 必须为空 |
| L2 | `{"shape":"opaque","evidence_commitment"}`，按承诺非降序 | 无 `violation_count`/类别/计数；`delegated` 必须为空 |

`evidence` 明文在**所有**级别都不进公开值（L0 也只留承诺）。L2 的列表长度
仍等于违规条数 —— 这是如实标注的泄露，不假装隐藏存在性。

**实现注记（踩过的坑）**：SP1 公开值用 **bincode** 编解码，而 bincode 不支持
`deserialize_any` —— 第一版把 `DisclosedViolation` 写成 internally-tagged enum
（`#[serde(tag = "shape")]`），出证到最后读公开值时直接 panic
`DeserializeAnyNotSupported`。最终用**固定字段 struct**（`shape` + `Option`
字段）保证 bincode 可解码，JSON 的精确形状由 `to_json_value()` 手工摊平。
因此 `ProofOutput`/`PrivateOutput` 的字段**不能**用
`skip_serializing_if`（bincode 会错位）；`violation_count` 的「L0/L2 不出现」
只在 JSON 侧实现。

### 2.1 承诺字节（Python ↔ Rust 逐字节一致）

```text
item(E)   = H("pop-disclose-v1" ‖ 0x01 ‖ RB ‖ u32be(len(E)) ‖ E)
bucket(C,n) = H("pop-disclose-v1" ‖ 0x02 ‖ RB ‖ u8(cat_id(C)) ‖ u32be(n)
                ‖ concat(sorted_raw32(item(E_i))))
rule_name(R) = H("pop-disclose-v1" ‖ 0x04 ‖ RB ‖ u32be(len(R)) ‖ R)
names(S)  = H("pop-disclose-v1" ‖ 0x03 ‖ RB ‖ u32be(|S|)
                ‖ concat(sorted_raw32(rule_name(R))))
```

`RB` = 公开值里 `response_binding` 的 64 个 ASCII 字节（盐）。类别 id：
`content=0, length=1, format=2, tool_arguments=3, budget=4,
trace_integrity=5, semantic=6, other=7`。

固定向量在 `tests/vectors/disclosure_v2.json`；Rust
`disclosure_contract_tests` 与 Python `TestCrossLanguageGolden` 读同一份。

### 2.2 类别映射

| 类别 | kind |
|---|---|
| content | `keyword_block`、`normalized_keyword_block`、`pattern_block` |
| length | `length_bound` |
| format | `format_check` |
| tool_arguments | `tool_arg_guard`、`retrieval_guard`（C1 的 Python 映射缺这条，已补） |
| budget | `budget_bound` |
| trace_integrity | `trace_unbound`（含合成规则 `<trace>`） |
| semantic | `semantic_bound`（只用于 delegated 桶，不产生 violation） |
| other | 未来新 kind 的兜底 |

---

## 3. fail-closed 规则（本 MVP）

- 未知 `public_value_schema` / `disclosure_level`；
- 证书顶层级别 ≠ 公开值里的级别；
- L0 出现 `violation_count`、L1 桶重复/乱序、L1 `violation_count` ≠ 桶和、
  L2 承诺乱序、任何级别出现多余键；
- L1/L2 的非空 `delegated`（类别桶 schema 未实现）；
- 非空 `delegated_buckets`（未实现）；
- 私有模式带非空 `delegated`（既有电路边界）；
- 证书载荷与解码公开值任一字段不同；
- 旧 v1 证明默认拒绝；`--legacy-v1` 只放行 L0 并标注。

---

## 4. 测试矩阵

| # | 级别 | 模式 | delegated | 期望 | 覆盖 |
|---|---|---|---|---|---|
| 1 | L0 | public | 空 | raw + 承诺，无明文 evidence | `TestV2Shapes` / Rust `l0_*` |
| 2 | L1 | public | 空 | 类别桶 + 计数 | 同上 |
| 3 | L2 | public | 空 | 仅承诺、排序 | 同上 |
| 4 | L0 | public | 非空 | 名字可见、通过 | `test_matrix_level_mode_delegated` |
| 5 | L1 | public | 非空 | fail closed | 同上 |
| 6 | L2 | public | 非空 | fail closed | 同上 |
| 7 | L0 | private | 空 | 通过 | 同上 + Rust parity（构建后） |
| 8 | L1 | private | 空 | 通过 | 同上 |
| 9 | L2 | private | 空 | 通过 | 同上 |
| 10–12 | L0/L1/L2 | private | 非空 | 拒绝（既有电路 panic / 验证器拒绝） | `test_matrix_*` |

另有：v1 三种组合（v1 cert×v1 proof / v1×v2 / v2×v1）、未知级别/schema、
级别不一致、L1 计数篡改、L2 乱序、raw 字段回流、CLI 重签篡改级别、
Python↔Rust 固定向量对拍。运行：

```bash
python3 -m unittest tests.test_disclosure_levels tests.test_cert tests.test_binding -v
cd circuits && cargo test -p pop-types
```

**本轮实测计数（2026-11-02）**：

- `tests.test_disclosure_levels tests.test_cert tests.test_binding tests.test_doc_links`
  → **76 passed, 0 skipped**（`pop-script` 已构建，Rust parity 真跑）；
- 再加 `tests.test_rules_incircuit` → **89 passed**；
- `cargo test -p pop-types` → **14 passed**。

---

## 5. 构建、binary 与 vkey

### 5.1 本机（WSL2）构建 —— **只作 smoke test**

| 项 | 值 |
|---|---|
| 构建命令 | `cd circuits && cargo build --release -p pop-script -p pop-verify` |
| rustc / cargo | `1.98.1` / `1.98.1` |
| `pop-script` sha256 | `c34572c40a7c543133b731fa6b9e0b308254230fa150ea8580ed8c8a171b0716`（91,153,104 B，2026-11-02 00:15） |
| `pop-verify` sha256 | `ec7099e787a37872017114b5004108433fa3fec0cbc20baf430d28f96e7008f1` |
| `pop-program` ELF sha256 | `e12ba4e6e104b6b5511224cf352ef40d90492810b1dba1fd62058aa3451d1ec5` |
| `pop-infer` ELF sha256 | `d8e295df2ae6d3c71968d1f8e10623a80ddc8edaef8c24b505a85e8a20ed33ae` |
| `pop-session` ELF sha256 | `802af38abefad0218cd6427c24e9583decbc65bdf192d000434b6af276c4bf91` |
| policy guest vkey | `0x00fa511955b3a42968dfe65bedd5d92060fe03f56d20264c07ffb2cc6ddb5e6a` |
| infer guest vkey | `0x00d9dd9d181f92ad194488f615a0c1b5dbcdd1ebc564628bc521354e0db13c51` |
| session guest vkey | `0x0079acd4084a69dd2656ef82ebaa4a2487b1eca396658cf4a9974b8a1d563d20` |

### 5.2 云机（AutoDL，16 核 / 90 GiB cgroup）构建 —— **实验结果以这套为准**

| 项 | 值 |
|---|---|
| 构建命令 | 同 5.1，`CARGO_TARGET_DIR=/root/autodl-tmp/zk-policy-c2-target` |
| rustc / cargo | `1.99.1` / `1.99.1`（succinct `1.94.0-dev`） |
| `pop-script` sha256 | `374ee241a72a5e5d55b69248f5812255d7a19dc32e8abede6b347ce0c684e13c` |
| `pop-verify` sha256 | `dfd4c7ffaa9dee3619b76b31f27697634bb5c24bf66c340eed3a706fe6516bcb` |
| `pop-program` ELF sha256 | `4d30bac4d5011954d1ef71abd9d6c0e89e4dc653a2835944a2a772ec131f3f51` |
| `pop-infer` ELF sha256 | `81e9dae78e8ce169798f41b586600938468a09090a7737658d78549e11410630` |
| `pop-session` ELF sha256 | `e36e5a6bee14d1d00a02b557f2047bf153d7f48fbee8a88668d571fb18da5806` |
| policy guest vkey | `0x000cfdfc7325f13f5887e434baa89860aae6675f0f30ec2b480dfe98b62c0b2a` |
| infer guest vkey | `0x0077c9fc2015ef47ff820270888723bd35546a8a3918b85fd04aaf1ccc8809d6` |
| session guest vkey | `0x003a4b7bc67b9250907987c8578814b2bd867cb25d9b1dfecdd742734c2e6905` |

### 5.3 结论：vkey **不是跨构建机可复现的**

同一份源码、同一套 SP1 版本，本机（rustc 1.98.1）与云机（rustc 1.99.1）编出的
guest ELF sha256 不同，因此 **vkey 也不同**（`0x00fa5119…` vs `0x000cfdfc…`）。
这不是本轮代码引入的偏差，而是「vkey 依赖编译器/构建环境」的既有事实：

- **本地 proof 只能当 smoke test**，不能与云机 vkey 混表；
- 论文/实验结果只引用**云机** vkey `0x000cfdfc…`；
- 本机 L0 真证明（§6）只用于确认代码路径能出证/验证，不作为实验口径。

**与旧记录的对比（均变化，旧结果不得混表）**：

| guest | 旧 vkey（`Core.md`） | 本机新 vkey | 云机新 vkey |
|---|---|---|---|
| policy | `0x003eb14d…` | `0x00fa5119…` | `0x000cfdfc…` |
| infer | `0x0068573e…` | `0x00d9dd9d…` | `0x0077c9fc…` |
| session | `0x00a633b0…` | `0x0079acd4…` | `0x003a4b7b…` |

> `pop-types` 被三个 guest 共享：即使推理/会话语义未改，ELF 与 vkey 也变了。
> 旧 vkey 结果保持历史，不得与新 binary 混表。vkey 用
> `cargo prove vkey --elf <ELF>` 得到；三个 ELF 在
> `circuits/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/`。

---

## 6. core 出证/验证结果

### 6.1 云机（实验口径）

AutoDL 云机（16 核 / 90 GiB cgroup）用 §5.2 的同一套 binary + ELF，串行跑一个
小策略点：`keyword_block(no-secret)` + 响应 `"this has a secret in it"`，
`--proof-mode core`。三档各自独立进程，出证后立即 `pop-script --verify`。

| 级别 | 出证 | `--verify` | proof sha256 | 公开值要点 |
|---|---|---|---|---|
| L0 | PASS | `verified=true` | `fafa63b4336a44efb338241a564ff99a9dbd490695307ed7de9b11ecf8e70134` | raw + 承诺，无明文 evidence |
| L1 | PASS | `verified=true` | `e0f5e81148ce52d795179cdd2508f3e5e977f0bff546f6bcbafd7807c240e32b` | 1 个 `content` 桶，`violation_count=1` |
| L2 | PASS | `verified=true` | `6846e62b4a130678d044f130781d5f073a276a8363b4c4d1392c85bfd9a50ed2` | 1 条 opaque 承诺 |

三档 `--verify` 输出的 `vkey_hash` 均为云机 policy vkey
`0x000cfdfc7325f13f5887e434baa89860aae6675f0f30ec2b480dfe98b62c0b2a`。
三档公开值的 `policy_hash` / `response_binding` / 承诺字节完全一致（只有披露形状
不同），与 Python 侧按同一 `response_binding` 重算的结果一致。

L1 解码公开值（`--verify` 输出，节选）：

```json
{"public_value_schema":"pop-pv-v2","disclosure_level":"L1",
 "violation_count":1,
 "violations":[{"shape":"category","category":"content","count":1,
                "evidence_commitment":"32dc7757930cfc60…"}],
 "delegated":[], "delegated_buckets":[]}
```

### 6.2 本机 smoke test（不进实验口径）

本机（WSL2，24 核 / 14 GiB）也跑过一次 L0 core 证明，`verified=true`，
vkey 是本地 build 的 `0x00fa5119…`（与云机不同，见 §5.3）。它只用于确认代码
路径可出证；L1/L2 在本机因内存压力被 OOM/SIGKILL 中断，最终三档以云机为准。

> 第一次 L0 出证在本机**读公开值**时失败（`DeserializeAnyNotSupported`），
> 原因与修法见 §2 的实现注记与 [`../blockers/C2.md`](../blockers/C2.md)。
> 修复后本机 L0 与云机三档均成功。

---

## 7. 未实现项 / 迁移

1. **delegated 类别桶**：`DelegatedBucket` 类型与承诺助手已落地，但电路内
   分组、`names_commitment`、陪伴证明按桶匹配**未实现**；L1/L2 非空
   delegated 一律 fail closed。
2. **groth16/plonk**：本轮范围明确**只跑 core**；不主张 witness-hiding，
   `core` 工件仍泄露 raw 见证。云机已可用于后续 groth16 实验，但不在本轮验收内。
3. **旧工件迁移**：旧 v1 证明默认拒绝。`--legacy-v1` 能接受 v1 证书与外部
   解码出的 v1 proof_result，但**新 `pop-script` 不再能解码 v1 公开值**
   （类型已变），要继续验证旧证明文件需要归档旧 binary。
4. **宿主判定镜像**：`policydsl/runtime/service.py::host_outcome` 仍输出 v1 raw
   形状，`verify_session.py` 仍按旧路径投影；未改（超出本轮硬边界）。
5. **bench**：`bench/bench_policy_corpus.py` 用
   `cert.build_payload(disclosure_level=...)` + v1 outcome，需改为真实 v2
   公开值后才能重跑推断实验。
6. **L2 列表长度**、**L1 类别/计数**、**core trace**、**重执行通道**仍泄露，
   与设计 §10.2 一致。

---

## 8. 复现

```bash
# 1) 编译（长任务，建议 nohup/tmux）
cd circuits && cargo build --release -p pop-script

# 2) Rust 单元 + 跨语言 golden
cargo test -p pop-types

# 3) Python 验收
cd .. && python3 -m unittest \
  tests.test_disclosure_levels tests.test_cert tests.test_binding tests.test_doc_links -v

# 4) 宿主校验（不出证）：三级公开值形状
cat > /tmp/v.json <<'JSON'
{"vectors":[{"name":"l1","response":"secret ...","spec_canonical":"<spec>","disclosure_level":"L1"}]}
JSON
circuits/target/release/pop-script --check --vectors /tmp/v.json --out /tmp/r.json

# 5) core 出证 + 验证（内存地板 ~10.15 GiB）
SP1_PROVER=cpu circuits/target/release/pop-script --vectors /tmp/v.json \
  --out /tmp/r.json --proof-out /tmp/proof.bin
circuits/target/release/pop-script --verify --proof /tmp/proof.bin --out /tmp/verify.json

# 6) vkey
cargo prove vkey --elf <guest ELF>
```
