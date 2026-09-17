# 重构与优化建议书 · 执行计划（2026-09-17）

> **状态：提案，尚未执行。** 本文件是 [`dev-plan.md`](dev-plan.md)（唯一维护中的计划）
> 的一次**专项输入** —— 它提出改什么、按什么顺序改、每步的闸门是什么。
> 采纳哪些、什么时候排进 `dev-plan.md`，由那份计划决定。
>
> 本文遵守 [`docs/README.md`](README.md) §4 的两条纪律：**不写恒真的断言**（每条结论
> 后面跟着「怎么验的」），**过期就标注**。文中的每个数字都**在结论旁边**带着重跑命令
> （测量环境见 §1.2），没有一份数字是孤零零摆在那里的。

---

## 0. 怎么读这份文档

### 0.1 证据分级

本文每条结论都带一个标记，**不要把三者混着读**：

| 标记 | 含义 |
|---|---|
| ✅ **实测** | 在 1.2 节那台机器上真跑出来的数字，命令写在结论旁边 |
| ⚠️ **推断** | 从实测数据推出来的，没有直接量过（例如「按线性外推到 4000 字符」）|
| ❓ **未验证** | 明确**没有**验证过，当作待办而不是结论。第 6 节集中列它们 |

### 0.2 这份建议书的立场

先说结论，免得读到第 2 节才发现重点：

1. **这个仓库的整体结构是健康的，不建议大动。** 跨层契约（ConstraintSpec 规范字节）、
   双实现交叉校验（Python golden ↔ `pop-types`）、fail-closed 的默认值 —— 这三条
   立得住，是仓库最值钱的部分。任何重构都不该碰它们。
2. **问题不在架构，在「同一件事被写了 3–34 遍」。** 本次普查找到的最集中在、
   最可机械验证的，全是这类：**34 处** `POP_SCRIPT` 路径、**16 份**策略加载器、
   **6 份** `sha256_file`、**4 条** kind 分派链。其中**三处已经真的漂移了**，
   而且第三处（`parse_ints`，§2.4.2 ③）**是一条活的 bug —— 它自己的 docstring
   举的例子都跑不过**。
3. **性能的真问题只有两个，都在热路径上，都有实测支撑**：NFA 匹配的常数因子
   （✅ 约 1 µs/字符）与**流式路径的 O(L²)**。第二个尤其值得看：同一个「2000 字符」
   在 7 个包里从 **116 ms 到 4855 ms（差 42 倍）**，而**最贵的那个包
   （`pii_redaction_v1`）恰恰没有 `length_bound`，代价因此没有天花板**（§2.2.3.2）。
   两者都不是「架构问题」，修法不改变任何语义。
4. **内存的真问题只有一个，但本机无解。** ~10.15 GiB 的地板是 SP1 默认配置的
   固定开销；Python 层的 24 MB 在它面前是噪声。**能做的是把它变成一次可测的实验**，
   而不是继续当它不存在（见 §2.3）。
5. **本轮的交付是「改什么 + 怎么验」，不是「改」。** 每一阶段都独立提交、独立回滚。

---

## 1. 起点：现状普查

### 1.1 规模（✅ 实测，`wc -l`）

| 部分 | 文件 | 行数 |
|---|---:|---:|
| `policydsl/` + `scripts/` + `bench/` + `semantic/`（生产 Python） | 64 | **18,291** |
| `tests/`（31 个 `test_*.py` + 3 个 helper） | 34 | 12,282 |
| `circuits/`（**不含** vendored `patches/` 与 `target/`） | 10 | **2,453** |
| 其中 `circuits/types/src/lib.rs` 单文件 | 1 | 1,752（= 项目 Rust 的 **71%**）|

单文件最大的几个：`runtime/service.py` 1,172 · `proofs/multiparty.py` 919 ·
`evidence/trace.py` 650 · `core/nfa.py` 575 · `evidence/anchor.py` 610。

**读法**：Python 是 7.5 倍于 Rust。这不是浪费 —— Python 是参考层 + 编排层 + 工具链，
Rust 只负责「进电路的那点判定」。但这个比例决定了**优化的主战场在 Python**。

### 1.2 测量环境（每台机器都不一样，引用数字时请连着这行引）

```
主机   24 核 Intel i7-14650HX，内存 11.7 GiB（与 bench/results/proofs.md 同一台）
Python 3.10.12（无 venv、无 pytest —— 项目用 stdlib unittest）
SP1    v6.7.0，pop-script 已构建于 circuits/target/release/pop-script
基线   python3 -m unittest discover -s tests -t .  →  Ran 685 tests, OK (skipped=15)，38.2 s
```

复现本文性能数字的命令都在 §2.2 与 §2.3 的表格里，逐条可重跑。

---

## 2. 建议书

### 2.1 技术框架

#### 2.1.1 立得住的部分（**不要动**）

| 机制 | 为什么它是这个仓库最值钱的东西 |
|---|---|
| **ConstraintSpec 规范字节**（`core/compile.py:43`） | 判定用的约束与 `policy_hash` 来自**同一段字节**，证明者无法「用空策略判定、声称真策略的哈希」。这是整个健全性的支点 |
| **双实现交叉校验** | 判定写了三遍（Python `evaluate` / Python `commit.canonical_violations` / Rust `pop_types::evaluate`），但 `cross_validate.py`（✅ 19/19）与 `runtime/service.py:311` 的 `VerdictMismatch` 把「三者必须一致」变成了**运行时会响的**检查，而不是一句注释 |
| **fail-closed 的默认值** | 未知 kind → `PolicyError`（✅ 84 组不可哈希/非字符串 kind 已测）；坏回执链 → `trace_unbound`；语义规则在私有模式 → panic。默认值是「拒绝」而不是「放行」 |

#### 2.1.2 分层倒置：`core → proofs`（⚠️ 结构问题，建议处理）

`core` 是「策略 DSL + golden 判定」层，`proofs` 在它**上面**。但：

```
core/compile.py:92   _semantic_constraint()      → from policydsl.proofs import semantic
core/compile.py:119  _model_vkey()               → 同上
core/compile.py:145  require_covering_length_bound() → 同上
core/evaluate.py:238 语义规则分支                 → 同上（还顺带 import core.compile）
```

同时 `proofs/multiparty.py:110` 顶层 import `core.compile`。于是两者**互相依赖**：
不是 import 期的硬环（compile 那三处是函数内延迟 import），但**逻辑上是双向的**。

**代价的实证**：本节所有「同口径，避免循环导入」的注释（`compose.py:470`、
`multiparty.py:272`、`session.py:477`）都是被这个倒置逼出来的 —— 它们各自重写了一份
策略加载器，理由写在 docstring 里就是「避免循环导入」。

**建议**：把 `semantic` 里**纯契约**的那部分（`model_manifest` / `input_width` /
`onnx_sha256` / `vk_path` / `ARTIFACT_NAMES`）下沉到 `core` 或一个新的 `core/model_fp.py`，
`proofs/semantic.py` 保留 ezkl 出证/验证逻辑并 re-import 契约部分。
**只搬位置，不改任何函数体**。

**风险**：中。`semantic.py` 是 602 行且与 `ezkl_prove.py` 有产物路径耦合。
**建议先做 §2.4 的加载器收敛，再考虑这一条** —— 两者都会碰到同一批文件。

#### 2.1.3 跨层字符串常量靠注释维持（✅ 已实证会漂移）

以下常量在 Python 与 Rust 各写一份，**只靠 docstring 说「必须逐字符相同」**：

`INFER_MODEL_SPEC`（`proofs/infer.py:74` ↔ `types/lib.rs:1341`）、
`SEMANTIC_SYSTEM_EZKL = "ezkl-halo2"` 值（`semantic.py:94` ↔ `lib.rs:349`）、
四个域分隔前缀（`BIND_DOMAIN` / `TRACE_DOMAIN` / `TRACE_GENESIS` / `MERKLE_NODE_DOMAIN`）、
`SPEC_VERSION` / `FOLD_VERSION` / `SPEC_VERSION`。

⚠️ **风险是实打实的**：`model_hash` 的原像、公开值里的 `system` 字段、
`response_binding` 的域分隔 —— 任何一个改一个字，**证明照样出得来，只是验不过**，
而且要到「你正好要演示的那一刻」才发现。

**建议**：新增 `tests/test_cross_layer_constants.py`，**用正则从 `.rs` 源码里抽字面量**
与 Python 侧的常量逐一比对。这是**机械手段**，与 `test_rule_kinds.py` 同一思路。

**判据**：故意把 `lib.rs:349` 的 `"ezkl-halo2"` 里改一个字符 → 该测试**必须变红**。

> ⚠️ 注意：`cross_validate.py` 覆盖的是**判定结果**，不覆盖这些常量本身。
> 所以「cross_validate 19/19 全绿」不能拿来当常量一致性的证据。

#### 2.1.4 CI 只覆盖了仓库的一小半（✅ 实测 `.github/workflows/ci.yml` 全文 27 行）

现有 CI 三个步骤：`unittest discover -s tests`、两个额外的 anchor 测试模块、
一条「文档里不许有本机绝对路径」的 grep。

**没有覆盖、但本机跑得动且成本可忽略的**：

| 缺什么 | 为什么该加 | 成本（✅ 实测） |
|---|---|---|
| `cross_validate.py --no-prove` | 项目自己的关键闸门，19 条交叉验证 | **0.048 s** |
| Rust 构建 | `cargo build --release -p pop-script` 无改动时 | 8.9 s |
| 文档相对链接普查 | §5.6.9 那 268 条链接的普查脚本是**一次性的，没入库** | < 1 s |

**建议**：这三条加进 `.github/workflows/ci.yml`。**改动只有十几行**，但把
「§5.6.9 手工验过一次」变成「每次 push 都验」。

---

### 2.2 执行效率与速度

#### 2.2.1 先把不是问题的排除掉（✅ 实测）

| 嫌疑 | 实测 | 结论 |
|---|---|---|
| **import 成本** | 空解释器 **9.6 ms** → `import policydsl` **25.5 ms**（净增 ≈16 ms）/ 24 MB；`import policydsl.runtime.service` **43.9 ms**（净增 ≈34 ms）/ 25.8 MB | **不是问题**，不要为此做 lazy import |
| **CLI 启动** | `python3 -m policydsl compile` 0.04 s、`check` 0.04 s | 同上 |
| **`Policy.validate()`** | 0.84 µs / 3 条规则（`model.py` 已被重构为分派表） | **不是瓶颈**（占 `check()` 的 0.04%）|
| **流式路径是否 O(n²) 之外的额外开销** | `check()` 每次调用被 `on_generate` 调 1 次，不是每 token 一次 | 无隐藏的二次爆炸 |

> 记录这一节是为了**防止有人再去优化这四项**。这个仓库的历史（`model.py` 的 if/elif）
> 说明「看起来该优化」和「实测是瓶颈」经常不是一回事。

**顺带两个 ✅ 实测的事实**（都不建议为它们单独开一项，但值得知道）：

1. **`import cryptography` 独占 6.2 ms** —— 来自 `evidence/cert.py:49-56` 的**模块级**
   `from cryptography... import` （包在 `try/except` 里，但 import 本身照跑）。
   `import policydsl` 因此加载了 **37 个** cryptography/bcrypt 模块。
   **不建议改**：16 ms 的净启动成本换一次「延迟导入 + 首次签名时的分支」，不划算。
2. **`import policydsl.core.model` 与 `import policydsl` 一样贵**（✅ 24.3 ms vs 25.5 ms）——
   因为 Python 先执行父包 `policydsl/__init__.py`，而那里就是 §2.4.5 那个**门面**。
   这给「门面是死的」补了第二条注脚：**它不只是没人用，而且每一次子包导入都在为它付费。**
   同样地，**不建议**为此改结构 —— 只是说明 §2.4.5 该收敛而不是维持现状。

#### 2.2.2 真问题 ①：NFA 匹配约 **1 µs/字符**，且每次 `check()` 重编译正则

✅ **实测**（`policy_packs/eu_ai_act_v1.json`，3 条规则，含 1 条 `pattern_block`）：

```
nfa.compile_pattern('[\\w.+-]+@[\\w-]+\\.[\\w.]+')   =  20.3 us
nfa.match_search(spec, text_167字符)                 = 163.2 us
nfa._closure_table(spec)          ← 每次 match_search 重算   =   6.5 us
evaluate.check(policy, text)      ← 现状：每次都重编译       = 204.9 us (median)
```

**输入长度与耗时（✅ 实测，线性）**：

| 响应长度 | `match_search` | µs/字符 |
|---:|---:|---:|
| 167 | 185 µs | 1.11 |
| 1000 | 1,024 µs | 1.02 |
| **2000** | **1,971 µs** | 0.99 |
| 4000 | 4,006 µs | 1.00 |

**为什么 2000 是那个该看的数**：项目自己的 `policy_packs/eu_ai_act_v1.json` 里
`length_bound.max = 2000` —— 这是**策略作者声明的合法响应的最大长度**。

**两个可修的浪费点**：

| # | 现状 | 建议 | 收益（✅ 实测） | 风险 |
|---|---|---|---|---|
| a | `core/evaluate.py:163` **每次调用** `nfa.compile_pattern(str(pat))` | `lru_cache` 缓存（`compile_pattern` 是 pattern 字符串的纯函数）| **4%**（2,057→1,970 µs @2000） | **极低** |
| b | `nfa._closure_table(spec)` 每次 `match_search` 重算，但它是 `spec` 的纯函数 | 随 spec 缓存 | **~7 µs/次**（@167 字符占 4%）| **极低** |
| c | `match_search` 内层：每个状态每条边都跑一次 `_point_in_ranges` 二分 | 预计算 `(state, codepoint) → 后继集合` 的转移表（ASCII 直查）| ⚠️ **推断** 3–10× | **中**（需逐字节等价验证）|
| d | 外层规则循环 `evaluate.py:118` **没有短路**：任一规则违规后，后面的规则仍然全跑（内层 `pattern_block` 的 `break` 只跳出**模式**循环）| 违规已成立时跳过纯「收集证据」性质的后续规则 | ⚠️ **推断**：仅对**违规**响应有效，合规响应 0 收益 | **低但不该做**（见下）|

> **关于 (d)，建议明确不做。** 它看起来是白捡的（违规就早退），但 `check()` 的契约
> 是「逐条规则收集违规证据」然后**统一打包**进 `CheckResult` —— 短路会改变
> `violations` 列表的**内容**，而那是证书公开值的一部分，也是 `cross_validate`
> 与 `VerdictMismatch` 逐条比对的输入。**省下的时间买不来这个语义损失。**
> （`_TraceRule` 那一段 `any(v.evidence_kind == "trace_unbound" ...)` 也依赖全量列表。）

**如实说明**：a 与 b 的收益加起来不到 10%，且是**零风险**的；c 才是常数因子的大头，
但它**改算法**，必须用「与新实现逐输入对拍」来验收（§4 P2 的闸门）。**若 c 不做，
a+b 也值得做。**

**关于 (c) 的一条好消息：仓库里已经有一台现成的对拍台。** `bench/bench_ablation.py`
就是做「同一个匹配语义、两种实现、量周期数」的（pike vs naive，✅ 实测它跑得通，
结果在 `bench/results/ablation.md`）—— 其中 naive 被实测为 **O(n²)**、到 n=200 已是
pike 的 **42.5×**（✅ 实测）。把 (c) 做成第三种模式挂上这台机器，
**收益就从「推断 3–10×」变成「同一套度量下量出来的一个数」**，也不需要新写验证脚本。

> ⚠️ 这台对拍台**目前跑不了逗号分隔的 `--ns`** —— 就是 §2.4.2 ③ 那个 `parse_ints` bug。
> 所以 **R18 是 R10 的前置**：不修它，量 (c) 的人第一步就会撞上这个报错。

**a 有一个现成的仓库内先例，照抄即可**（✅ 实测）：

```python
# policydsl/core/pii.py:26 —— 同一个 NFA，早就预编译好了
_NFA_CACHE = {name: nfa.compile_pattern(pat) for name, pat in PII_PATTERNS.items()}

# policydsl/privacy/commit.py:145 —— 也是同一条正确路径：从契约里取预编译结果
for i, s in enumerate(c["nfa"]["compiled"]):
    if nfa.match_search(s, response): ...
```

也就是说 **`evaluate.check()` 是全仓库唯一一处「拿着 pattern 字符串现编译」的地方** ——
`compile.compile_constraints` 编译一次写进契约、`commit` 从契约里读、`pii.py` 模块级预编译。
**这不是发明新做法，是把漏掉的那一处补上。**

#### 2.2.3 真问题 ②：**流式路径是 O(L²)**（这是本轮最大的一处）

**机制**（`policydsl/adapters/langchain_adapter.py:271-297`）：
`on_llm_new_token` 每收到一个 token，就对**从 1 到当前长度的每一个前缀**各判一次
（`stream_step_chars` 的**默认值是 1**，`langchain_adapter.py:185`）。

于是总代价 = Σ(k=1..L) O(k) = **O(L²)**。

✅ **实测** —— 走**真实**的 `PoPCallbackHandler.on_llm_new_token`，逐字符喂
（provider 最细的切法），采样 `stream_step_chars=1`：

| 策略包 | 规则 | 2000 字符 | 拟合常数 c |
|---|---|---:|---:|
| `agent_tool_v1` | tool_arg_guard ×1 + budget_bound ×1 | 116 ms | — |
| `agent_content_v1` | keyword + length + pattern | **729 ms** | 0.361 µs/字符 |
| `eu_ai_act_v1` | 同上 | **2,115 ms** | — |
| `pii_redaction_v1` | pattern_block ×**4** | **4,855 ms** | 2.426 µs/字符 |

**二次性是钉死的，不是外推**：`agent_content_v1` 在 L=2000/5000 上拟合出
0.361 / 0.352 µs/字符，`pii_redaction_v1` 在 2000/5000 上拟合出 2.426 / 2.389 µs/字符 ——
**两点各自相差 1.5% 以内**，说明 `总耗时 ≈ c·L²/2` 这个模型站得住。

> **同一个「2000 字符」差了 42 倍**（116 ms → 4855 ms），**差别全在策略包上** ——
> 因为每个采样点都要对**完整前缀**跑一遍**全部** pattern 的 NFA。
> 所以「流式要多久」这个问题**没有单一答案，必须连着策略包说**。

**上表的复现命令**（`docs/README.md` §3 要求数字指得回来源；本文还没有对应的
`bench/results/` 文件，所以把命令原样放在这里，任何人可重跑）：

```python
# 逐字符喂，走真实回调（不是自己模拟采样循环）
python3 - <<'PY'
import time, json, pathlib
from policydsl.core.model import Policy, Rule
from policydsl.adapters.agent import AgentMonitor
from policydsl.adapters.langchain_adapter import PoPCallbackHandler
REPO = pathlib.Path(".").resolve()
d = json.loads((REPO / "policy_packs/pii_redaction_v1.json").read_text())
pol = Policy(d["id"], d.get("version", "0.1.0"),
             rules=[Rule(kind=r["kind"], name=r["name"], params=r.get("params", {}))
                    for r in d["rules"]])
text = ("The quarterly report covers routine operational metrics and general "
        "observations about the deployment process. " * 400)
for L in (2000, 5000):
    h = PoPCallbackHandler(AgentMonitor(pol))
    t0 = time.perf_counter()
    for ch in text[:L]:
        h.on_llm_new_token(ch, run_id="r")
    dt = (time.perf_counter() - t0) * 1000
    print(f"L={L}  {dt:.1f} ms  c={dt*1000/(L*(L+1)/2):.3f} us/char")
PY
```

**这不是理论问题，是跑得出来的**：`demo_e2e.py` 里 `canonical_violations` 被调
**69 次**（✅ 实测），而 `check()` 只有 5 次 —— **流式路径是这个仓库里被调得最勤的判定路径**。

#### 2.2.3.1 顺带发现：两份文档里的流式代价数字，被低估了约 25 倍

`docs/modules/06-frameworks.md:133` 与 `adapters/langchain_adapter.py:176` 的 docstring
（**同一句话，两处**）写着：

> 每个采样点要对**完整前缀**跑一次参考评估器（实测 ~0.07 ms/字符，10k 字符的响应约 0.7 s）

✅ **实测对不上**：

```
L =  2000  →     716 ms     文档口径推出来应是 0.07 × 2000  =    140 ms
L = 10000  →  17,542 ms     文档写的是                      =    700 ms   ← 低估 25×
```

**这个数字是怎么错的（可复现的推断）**：0.07 ms/字符 是我实测 **L≈200** 处的瞬时值
（✅ 0.055 ms/字符 @200）。它被当成了**常数**去线性外推 —— 而真实关系是
**二次**的，于是每字符成本随 L **线性增长**（@200 → 0.055，@2000 → 0.36，
@10000 → 1.75 ms/字符）。**「10k 字符约 0.7 s」这个数，恰好是 L=2000 的真实值**
（✅ 716 ms）—— 分母写错了，不是算错了。

**建议**：把这句改成引用一张表（或直接引用本文 §2.2.3 的表），并写明是 **O(L²)**。
按仓库自己的纪律，「评测原始数据应当指得回某一份结果文件」—— 这个 0.07 目前
**指不回任何一份结果文件**。

#### 2.2.3.2 最关键的一点：**代价没有天花板的那两个包，恰好是最贵的**

✅ **实测 7 个策略包的 `length_bound`**：

| 包 | `length_bound.max` | 流式代价有上界吗 |
|---|---:|---|
| `agent_content_v1` / `eu_ai_act_v1` / `multiparty_demo_v1` | 2000 | ✅ 有，最坏 ~0.7–2.1 s |
| `finance_redaction_v1` | 1500 | ✅ 有 |
| `semantic_demo_v1` | 64 | ✅ 有 |
| **`agent_tool_v1`** | **无 `length_bound`** | ❌ **没有**（但它是便宜的包，116 ms @2000）|
| **`pii_redaction_v1`** | **无 `length_bound`** | ❌ **没有，且它是 42× 最贵的那个** |

**这两条事实合起来是一个真问题**：`pii_redaction_v1` 是唯一**既没有长度上界、
又是全部 7 个包里最贵的**（4 pattern_block）。它的流式代价按 `c=2.4 µs/字符`：

- L=2000 → 4.9 s（✅ 实测）
- L=5000 → 29.9 s（✅ 实测）
- L=10000 → ⚠️ **推断 ~2 分钟**（由两个实测点外推，常数在 1.5% 内吻合）

**而 10k 字符的响应在这个策略下是「合法」的** —— 没有 `length_bound` 意味着
**没有任何东西说它太长**。也就是说：**一份合法输入可以让流式守卫花两分钟**，
而 `stop_on_violation` 只在**判定翻转**时才停，干净的长响应会一路判到底。

> **这不是「性能优化」话题，是一条可用性边界**，而且它的修法不是调参数：
> 要么给这两个包补 `length_bound`（作者侧的决定），要么把流式改成增量（§2.2.3 档 2）。
> **建议先补 `length_bound`** —— 它一行 JSON，且与 §2.2.3 档 1 改动默认值不同，
> **它不改变任何已有行为**（只让原本「没有上界」变回「有上界」）。

**建议**（按收益排序，可只做第一档）：

| 档 | 做法 | 收益 | 风险 |
|---|---|---|---|
| **0** | 给 `pii_redaction_v1` / `agent_tool_v1` 补一条 `length_bound`（§2.2.3.2）| ✅ 把「无天花板」变回「有天花板」：最坏从 ~2 分钟（推断）压到 ~4.9 s（实测）| **极低**：只影响这两个包，且**不改变任何已有通过/不通过的结论** |
| **1** | `stream_step_chars` 默认值从 1 改到一个有理由的值（如 8–16），并在文档里写明「这是**采样精度**的参数，改小=更早发现违规但要付平方代价」 | ✅ 直接 **L/step 倍**（step=16 → ~16×）| **低，但改默认值=改行为**：会推迟「第几个字符发现违规」。**必须先问清楚这个口径能不能动** |
| **2** | 把 `match_search` 改成**可增量**的：`cur` 状态集可以跨前缀携带（Pike VM 的 `cur` 只依赖 `text[:k]`），于是总代价 O(L) 而非 O(L²) | ⚠️ 推断 **~1000×** @2000 字符 | **中**：需要新增一个有状态的 API，语义必须逐字节等价（「匹配过就永远为真」是单调的，可直接对拍）|

> ⚠️ **档 1 会改变可观察行为**（早停发生在第几个字符）。§4 把稿 1 排在档 2 前面，
> 正是因为**它便宜但要征得同意**。若口径不能动，就只做档 2。

#### 2.2.4 副产品：`host_outcome` 把同一次 NFA 扫描做了两遍

`runtime/service.py:283` 的 `host_outcome`（`/v1/check` 与 `/v1/attest` 的公共路径）
**故意**跑了两个评估器，并用 `VerdictMismatch` 做交叉校验：

✅ **实测**（2000 字符）：

```
host_outcome() 总计     = 4,120.6 us
  ├ evaluate.check()          = 2,011.5 us   ← 走 Rule.params，且每次重编译 NFA
  └ canonical_violations()    = 2,012.2 us   ← 走编译后的约束，NFA 已预编译
```

**这不是缺陷，是有意的**（`service.py:311` 的注释把它说成「白拿」）。但它意味着
§2.2.2 的每一微秒**在服务路径上要被付两遍** —— 所以 §2.2.2 的收益在这一段是**翻倍**的。
**建议保留双评估器**：它买到的是一道真实的健全性检查，代价是 2× 的常数因子，
而常数因子正是 §2.2.2 要压的东西。

---

### 2.3 内存占用与优化

#### 2.3.1 先把量级摆正（否则会优化错东西）

| 对象 | 峰值内存 | 来源 |
|---|---:|---|
| Python 进程（含 `runtime.service`） | **~24–26 MB** | ✅ 实测 `/usr/bin/time -v` |
| **SP1 `core` 证明（200 字符 × 1 条规则，最小配置）** | **10,389 MiB** | ✅ `bench/results/proofs.md` |
| 同上（10000 字符 × 1 条） | 10,506 MiB | 同上 |
| 本机可用上限 | ~10,385–11.9 GiB | 同上 |

**结论：Python 层的内存优化，在这个项目里没有意义。** 两者差 **400 倍**。
任何「省掉一个中间列表」「不用 read_bytes」的建议，在这里都是噪声。

#### 2.3.2 真正的内存问题，与一条从未被验证过的假设

`bench/results/proofs.md` 的结论是：**~10.15 GiB 是 prover 的固定开销**，
「换机器也还在」，本机因此有一条「固定地板 + 两级台阶」的边界
（1 条规则 ≤10k 字符可证；3 条及以上出不来）。

**这个结论对，但它的主语被省略了**：10.15 GiB 是 **SP1 v6.7.0 默认配置下**的固定开销。
而 `pop-script` 对 prover **没有设任何配置**：

```rust
// circuits/script/src/main.rs:407
let req = client.prove(&pk, stdin);      // ← 没有 .core_opts(...)，全默认
```

✅ **实测（读 `~/.cargo/registry/.../sp1-{core-executor,prover}-6.7.0` 源码）**，
SP1 v6.7.0 暴露了**一批**内存相关的旋钮，本项目**一个都没设过**：

| 类别 | 环境变量（部分） | 默认值 |
|---|---|---|
| 分片 | `SHARD_SIZE` | `MAX_SHARD_SIZE = 1<<24` |
| 执行器 | `MEMORY_LIMIT`、`TRACE_CHUNK_SLOTS`、`MINIMAL_TRACE_CHUNK_THRESHOLD` | **`MEMORY_LIMIT = 24 GiB`**（本机只有 11.9 GiB）|
| worker 数 | `SP1_WORKER_NUM_CORE_WORKERS` / `_NUM_RECURSION_PROVER_WORKERS` / `_NUM_SETUP_WORKERS` / …（≥10 个）| 4 / 8 / 2 / … |
| worker 缓冲 | `SP1_WORKER_CORE_BUFFER_SIZE` / `_RECURSION_PROVER_BUFFER_SIZE` / `_GLOBAL_MEMORY_BUFFER_SIZE` / …（≥10 个）| 4 / 8 / … |

**建议：把「10.15 GiB 能不能降」变成一次有界的实验**，而不是继续当它是自然常数。

- **实验**：固定 `(200 字符, 1 条规则, core)`，只改环境变量，量 `峰值 RSS`：
  1. 全默认（基线，✅ 已知 10,389 MiB）
  2. `SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2`（8→2）
  3. `SP1_WORKER_NUM_CORE_WORKERS=1`（4→1）
  4. 2+3 同时
  5. `MEMORY_LIMIT=8GiB`（让执行器自己先失败，而不是被内核 OOM-kill）
- **成本**：5 次 × ~2 分钟 ≈ **10 分钟**，风险是被 OOM-kill（会如实记下来）。
- **判据**：只要**任何一个配置把地板压低 ≥5%** 且证明仍能验证通过（`--verify`），
  就写进 `docs/modules/05-zk-circuits.md` 与 `bench/results/proofs.md`；
  一个都没降，也**照样写进结果文件**（「试过 5 个配置，地板不动」本身就是结论）。

> ⚠️ **另一条诚实的话**：`SP1CoreOpts.drop_ldes`（注释说「提交阶段后丢弃已提交的
> codeword，查询阶段重新编码」—— 一个直接的内存/时间权衡开关）在 v6.7.0 里
> **只被定义、从未被读取**（✅ 实测：`grep drop_ldes` 全仓库只有结构体字段与
> `Default` 两处）。也就是说这条路在 6.7.0 上是**关着的**。
> 打开它需要给 SP1 打补丁 —— 本项目**已有**给 SP1 的依赖打补丁的先例
> （`circuits/patches/tempfile`），所以不是不可行，但**那是另一个量级的工程**，
> 建议只登记为「可能的下一步」，不排进本轮。

#### 2.3.3 另一条不需要在本机证明的路（登记，不推荐现在做）

`sp1-sdk 6.7.0` 带 `network` feature 与 `network/` 模块（✅ 实测源码存在）——
即 **NetworkProver**：出证交给远端，本机只发请求。这**完全不改证明语义**
（同一个 guest、同一个 vkey、同一份公开值），只换 client。代价是需要 API key 与联网，
且**证明不再本地可复现**。建议**只登记**：它改变的是「这台机器能不能出证」，
不改变项目本身的正确性，而本仓库的定位恰恰是「本机可复现」。

---

### 2.4 代码简洁与可读性

#### 2.4.1 「同一件事写了 N 遍」的完整清单（✅ 全部实测，可复现）

| 重复对象 | 份数 | 命令 | 已有漂移？ |
|---|---:|---|---|
| `POP_SCRIPT` / `POP_VERIFY` 路径赋值 | **34** | `grep -rn 'POP_SCRIPT *[:=]\|POP_VERIFY *[:=]\|DEFAULT_POP *=' --include='*.py' .` | 否，但 34 份里只有 3 份是 re-import |
| 策略加载器（JSON → `Policy`） | **16**（`policydsl`+`scripts` 11，`tests` 5） | `grep -rn 'def load_policy\|def _load_policy\|def load_pack' --include='*.py' .` | ✅ **是**（见下）|
| `sha256_file` | **6** | `grep -rn 'def sha256_file' --include='*.py' .` | 否（6 份逐字相同）|
| kind 分派链 | **4** + 2 张表 | `model._RULE_VALIDATORS` / `evaluate.check` / `compile.compile_constraints` / `commit.canonical_violations` / `multiparty.KIND_OWNER` | 否（已被 `test_rule_kinds.py` 钉住）|
| `find_repo`（标记搜索） | **2** | `policydsl/paths.py:38` vs `scripts/_bootstrap.py:44` | 否（`_bootstrap.py:37` 注释自认「改一处要改两处」）|
| `KIND_MAP` | **2** | `prove_policy.py:41`（**3 项**）vs `cross_validate.py:72`（**7 项**）| ✅ **是**（见下）|

#### 2.4.2 已经漂移的三处 —— 这是「重复有害」的实证，不是理论

**① 16 份策略加载器分成了 3 种行为**（✅ 逐份读过函数体）：

| 变体 | 代表 | `kind` 缺失时 | 规则名缺省 | `description` | `semantic` |
|---|---|---|---|---|---|
| A | `verify_cert.py:73`、`issue_cert.py:56`、`compose.py:470`、`session.py:477`、`multiparty.py:272`、`service.py:141`（**8 份**）| `r["kind"]` → **KeyError** | `f"r{i}"` | **丢弃** | **丢弃** |
| B | `__main__.py:20`、`prove_policy.py:44`、`prove_multiparty.py:49`（**3 份**）| `r.get("kind","")` / `r["kind"]`（B 内部也不一致）| `f"rule-{i}"` | 保留 | 保留 |
| C | `tests/` 5 份 | `r["kind"]` → KeyError | `r["name"]`（**无缺省**）| 丢弃 | 丢弃 |

**为什么这不是洁癖**：`Rule.name` 与 `Policy.semantic` **都进 `policy_hash`**
（`core/compile.py:40` 的 `STABLE_KEYS` 含 `constraints`，而 `constraints[i].name` 就是
`rule.name`）。同一个策略包，用变体 A 与变体 B 加载，只要有一条规则没写 `name`，
就会算出**两个不同的 `policy_hash`** —— 出证方与验证方各说各话。

✅ **当前是潜伏的，不是活跃的**：实测 7 个策略包，**所有规则都写了 `name`**，
且 `semantic` 全是 `"and"`。所以今天不会出错。但**没有任何东西阻止它出错**，
而 `service.py:144` 的注释已经把这个风险点名了。

**② `KIND_MAP` 已经漂移**（✅ 实测两处定义）：

```python
# prove_policy.py:41 —— 3 项
{"keyword": "keyword_block", "length": "length_bound", "pattern": "pattern_block"}

# cross_validate.py:72 —— 7 项
{... 再加 "format"/"tool_arg"/"budget"/"normalized_keyword" }
```

同一段 `golden()` 的函数体（`rules = sorted({(v.rule.name, KIND_MAP.get(v.evidence_kind, …)) ...})`）
在两处逐字重复，但**表不同**。对 `tool_arg_guard` / `budget_bound` 的违规
（✅ 7 个策略包里各有 2 处），两个脚本会给出**不同的 kind 字符串**。

**③ `parse_ints` 已经漂移 —— 这一处是「活 bug」，不是潜伏的**（✅ 实测复现）：

```python
# bench/bench_ablation.py:48-50  ← 坏的
def parse_ints(spec: str) -> list[int]:
    """``"100,200"`` → ``[100, 200]``。"""
    return [int(tok) for tok in spec.replace(";", " ").split() if tok]

# bench/bench_cycles.py:480-482  ← 好的，与 docstring 一致
return [int(x) for x in spec.replace(",", " ").split()]
```

前者把 `,` 换成了 `;`，**于是它自己的 docstring 举的例子都跑不过**：

```
$ python3 bench/bench_ablation.py --ns 100,200
error: argument --ns: invalid parse_ints value: '100,200'
$ python3 bench/bench_ablation.py --ns 100;200      # 只有分号能过，且在 shell 里要转义
```

**修法**：`bench_ablation.py` 直接从 `bench_cycles` import，或两者都挪到一处共用 ——
与 ①② 同属「收敛」而非「重构」。**收益是可量化的：它现在让一条文档化的调用方式直接报错。**

#### 2.4.3 建议：一次「收敛」，不是一次「重构」

| 建议 | 做法 | 为什么安全 |
|---|---|---|
| **① 收敛策略加载器 → 1 处** | 在 `core/model.py` 加 `Policy.from_dict(data, *, strict=...)`，16 处全部改调它 | **唯一的行为变化必须是「三变体归一」**，而这需要**逐包对拍**：用 16 份旧加载器与新的各跑一遍 7 个包，断言 `policy_hash` 与 `repr` 完全一致（变体 A 丢 `semantic` 的差异要用 `semantic="and"` 的默认值显式补上，并在测试里钉住）|
| **② 收敛 `POP_SCRIPT` → 1 处** | 已有唯一出处 `evidence/verifier.py:25`，其余 31 处 re-import 它（`session.py:65` 已经是这么做的，照抄即可）| 纯路径常量，无行为变化 |
| **③ 收敛 `sha256_file`** | 6 份 → `evidence/cert.py:133 sha256_hex` 的一个薄包装 | 6 份逐字相同，机械替换 |
| **④ 消掉 `KIND_MAP` 的第二份** | `prove_policy.py` 从 `cross_validate` import（或两者都从 `core` 的一个新常量取）| 两份**本来就应该相同**，取 7 项那份 |
| **⑤ kind 分派收敛为注册表** | `evaluate` / `compile` / `commit` 跟进 `model.py` 已有的分派表写法 | ⚠️ **风险最高的一项**：这三处都在判定热路径上，且 `commit` 只覆盖 7 类（`semantic_bound` 有意豁免）。**建议本轮不做** —— `test_rule_kinds.py` 已经把漂移变成 CI 会红的，边际收益低而回归风险高 |

#### 2.4.4 死代码（✅ 全部机械确认：全仓只出现 1 次，即定义本身）

```
model.py:227            Rule.to_dict()          ← 注意：Violation.to_dict() 用的是
                                                   self.rule.name/kind，不经它
trace.py:221/226/422    seal_digest / seal_for / chain_digest
nfa.py:459              format_spec
cert.py:371             public_signer
anchor.py:347           CastRpc.call_bool
mcp_adapter.py:224      MCPGuard.call_tool_sync
multiparty.py:378       MultipartyCertificate.proved_parts
```

外加 `compile.py:253-260` 的 else stub 分支（`test_rule_kinds.py:17` 自己注明是死代码）。

**建议**：**先别删**。逐条确认「是不是留给外部使用者/文档承诺的公开 API」——
`format_spec` 与 `public_signer` 看着像。**删除是不可逆的，而它们不占任何运行时成本。**
若要清，请一次一条、单独提交。

#### 2.4.5 门面 `__all__` 目前是**无人使用的接口**（✅ 实测）

`policydsl/__init__.py:35` 的 `__all__`（17 个符号）号称是「稳定门面」。
✅ 实测：全仓 `from policydsl import X` 的真实调用 **0 处** ——
唯一的提及是 `__init__.py:17` 自己的 docstring 与 `proofs/ezkl_evm.py:36` 的 doctest 注释。
所有内部代码都走 `from policydsl.core.model import ...` 这类子包绝对导入。

> ⚠️ 这与 `dev-plan.md` §5.6.3 硬约束 1 的表述（「包外 82 处依赖它」）**不一致**。
> 那个 82 大概是拆包普查时的**路径引用**计数，不是 `from policydsl import` 的调用数。
> 这条差异本身值得留档：**一个「硬约束」如果保护的是 0 个调用点，它的约束力是想象出来的。**

**建议**：二选一，别维持现状 ——
(a) **承认它是给第三方用的公开 API**，加 `tests/test_facade.py`（断言 17 个符号可导入、
且与子包里的对象是同一个 `id`）；
(b) **承认它是死的**，把 `__all__` 缩到真正被外部需要的最小集，或直接删掉。
**推荐 (a)**：成本一个测试文件，保住一个对外承诺；删掉的话，将来第三方接入时会踩空。

#### 2.4.6 超长函数（按优先级，✅ AST 实测）

| 行数 | 位置 | 建议 |
|---:|---|---|
| 432 | `scripts/verify/verify_cert.py:86 main` | 七段独立校验（签名/mode/vkey/challenge/trace+seal/delegated/rpc）线性铺开 → **拆成 7 个具名子函数**。**收益最高、风险最低**（纯脚本、有测试）|
| 286 | `scripts/verify/verify_session.py:65 main` | 同上 |
| 239 | `proofs/multiparty.py:681 verify_multiparty` | 与 919 行的文件一起看，**本轮不动** |
| 167 | `proofs/compose.py:291 verify_composite` | 同上 |
| 160 | `core/evaluate.py:100 check` | 见 §2.4.3 ⑤，**本轮不动** |

**边界**：`service.py`（1,172 行 / 64 个顶层符号）**建议本轮不动** ——
它是常驻服务的核心，改动面大而收益是「好读一点」。要动的话单独立项。

---

## 3. 建议项汇总（按「收益 ÷ 风险」排序）

| # | 建议 | 视角 | 证据 | 风险 | 建议档位 |
|---|---|---|---|---|---|
| **R17** | **给 `pii_redaction_v1` / `agent_tool_v1` 补 `length_bound`**，并把流式代价改成 O(L²) 事实 | 效率 | ✅ 42× 包间差 / ✅ 实测二次 | **极低** | **P0** |
| **R18** | 修 `bench_ablation.parse_ints`（`;` → `,`），或与 `bench_cycles` 合并 | 简洁 | ✅ **活的 bug** | **极低** | **P0**（**也是 R10 的前置**）|
| R1 | CI 补 `cross_validate --no-prove` / Rust 构建 / 链接普查 | 框架 | ✅ 0.048 s / 8.9 s | **极低** | **P0** |
| R2 | 新增跨层常量一致性测试 | 框架 | ✅ 常量已列全 | 低 | **P0** |
| R3 | `nfa.compile_pattern` + `_closure_table` 加缓存 | 效率 | ✅ 4% + 7 µs | **极低** | **P0** |
| R4 | `POP_SCRIPT` 34 → 1 | 简洁 | ✅ | **极低** | **P1** |
| R5 | `sha256_file` 6 → 1 | 简洁 | ✅ | **极低** | **P1** |
| R6 | `KIND_MAP` 消掉第二份 | 简洁 | ✅ 已漂移 | **极低** | **P1** |
| R7 | 策略加载器 16 → 1（`Policy.from_dict`）| 简洁 | ✅ 三种行为 | 中（要逐包对拍）| **P1** |
| R8 | 拆 `verify_cert.main` / `verify_session.main` | 简洁 | ✅ 432/286 行 | 低 | **P1** |
| R9 | 流式 `stream_step_chars` 默认值 + **增量匹配** | 效率 | ✅ 4.9 s @2000（最贵包）| **中**（改行为 / 改算法）| **P2** |
| R10 | `match_search` 转移表（常数因子）| 效率 | ⚠️ 推断 3–10× | 中 | **P2** |
| R11 | **SP1 prover 旋钮矩阵实验**（5 个配置）| 内存 | ✅ 旋钮存在、从未设过 | 中（会 OOM）| **P2** |
| R12 | 门面 `__all__` 加测试或删 | 简洁 | ✅ 0 调用 | 低 | **P2** |
| R13 | 清死代码 | 简洁 | ✅ 9 处 | 低但不可逆 | **P3** |
| R14 | 拆 `core → proofs` 倒置 | 框架 | ✅ 4 处 | 中高 | **P3** |
| R15 | 统一异常基类 / `verify_*` 返回风格 | 简洁 | ✅ 11 类异常 | 中 | **P3** |
| R16 | 拆 `service.py` | 简洁 | ✅ 1,172 行 | 中高 | **不建议本轮** |

---

## 4. 执行计划

### 4.1 通用规则（沿用本仓库既有工作方式）

1. **每个阶段独立提交**，闸门不过就迭代到过，**绝不带病提交**。
2. **闸门优先用机械手段**：「我读过了」不算，「脚本跑出来是 0」才算。
3. **凡是本机能跑的路径都真跑一遍**（`dev-plan.md` §5.6.7 的纪律）。
4. **失败就回滚整步**，不写「改一半还绿」的中间态。

### 4.2 各阶段

| 阶段 | 内容 | 闸门（**全部要真跑**）| 预计 |
|---|---|---|---|
| **P0** | R17 + R18 + R1 + R2 + R3 | ① `unittest discover` → 685+ 通过、skip 数不变；② `cross_validate.py --no-prove` → **19/19**；③ **故意把 `lib.rs:349` 的 `SEMANTIC_SYSTEM_EZKL` 改一个字符 → 新测试必须变红**，改回 → 绿；④ `check()` 中位耗时不升（✅ 应降 ~4%）；⑤ 写一个 7 包 × 16 加载器的**逐包对拍**脚本（为 P1 的 R7 预先建好基线）；⑥ **R17 的闸门：7 个包重跑 `check`/`compile`，通过的仍通过、不通过的仍不通过**（补 `length_bound` 会让两个包从「无上界」变「有上界」，须确认没有包的结论被改变）；⑦ **R18 的闸门：`python3 bench/bench_ablation.py --ns 100,200` 不再报错**| 半天 |
| **P1** | R4 + R5 + R6 + R7 + R8 | ① 每一条收敛**单独提交**，各自跑 `unittest` 全绿；② R7 的闸门是 **P0 建好的对拍脚本**：7 个包 × 16 份旧加载器 vs 新的 `Policy.from_dict`，**`policy_hash` 与 `repr` 逐字相同**；③ `demo_all.sh` fast 模式 → **8 条支路全 PASS**（搬家会踩坏 import，这是唯一能发现的闸门）；④ `verify_cert.py --proof …` 真验一份**已有**证明 → **13 项 PASS**（证明与脚本路径有关）| 1–1.5 天 |
| **P2** | R9 + R10 + R11 + R12 | **R9 前置：先确认 `stream_step_chars` 的默认值能不能改**（这是一个**可观察行为**，`docs/modules/06-frameworks.md` 里把它写成了「口径钉死」）；改已停字符数就要改文档并说明；R10 的闸门是**逐输入对拍**（新 `match_search` vs 旧：先在 7 个包的全部 pattern 上跑一遍穷举对拍，再跑 `cross_validate` 19/19 与 `test_rules_incircuit`）；**R11 的闸门 = 实验本身**：5 个配置的峰值 RSS 表，无论结论正负都写进 `bench/results/proofs.md`；R12 二者选一 | 1–2 天（R11 只要 10 分钟机器时间）|
| **P3** | R13 + R14 + R15 | 每条单独提交；R14 是**纯搬位置**，闸门 = `unittest` + `cross_validate` + demo fast + `5.6.7` 那条「import 坏了会在 tests 里报红」；R13 每条确认无外部使用者后再删 | 1–2 天 |
| **不做** | R16、§2.4.3 ⑤、§2.3.3 | 见 §5 | — |

### 4.3 提交切分（建议的 9 个提交）

```
1  fix(bench): parse_ints 接受逗号分隔（现在 docstring 的例子会报错）  ← R18
2  fix(policy): pii_redaction_v1 / agent_tool_v1 补 length_bound        ← R17
3  docs: 流式代价改为 O(L²) 的事实（06-frameworks + 适配器 docstring）  ← R17
4  ci: 补三条本机跑得动的检查（cross_validate / cargo build / 文档链接）
5  test(contract): 跨层字符串常量一致性测试（Python ↔ pop-types）
6  perf(nfa): compile_pattern 与闭包表加缓存（不改变匹配语义）
7  refactor: 收敛重复的路径常量 / sha256_file / KIND_MAP / 策略加载器
8  refactor(scripts): 拆 verify_cert / verify_session 的 main
9  perf(stream): 采样步长 + 增量匹配（若口径可动）
```

> 第 1–3 个提交是**三个最小的**（一处函数、两行 JSON、两处文案），
> 但它们是**唯一能立刻消掉一个 bug 和一条无界代价**的 —— 建议先做它们。

---

## 5. 明确不做的，以及为什么

| 不做 | 为什么 |
|---|---|
| **不改 `ConstraintSpec` 规范字节、`STABLE_KEYS`、任何域分隔符** | 这些是健全性支点。改一个字就是全链失效 |
| **不合并 `evaluate.check` 与 `commit.canonical_violations`** | 它们是**故意的双实现**（`service.py:311` 的 `VerdictMismatch` 靠它们）。合并=拆掉一道真实的健全性检查 |
| **不把 `cross_validate` 换成单测** | 它的价值恰恰是**跨语言**：跑真 `pop-script`。单测覆盖不了 Rust 侧 |
| **不优化 Python 内存** | 24 MB vs 10.4 GB，差 400 倍（§2.3.1）|
| **不做 lazy import 提速** | import 已经只要 0.03 s（§2.2.1）|
| **不动 `circuits/types/src/lib.rs` 的文件划分** | `types` 一改，三个 ELF、三个 vkey 都变，已入库的证明工件集体失效（`docs/modules/05-zk-circuits.md:439` 已记）。收益（好读）远小于代价 |
| **不在本机强行做 groth16 / 链上验证** | 需要 ≥64 GB 机器（`dev-plan.md` §5.6.11 已记）|
| **不引入 pytest / 任何新依赖** | 项目是 stdlib unittest，CI 靠零依赖跑起来 |

---

## 6. 未验证的假设（**不要当结论读**）

| # | 假设 | 怎么验 |
|---|---|---|
| A1 | `match_search` 改转移表能快 3–10× | 属于 §2.2.2(c)，**没量过**。先写一个 30 行的原型再决定要不要改生产代码 |
| A2 | 增量匹配能把流式从 O(L²) 降到 O(L)，收益 ~1000× | 是**渐近分析**，实际常数没量过。且「匹配后再收到的字符也得处理」的边界要单独验 |
| A3 | SP1 的 worker 数/缓冲旋钮能压低 10.15 GiB 地板 | **完全没试过**。这正是 R11 要做的事。**可能一试就发现一个都降不下来** |
| A4 | 收敛 16 份加载器不会改变任何现有结论 | 需要 P0 建的对拍脚本跑出来才算。**「读起来一样」不算** |
| A5 | 34 处 `POP_SCRIPT` 收敛后不会有路径差异 | 其中 `cross_validate.py:60` 支持 `$POP_SCRIPT` 覆盖，是**唯一可注入的**。收敛时必须保留这个能力 |
| A6 | 拆 `verify_cert.main` 不影响输出 | 它有 13 项 PASS 的实测基线，拆完必须逐项复现 |
| A7 | 给 `pii_redaction_v1` 补 `length_bound` **不改变任何现有结论** | ⚠️ **尚未验证**。7 个包今天都没有超长响应，所以「看起来不会变」；但 P0 闸门 ⑥ 必须真跑（尤其是 `tests/` 里有没有用超长响应喂这两个包的用例）|
| A8 | `pii_redaction_v1` 在 10000 字符上的流式代价 ≈ 2 分钟 | **外推**：由 L=2000（4855 ms）与 L=5000（29874 ms）两个实测点拟合 c≈2.4 µs/字符后外推。**没有直接量过 10000**（量一次约 2 分钟机器时间，建议在 R17 时顺手量掉）|

---

## 7. 一页纸总结

**该做的**（前三条都是一行到几行的改动，先做）：修 `parse_ints` → 补两个
`length_bound` + 改流式代价的文档 → CI 补三条 → 常量一致性测试 → NFA 两级缓存 →
收敛四处重复（路径 / 哈希 / KIND_MAP / 加载器）→ 拆两个 `main` →
流式 O(L²) → SP1 旋钮实验。

**不该做的**：碰跨层契约、合并双评估器、优化 Python 内存、动 `lib.rs` 的文件划分、
给 `check()` 的规则循环加短路（§2.2.2 (d)）。

**最该记住的两条**：

1. **这个仓库最大的风险不是「代码写得不够漂亮」，而是同一件事在多处各写一份。**
   本次普查里**三处已经漂移**：`KIND_MAP`（3 vs 7 项）、策略加载器（3 种行为）、
   `parse_ints`（`;` vs `,`，**已经是活的 bug**）。
   前两处今天都不出错，**因为 7 个策略包恰好都写全了字段** —— 而「恰好」不是契约。

2. **「代价有界」这件事要么被验证，要么不存在。**
   `pii_redaction_v1` 没有 `length_bound`，而它是全部包里最贵的（✅ 2000 字符 4.9 s、
   5000 字符 29.9 s）—— **没有上界意味着这两条数字之上没有天花板**。
   同一份仓库里，两个文档（`06-frameworks.md:133` 与适配器 docstring）把这份代价
   写成了「10k 字符约 0.7 s」，**比实测低估约 25 倍**（✅ 实测 17.5 s）——
   因为它把一个 O(L²) 的瞬时值当成常数做了线性外推。
