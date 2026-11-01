# Core blocker：V1 差分模糊两条 NFA 实现 bug 的修复记录

> **状态**：2026-11-01，Core owner 修复记录；分支 `bhv/core-nfa`，
> 基线 `c78ca67`。关联 [`V1.md`](V1.md) 的 **G-1** / **V1-2**，
> 以及 [`docs/proofs/theorem-d-g.md`](../proofs/theorem-d-g.md) §12.3 / §19。
>
> **边界**：本文件记录**已落地的修复**与解析器契约；`V1.md` 与定理文档由各自
> owner 维护，其中「已知缺口」的表述需要他们同步更新（见文末「残留」）。

## 一句话

两条 bug 都已修复，并补了 Python / Rust 两侧测试：

| 编号 | 修复选择 | 语义变化 |
|---|---|---|
| G-1 空字符类 `[^\d\D]` | **解析期 fail-closed**：抛 `RegexSyntaxError` | 从「编译成 ε、匹配空串」变为「编译期拒绝」 |
| V1-2 零次重复 `a{0}` | `_chain([])` 返回显式 ε 片段 + 修方法名笔误 | 从 `AttributeError` 崩溃变为「等价于 ε」 |

修复过程中还发现并修掉了一条 **Rust 侧真实缺口**：朴素匹配器
`nfa_match_naive` 对「空文本 + 可空模式」漏判 ε（见 §3）。这是 guest 代码
变更，因此 **vkey 变化**。

---

## 1. G-1：空字符类改为解析期拒绝（fail-closed）

**复现（修复前）**：

```python
from policydsl.core import nfa
spec = nfa.compile_pattern(r"[^\d\D]")
nfa.match_search(spec, "")             # True  ← bug：空语言匹配了空串
```

**根因**：`_parse_char_class` 取反后得到空区间列表，构造 `Lit([])`；而
`_Builder.build` 把 `Lit([])` 当成 ε 直连。`_parse_concat` 的空连接也用
`Lit([])` 表示 ε —— 同一个表示承担了「空语言 ∅」与「空串 ε」两种语义。

**修复**（`policydsl/core/nfa.py`）：不引入新的 `Empty` AST 节点（避免改动
spec / vkey 结构），而是在解析器遇到**空区间字符类**时直接抛
`RegexSyntaxError`：

```python
ranges = _merge(parts)
if negate:
    ranges = _complement(ranges)
if not ranges:
    raise RegexSyntaxError(
        "empty character class at position ...: its language is "
        "the empty set, which is outside the supported subset")
```

**解析器契约（受支持子集）**：本仓只接受「语言非空」的字符类。空字符类
（`[^\d\D]`、`[^\w\W]`、`[^\s\S]`，以及 `[]` / `[^]` 这类边界写法）一律在
**编译期**拒绝，并经由 `core/compile.py` 包装成 `PolicyError`。这是**有意的
子集边界**，不是 bug：Python `re` 接受这些模式（语言为 ∅），本仓拒绝它们。
`Lit([])` 从此只表示空连接 ε。

**影响**：

* 任何包含空字符类的策略现在在 `compile_policy` 阶段失败（可读的
  `PolicyError`），而不是静默匹配空串；
* spec 结构与 vkey 的 NFA 契约**没有**改变（没有新增 AST/serde 字段）；
* 定理 G(a)(b) 不再需要假设 A-G0 之外的特别处理 —— 空类被排除在输入之外。

---

## 2. V1-2：零次重复等价于 ε

**复现（修复前）**：

```python
nfa.compile_pattern(r"a{0}")
# AttributeError: '_Builder' object has no attribute '_build'
```

**根因**：`_Builder._build_repeat` 在 `min == max == 0` 时得到空片段列表，
`_chain([])` 调用 `self._build(Lit([]))`，但类里只有 `build`。

**修复**（`policydsl/core/nfa.py`）：

```python
if not frags:
    s, t = self.new_state(), self.new_state()
    self.states[s].eps.append(t)
    return s, t
```

同时删除了 `_build` 笔误。`a{0}` 与 `a{0,0}` 现在都编译成
`start --ε--> accept`，匹配空串。

**注意 search 语义**：`match_search` 对应 `re.search`，零宽匹配会让
`a{0}` 对任意文本（包括 `"a"`）返回真。测试里「不匹配 `a`」的含义是
**不消耗字符**：`anchored_full_match(spec, "a", 0, 1) == False`、
`find_spans(spec, "a") == []`，与 `re.fullmatch("a{0}", "a") is None` 一致。

---

## 3. Rust 同步：结构不同，语义对齐

`circuits/types/src/lib.rs` 在基线 `c78ca67` 上**没有**正则解析器或 Thompson
构造器：正则解析与 NFA 构造只在 `policydsl/core/nfa.py`，Rust 只解释编译后
的 `NfaSpec`。因此：

* **G-1**：Python 解析器拒绝空字符类后，坏 spec 不可能再被生成并送进电路。
  Rust 解释器对「空区间边」（`ranges: []`）本来就返回不匹配（即语言 ∅，
  不是 ε）。两侧语义一致，Rust 无需改动解释逻辑。
* **V1-2**：零次重复的 ε spec（`start --ε--> accept`）Rust 的 Pike 与朴素
  匹配器都必须接受。检查时发现 **`nfa_match_naive` 对空文本漏判 ε**：

  ```rust
  // 修复前：空文本时 0..chars.len() 一次都不跑，直接返回 false
  for start in 0..chars.len() { ... }
  ```

  这会让 `a{0}`（以及任何可空模式）在 `mode=naive` 下对 `""` 判为不通过，
  与 Pike、Python 参考实现都不一致。修复：在循环前先判起始 ε-闭包是否含
  接受状态（与 Python `match_search_naive` 逐语义对齐）：

  ```rust
  let start_closure = eps_closure(spec, core::slice::from_ref(&spec.start));
  if reached_accept(spec, &start_closure) { return true; }
  ```

  **这是一处 guest 代码变更 ⇒ vkey 变化**。它只影响 `match_mode=naive`
  （消融旋钮）在「空文本 + 可空模式」上的判定；默认 Pike 路径不受影响。
  该缺口在修复前被两件事遮住了：Python 侧 `a{0}` 直接崩溃，且现有
  `TestRustNaivePath` 只拿邮箱模式试空串。

Rust 侧新增了 3 条 `#[cfg(test)]` 回归测试（文件末尾，**不进入 guest ELF**）：
零次重复 spec 接受 ε、空区间边是 ∅、Pike/naive 在两种 spec 上一致。

---

## 4. 测试与回归

```bash
python3 -m unittest tests.test_fuzz_rules tests.test_nfa tests.test_ablation \
    tests.test_rules_incircuit tests.test_cross_validate \
    tests.test_acceptance_baseline -v
cargo test -p pop-types --offline          # 3 条 Rust NFA 契约测试
```

结果（构建 `pop-script` 后重跑，**0 skipped**）：

* `tests.test_fuzz_rules`：差分扫描仍是 **0 mismatch**（Pike vs `re`、
  Pike vs naive）；跨层对拍 **172 对样本，Python vs Rust = 0 mismatch，
  Rust vs `re` = 0 mismatch**。原 G-1 的 `expectedFailure` 与 V1-2 的
  `assertRaises(AttributeError)` 已改为「空类抛 `RegexSyntaxError`」、
  「零次重复 = ε」的正向断言。
* `tests.test_nfa`：新增空字符类拒绝、零次重复 ε 的用例。
* `tests.test_acceptance_baseline` / `test_loader_parity`：现有 **7 个策略包
  的 `policy_hash` 全部不变**（这些包没有使用空字符类或 `{0}`）。
* `cargo test -p pop-types --offline`：3 条 Rust NFA 契约测试全绿。
* 回归命令共 **55 tests OK**（无 skip）。

---

## 5. 二进制与 vkey

本地构建（`cargo build --release -p pop-script --offline`，
`target` 为本 worktree 私有，2m30s，未同步云机）：

| 工件 | sha256 |
|---|---|
| `circuits/target/release/pop-script`（90,950,968 B） | `7f99fdb11a4a859c45598c384db3b98dd50426210adbc14d6b576c4d15dda49f` |
| `pop-program` guest ELF（新） | `365ad87c435457dc7b8451db62f75cc87b5caebf4f789e9c7b2e0c9f4c908972` |
| `pop-program` guest ELF（旧，main checkout 2026-10-20） | `840d4eeca6560597dccf287acbe5d58007d19b76e3d6c8e0dd94f6012e2d666b` |

由本轮 ELF 经 `ProverClient::setup` 推导的 vkey（`bytes32`）：

| 域 | 新 vkey | 旧 vkey（对照） |
|---|---|---|
| policy（`pop-program`） | `0x003eb14de80339bddef2b9207ef27469088267888bb9bebb9836b4ee701fd7be` | `0x0091b406dcaf1ea6605439d4f1379835f0824dfb74f909a3d9930fbfbc9c434b` |
| infer（`pop-infer`） | `0x0068573ee6818fa5069f339230c7d900cf548f58ea5a3dac31bf14f370003d32` | — |
| session（`pop-session`） | `0x00a633b063f8c3cdae4f3e5fa7bbccb39c1237259442ab9963164ffbd46891c7` | — |

**X1 的云机结果仍属旧二进制。** 本轮没有同步二进制到云机；任何使用本轮
`nfa_match_naive` 修复的结果表都必须标注其测量的 binary sha256（上表第一行），
不能与旧 vkey 的 groth16 结果混在同一张表里比较。

---

## 6. 残留 / 需要其它 owner 同步的地方

* [`V1.md`](V1.md) 仍把 G-1 / V1-2 描述为「已知缺口、未修」；
  [`docs/proofs/theorem-d-g.md`](../proofs/theorem-d-g.md) §12.3 / §19 仍把
  G-1 列为未修缺口。两条都以本文为准更新（Core 不越界改它们）。
* `bench/results/fuzz.{json,md}` 是 V1 的产物；修复后需由 bench owner 重新
  生成（测试会写出新内容，但本轮按 Core 的文件边界不提交生成物）。
* 空字符类现在是**编译期拒绝**而非「匹配 ∅」。若有下游文档/工具假设
  `[^\d\D]` 可编译，需要按新契约调整。
