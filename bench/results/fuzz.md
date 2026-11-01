# 差分模糊测试：Pike VM vs Python `re`（P2-03）

固定种子 `20261101`；120 个模式 × 386 条文本 = **46,320** 次比较。

| 比较 | mismatch 数 | 说明 |
|---|---:|---|
| Pike (`match_search`) vs Python `re.search` | **0** | 受支持子集；期望 0 |
| Pike vs 朴素 (`match_search_naive`) | **0** | 消融实验的可比性前提；期望 0 |
| 空字符类（原 G-1） | **5** | 5 个模式全部被解析器拒绝（fail-closed） |
| 零次重复 `a{0}`（原 V1-2） | **0** | 4 个模式均编译为 ε |

## 空字符类契约（原 G-1，已修复：fail-closed）

`[^\d\D]` 等取反字符类在求补后区间为空，其语言按定义是 **空集 ∅**。修复选择是让**解析器直接拒绝**空字符类，而不是引入新的 AST 节点：

```
nfa.compile_pattern(r"[^\d\D]")   # RegexSyntaxError
re.compile(r"[^\d\D]")             # 接受（语言 = ∅，永不匹配）
```

这是**有意的子集边界**：本仓把空字符类归入「受支持子集」之外，由 [`docs/blockers/Core.md`](../../docs/blockers/Core.md) 记录解析器契约。Rust 侧不解析正则、只解释编译后的 spec，因此该模式在编译期就被拦下，不会到达电路。

### 边界对照

| 模式 | Python `re.compile` | NFA `compile_pattern` | 结论 |
|---|---|---|---|
| `[]` | 拒绝 | 拒绝 | 两端一致（都 fail closed） |
| `[^]` | 拒绝 | 拒绝 | 两端一致（都 fail closed） |

## 零次重复 `a{0}`（原 V1-2，已修复）

| 模式 | NFA `compile_pattern` | 匹配空串 | 消耗 `a` |
|---|---|---|---|
| `a{0}` | compiled as epsilon (matches empty string) | True | False |
| `a{0,0}` | compiled as epsilon (matches empty string) | True | False |
| `(ab){0}` | compiled as epsilon (matches empty string) | True | False |
| `(a|b){0,0}` | compiled as epsilon (matches empty string) | True | False |

`_Builder._chain([])`（零次重复展开后为空）现在返回一个显式的 ε 片段（`s --ε--> t`），并修掉了原先指向不存在方法 `_build` 的笔误。注意 `match_search` 是 **search** 语义：零宽匹配会让 `a{0}` 在 `"a"` 上也返回真，但它**不消耗**任何字符（`anchored_full_match` 为假）。


## Python ↔ Rust 对拍

驱动：`/home/dong/Proof-of-Policy/03_代码仓库/zk-policy/circuits/target/release/pop-script`；样本 172 对。

| 比较 | mismatch 数 |
|---|---:|
| Python Pike vs Rust `--check` | **0** |
| Rust vs Python `re` | **0** |

修复后两种实现与 Python `re` 均一致（空字符类在编译期被拒绝，零次重复编译为 ε）。

## 复现

```bash
python3 -m unittest tests.test_fuzz_rules -v
# 有构建产物时加 Rust 对拍：
POP_SCRIPT=/path/to/pop-script python3 -m unittest tests.test_fuzz_rules -v
```

