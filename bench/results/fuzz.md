# 差分模糊测试：Pike VM vs Python `re`（P2-03）

固定种子 `20261101`；120 个模式 × 386 条文本 = **46,320** 次比较。

| 比较 | mismatch 数 | 说明 |
|---|---:|---|
| Pike (`match_search`) vs Python `re.search` | **0** | 受支持子集；期望 0 |
| Pike vs 朴素 (`match_search_naive`) | **0** | 消融实验的可比性前提；期望 0 |
| G-1 空字符类（单独统计） | **30** | **已知 NFA 语义 bug**，见下 |

## G-1：空字符类的语义缺口（已知，不是测试问题）

`[^\d\D]` 等取反字符类在求补后区间为空。Python 把它当作**空语言**（`re.search` 永不匹配）；当前 NFA 把空区间编译成 `Lit([])` → ε 边，于是**匹配空串**。复现：

```
pattern = r"[^\d\D]"
nfa.match_search(spec, "")   == True    # 代码：ε 边
re.search(pattern, "")        == None    # Python：空语言
```

本文件用 `@unittest.expectedFailure` 显式标注这条相等断言；30 条 G-1 样例全部记录在 `fuzz.json` 的 `g1.entries` 里（`known_gap: true`）。

**这是 NFA 语义 bug，不是测试问题**：空字符类的语言应为 ∅，而不是 `{ε}`。修复需要把 AST 的「空语言」与「空连接（ε）」分开（T3 §12.3、[`docs/blockers/V1.md`](../../docs/blockers/V1.md)）。在修复前，定理 G(a)(b) 只在假设 A-G0（字符类区间非空）下成立。

### 边界对照

| 模式 | Python `re.compile` | NFA `compile_pattern` | 结论 |
|---|---|---|---|
| `[]` | 拒绝 | 拒绝 | 两端一致（都 fail closed） |
| `[^]` | 拒绝 | 拒绝 | 两端一致（都 fail closed） |

## 另一条已知实现 bug：`a{0}`（V1-2）

| 模式 | Python `re` | NFA `compile_pattern` |
|---|---|---|
| `a{0}` | 接受，匹配空串 | `AttributeError: '_Builder' object has no attribute '_build'` |

`_Builder._chain([])`（零次重复展开后为空）调用了 `self._build`，而类里只有 `build`。这是**实现 bug**，由 [`docs/blockers/V1.md`](../../docs/blockers/V1.md) 的 V1-2 记录；本测试不修 core，只用 `assertRaises(AttributeError)` 把它钉成已知行为。


## Python ↔ Rust 对拍

驱动：`/tmp/pop-script-v1`；样本 172 对。

| 比较 | mismatch 数 |
|---|---:|
| Python Pike vs Rust `--check` | **0** |
| Rust vs Python `re` | **12** |

两种实现判据一致；Rust vs `re` 的非零项来自 **G-1**（Python 与 Rust 共有的空字符类缺口），不是两种实现之间的分歧。

## 复现

```bash
python3 -m unittest tests.test_fuzz_rules -v
# 有构建产物时加 Rust 对拍：
POP_SCRIPT=/path/to/pop-script python3 -m unittest tests.test_fuzz_rules -v
```

