# 01 · 策略 DSL 与编译

> 覆盖 `policydsl/model.py`、`compile.py`、`evaluate.py`、`serialize.py`、`nfa.py`、`pii.py`、
> `__init__.py`、`__main__.py`。
> 这一板块回答：**策略长什么样 → 编译成什么 → 谁怎么判定它**。

---

## 1. 职责

| 文件 | 一句话职责 | 纯标准库 |
|---|---|---|
| `model.py` | 领域模型与**编译期校验**（`PolicyError` 快速失败） | ✅ |
| `compile.py` | `Policy` → `ConstraintSpec`（**唯一跨层契约** + `sha256` 绑定哈希） | ✅ |
| `nfa.py` | 正则子集 → **可序列化 NFA**（Thompson 构造）+ Pike VM + 匹配区间计算 | ✅ |
| `evaluate.py` | **参考判定器（golden）**：自由文本或结构化轨迹 → `CheckResult` | ✅ |
| `serialize.py` | `ConstraintSpec` → serde **外部标签枚举** JSON（喂给 Rust） | ✅ |
| `pii.py` | 规范 PII 正则（NFA 子集内）+ IBAN MOD-97 校验位 | ✅ |
| `__init__.py` | re-export 常用符号（`Policy` / `compile_policy` / `check` / …） | ✅ |
| `__main__.py` | CLI：`compile` / `check [--emit-proof-request]` | ✅ |

**不负责**：证明生成（`05`）、证书与锚定（`03`/`04`）。本板块只产「契约」与「参考结论」。

---

## 2. 六种规则类型

规则是 `Rule(kind, name, params)`。`kind` 决定语义与参数 schema，`name` 是**证书与违规记录里的稳定标识**。

| kind | params | 判定对象 | 电路内？ | 语义 |
|---|---|---|---|---|
| `keyword_block` | `keywords: [str]`（非空） | `response` | ✅ | 响应**不得包含**任一关键词（ASCII 不区分大小写） |
| `length_bound` | `min:int, max:int`，`0 ≤ min ≤ max` | `response` | ✅ | 码点长度须落在 `[min, max]` |
| `pattern_block` | `patterns: [str]`（非空），可选 `match_mode: pike\|naive` | `response` | ✅ | 响应**不得匹配**任一正则（子串存在性） |
| `format_check` | `format: json\|int\|float` | `response` | ✅ | 响应整体须能按规范子集解析 |
| `tool_arg_guard` | `forbidden_fields: [str]`（非空），可选 `tools: [str]` | `tool_calls` | ✅ | 工具参数不得含被禁字段（`tools` 非空时限定范围） |
| `budget_bound` | `budget:int ≥ 0`，`unit: calls\|tokens` | `tool_calls` / `token_count` | ✅ | 累计量不得超过 `budget` |

> 六类**全部入电路**（P7-b 之后）。两处边界见 `../security-model.md` §5：
> ① `budget_bound/tokens` 依赖**证明者声明**的 `token_count`（电路内不做分词）；
> ② agent 工具路径证书的 `zk:true` 表示「规则可证」，是否**附了证明**看 `binding.vkey_hash`（`unproven` = 仅链下判定）。

`params` 校验在 `Rule.validate()` 中**逐类型**进行，未知 kind 直接报错（防止拼写错误退化成空操作）：

```python
Rule("keyword_block", "no_bad", {"keywords": ["exploit"]}).validate()   # OK
Rule("keyword_blok", "no_bad", {"keywords": ["exploit"]}).validate()    # PolicyError: unknown kind
```

---

## 3. 关键数据结构

### 3.1 领域模型（`model.py`）

```python
@dataclass
class Rule:        kind: str; name: str; params: dict          # + validate() / to_dict()
@dataclass
class Policy:      id: str; version: str; description: str = ""
                   rules: list[Rule]; semantic: str = "and"    # + validate()
@dataclass
class Violation:   rule: Rule; evidence_kind: str; evidence: Any
@dataclass
class CheckResult: passed: bool; violations: list[Violation]; notes: list[str]
@dataclass
class ToolCall:    name: str; args: dict
@dataclass
class Transcript:  response: str|None; tool_calls: list[ToolCall]; token_count: int|None
```

`Violation.evidence_kind` 与 `evidence` 的对应（**跨层证据字符串的参考定义**）：

| kind | evidence_kind | evidence |
|---|---|---|
| `keyword_block` | `"keyword"` | 命中关键词列表 |
| `length_bound` | `"length"` | `{"len", "min", "max"}` |
| `pattern_block` | `"pattern"` | 命中的模式串 |
| `format_check` | `"format"` | `{"format", "len"}` |
| `tool_arg_guard` | `"tool_arg"` | `{"tool", "field"}` |
| `budget_bound` | `"budget"` | `{"unit", "total", "budget"}` |

> ⚠️ 私有模式的证据承诺用的是**另一种更简单的规范形式**（如 `"len=42"`），
> 见 `commit.canonical_violations` 与 `../modules/02-privacy-commitment.md` §3。

### 3.2 契约 `ConstraintSpec`（`compile.py`）

```jsonc
{
  "spec_version": "v1",
  "policy_id": "eu-ai-act-v1",
  "policy_version": "0.1.0",
  "semantic": "and",
  "constraints": [
    {"kind": "keyword_block", "name": "banned_high_risk_topics",
     "keywords": ["child abuse", "doxxing", "exploit", ...]},        // 排序去重 + 小写化
    {"kind": "length_bound", "name": "bounded_length", "min": 1, "max": 2000},
    {"kind": "pattern_block", "name": "no_email",
     "patterns": ["[\\w.+-]+@[\\w-]+\\.[\\w.]+"],
     "nfa": {"compiled": [ {"start":0, "accept":[9], "states":[...]} ]}},
    // match_mode=="naive" 才出现 "mode": "naive"；缺省 pike
    {"kind": "tool_arg_guard", "name": "no_secret_args",
     "forbidden_fields": ["api_key", "password", "token"], "tools": ["search_kb"]},
    {"kind": "budget_bound", "name": "call_budget", "budget": 2, "unit": "calls"}
  ],
  "sha256": "<64hex>"
}
```

**`sha256` 的计算范围**是所有**稳定字段**（`spec_version` / `policy_id` / `policy_version` /
`semantic` / `constraints`），不含 `sha256` 自身：

```python
_canonical_hash(stable) = sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")))
```

这条「规范化 JSON + 键排序」的规则是**整个溯源链的地基**：验证方只要拿到策略包就能重算哈希，
进而确认证书绑定的正是这份策略（`verify_cert.py` 的 `policy_hash` 卡）。

编译期做的**归一化**（都是为了消除「语义相同、字节不同」的漂移）：

| 字段 | 处理 |
|---|---|
| `keywords` | `sorted({w.lower()})` |
| `forbidden_fields` / `tools` | `sorted(set(...))` |
| `min` / `max` / `budget` | `int(...)`（容忍 JSON 里写成字符串的数字） |
| `patterns` | 逐条 `nfa.compile_pattern`；**不支持的语法在编译期就 `PolicyError`** |
| `match_mode` | 仅显式 `naive` 才写入 |

### 3.3 序列化 NFA（`nfa.py`）

```
{"start": int, "accept": [int, ...],
 "states": [{"eps": [int, ...],
             "edges": [{"to": int, "ranges": [[lo, hi], ...]}, ...]}, ...]}
```

- 区间为**闭区间码点**，已排序 + 合并 —— Rust 侧 `in_ranges` 依赖「按 lo 升序」做线性扫描。
- 语义为**无锚点存在性搜索**，对齐 `re.search`（不是 `re.fullmatch`）。

支持子集：字面量、`.`、字符类 `[...]`（含区间、`\w\d\s`、取反）、转义、分组与 `|`、量词
`* + ? {m} {m,} {m,n}`。
**明确不支持**（抛 `RegexSyntaxError`）：锚点 `^ $`、反向引用、环视、懒惰/贪婪区分、`\b`。

ASCII 语义：`\w` = `[A-Za-z0-9_]`、`\d` = `[0-9]`、`\s` = `[ \t\n\r\f\v]`。
在 ASCII 输入上与 Python `re` 一致，非 ASCII 字母上不一致 —— 这是**文档化的差异**。

---

## 4. 函数级 API

### `compile.py`

| 函数 | 签名 | 说明 |
|---|---|---|
| `compile_policy` | `(policy: Policy) -> dict` | 校验 → 逐规则映射 → 计算 `sha256`。抛 `PolicyError` |
| `_canonical_hash` | `(obj: dict) -> str` | 规范化 JSON 的 SHA-256（内部） |
| `SPEC_VERSION` | `"v1"` | 契约版本，参与哈希 |

### `evaluate.py`

| 函数 | 签名 | 说明 |
|---|---|---|
| `check` | `(policy, target: str \| Transcript) -> CheckResult` | **golden 判定**；语义固定为 `and` |
| `_parse_format` | `(fmt, text) -> bool` | 规范子集解析器，**必须与 `pop-types` 的 `parse_*_ok` 一致** |
| `_to_transcript` | `(target) -> Transcript` | `str` → 仅含 `response` 的 `Transcript` |

规范子集的精确边界（两侧都靠这几行保持一致）：

| format | 规则 | 对应 Rust |
|---|---|---|
| `int` | `[+-]?\d{1,19}`（19 位上限避免 u64/i64 溢出差异） | `parse_int_ok` |
| `float` | 非空、无 `_`、不含 `nan`/`inf`（大小写不敏感），且 `float()` 可解析 | `parse_float_ok` |
| `json` | `json.loads` 且 `parse_constant=_reject_json_constant`（拒绝 `NaN`/`Infinity`） | `parse_json_ok`（serde_json） |

短路行为：`pattern_block` 命中**第一条**模式即记录并跳出（不收集全部命中）。

### `nfa.py`

| 函数 | 说明 |
|---|---|
| `compile_pattern(pattern) -> dict` | **唯一的正则编译器**：AST → Thompson NFA → 可序列化 spec |
| `parse(pattern) -> Node` | 解析为 AST（`Lit` / `Concat` / `Alt` / `Repeat`），尾随字符报错 |
| `match_search(spec, text) -> bool` | Pike VM：**单趟**扫描并追踪全部状态；每个位置允许重新从 `start` 出发 |
| `match_search_naive(spec, text) -> bool` | 消融对照：每个起点重跑锚定匹配，语义相同但 **O(n²)** |
| `find_spans(spec, text) -> [(lo,hi)]` | 每个起点的最长匹配区间，排序 + 合并（脱敏掩码的来源） |
| `mask_indices(specs, text) -> [int]` | 被任意 spec 覆盖的字符下标（排序） |
| `anchored_full_match(spec, text, start, end) -> bool` | `text[start:end]` 是否**完整**匹配且**至少消耗 1 字符**（脱敏见证校验） |
| `merge_spans(spans) -> spans` | 排序 + 合并重叠/相邻 |
| `format_spec(spec) -> str` | 调试用可读输出 |
| `RegexSyntaxError` | 使用子集外语法时抛出（`compile_policy` 会转成 `PolicyError`） |

`match_search` 与 `match_search_naive` **必须语义等价**，这是消融实验有意义的前提
（`tests/test_ablation.py` 保证）。

### `serialize.py`

| 函数 | 说明 |
|---|---|
| `spec_canonical_text(spec) -> str` | 策略的**规范 JSON 文本**（再导出 `compile.canonical_spec_text`）——写进 vectors 条目的 `spec_canonical` 字段 |
| `vector_entry(spec, response, **extra) -> dict` | 构造一个 vectors 条目，把「契约文本从哪来」收敛到一处 |
| `build_vectors(entries) -> dict` | 包装成 `{"vectors": [...]}` |

> **契约只有一份，且是原始字节。** 电路侧收到的不是「转换后的枚举」，而是
> `canonical_spec_text` 产出的**同一段字节**：guest 从它同时派生 `policy_hash`
> 与解析出的约束。因此这里**不存在**「Python 形状 → Rust 形状」的映射，
> 也就没有映射带来的可分离性（P0-1 之前 `spec_to_rust_constraints` 的
> 外部标签映射正是漏洞所在，已经删除）。
>
> **fail-closed 依然成立，只是换了机制**：未知 kind 被**原样**写进规范字节，
> guest 的 serde 解析失败即 panic —— 产不出证明，而不是静默跳过（全局不变量 I4）。

### `pii.py`

| 成员 | 说明 |
|---|---|
| `PII_PATTERNS` | 规范来源：`email` / `phone` / `secret_key` / `bearer_token`，全部落在 NFA 子集内 |
| `_NFA_CACHE` | **导入时**即编译全部模式（不兼容的正则立刻暴露） |
| `compiled_pattern(name)` / `contains(name, text)` / `pattern_names()` | 查询接口 |
| `iban_mod97(iban) -> int` / `is_valid_iban(iban) -> bool` | 校验位验证器（正则只能刻画外形，校验和需独立函数） |

### `__main__.py`

```bash
python3 -m policydsl compile <policy.json>            # 打印 ConstraintSpec
python3 -m policydsl check <response.txt> --policy <policy.json>
                                                      # 打印 CheckResult；--emit-proof-request 额外写 proof-request.json
```

退出码：`0` 成功；`2` 策略/参数错误（`PolicyError`）；文件缺失或 JSON 非法 → `SystemExit` 带明确消息。

---

## 5. 不变量与边界

1. **`passed ⇔ violations == []`**（`and` 语义）——没有例外，也没有 `semantic="or"`（会报 `PolicyError`）。
2. **内容类规则要求 `response` 非空**：`keyword/length/pattern/format` 遇到 `Transcript(response=None)` 抛
   `PolicyError`；`tool_arg_guard` 不要求 `response`；`budget_bound/tokens` 要求 `token_count`。
3. **顺序敏感处**：`pattern_block` 的证据取「第一条命中的模式」；`tool_arg_guard` 每个工具调用**至多记一条**违规。
4. **长度按码点**（Python `len(str)` = Rust `chars().count()`），不是字节数。
5. **函数外无副作用**：`check` / `compile_policy` 不写文件、不联网（`__main__` 会写 `proof-request.json`）。
6. **`semantic` 只支持 `"and"`**；扩展 or/优先级需要同时改两侧判定器与哈希覆盖字段。

---

## 6. 测试对应

| 文件 | 覆盖 |
|---|---|
| `tests/test_dsl.py` | 模型与校验、六类规则的通过/违规矩阵、`PolicyError` 路径 |
| `tests/test_nfa.py` | 解析器、NFA 构造、`match_search` 与 Python `re` 的行为对照、不支持语法的 fail-fast |
| `tests/test_pii.py` | 四个 PII 模式的命中/漏报、IBAN 校验位 |
| `tests/test_serialize.py` | **契约字节**的性质：确定性/键排序/紧凑、纯 ASCII、`sha256(字节) == spec["sha256"]` 恒等式、六类 kind 与编译后 NFA 都在字节里、未知 kind 原样携带 |
| `tests/test_policy_binding.py` | 策略绑定：攻击回归（空策略证明 + 真策略哈希）、fail-closed、三方比对、伪造证书必须被拒 |
| `tests/test_ablation.py` | `match_search` ≡ `match_search_naive`（pike/naive 语义等价） |
| `tests/test_rules_incircuit.py` + `scripts/cross_validate.py` | Python golden ↔ SP1 逐向量一致（I1） |

---

## 7. 扩展指引：新增一种规则类型

必须**同时**改动下面 5 处，缺一不可（否则违反 I1/I4）：

1. `model.py::Rule.validate` —— 新 kind 的参数校验分支。
2. `compile.py::compile_policy` —— 归一化后写入 `constraints`。
3. `evaluate.py::check` —— golden 判定分支（决定 `evidence_kind` 与 `evidence` 形状）。
4. `circuits/types/src/lib.rs` —— `SpecConstraint` 新变体（内部标签 `kind`）+
   `evaluate` 分支（**必须与第 3 步逐字段一致**）。
5. `tests/` + `scripts/cross_validate.py` —— 至少一条 pass、一条 violate 向量，
   跑 `cross_validate` 确认 host/prove 都对上。

若该规则只打算**链下**支持（不打算证），则**不要**加第 2 步：让未知 kind 原样进规范
字节，电路侧解析失败即产不出证明（fail-closed）。这是刻意设计，不要改成静默跳过。

> 注意第 2/4 步是「同一种 kind」的两侧实现：`compile.py` 必须让该 kind 的字段名与
> Rust 变体逐一对应（serde 内部标签直接吃这份形状）。**没有中间映射层**，字段名
> 对不上就是解析失败 —— 这正是 P0-1 想要的耦合。

---

**相关**：契约如何被证书绑定 → [`03-certificate.md`](03-certificate.md)；
同一份契约在 zkVM 内怎么跑 → [`05-zk-circuits.md`](05-zk-circuits.md)；
私有模式下证据是怎么被承诺的 → [`02-privacy-commitment.md`](02-privacy-commitment.md)。
