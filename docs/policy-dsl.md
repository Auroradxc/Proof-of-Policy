# 策略 DSL 规范（v0.1）

## 策略包格式（JSON）

```jsonc
{
  "id": "eu-ai-act-v1",
  "version": "0.1.0",
  "description": "...",
  "semantic": "and",          // 目前仅支持 "and"
  "rules": [
    {"kind": "keyword_block", "name": "...", "params": {"keywords": ["..."]}},
    {"kind": "length_bound",  "name": "...", "params": {"min": 1, "max": 2000}},
    {"kind": "pattern_block", "name": "...", "params": {"patterns": ["..."]}}
  ]
}
```

## 规则类型

| kind | 语义 | params | 状态 |
|---|---|---|---|
| `keyword_block` | 响应不得包含任一关键词/短语（大小写不敏感） | `keywords: [str]` | W2 已实现 |
| `length_bound` | 响应字符数在 `[min, max]` | `min, max: int` | W2 已实现 |
| `pattern_block` | 响应不得匹配任一正则（子串；正则须在受支持子集内） | `patterns: [str]` | W3 已实现（NFA 编译进 ConstraintSpec） |
| `format_check` | 响应必须可解析为声明格式（json/int/float） | `format: str` | W1.5 已实现(Python) |
| `tool_arg_guard` | 工具调用参数不得含禁止字段（可限定 `tools`） | `forbidden_fields: [str]`, `tools?: [str]` | W1.5 已实现(Python) |
| `budget_bound` | 累计调用次数/token 预算 | `budget: int`, `unit: calls\|tokens` | W1.5 已实现(Python) |

## 语义

- `semantic="and"`：全部规则通过 → 合规；任一违反 → 违规并记录 `violations[].kind` 与证据。
- `pattern_block` 语义 = **子串存在匹配即违规**（对齐 Python `re.search`）。参考判定用编译进 ConstraintSpec 的 NFA（`policydsl.nfa`），SP1 用同一份 NFA spec（`pop-types::nfa_match`）——保证跨层一致。受支持语法子集（字符类/转义/`.`/量词/分组/或）与 ASCII 语义见 `policydsl/nfa.py`；不支持语法（锚点、反向引用、环视）在编译时 fail-fast。
- 内容规则（keyword/pattern/length/format）判定自由文本 `response`；`tool_arg_guard` / `budget_bound` 判定结构化 `Transcript`（`evaluate.check` 的入参可以是 `str` 或 `policydsl.model.Transcript`：含 `response` 与 `receipts`——**工具网关签发的回执链**，P1-5）。`budget_bound(unit="tokens")` 数的是 `response` 按固定空白字节集切出的 run 数（电路内自算），**没有**可自填的 `token_count`。

## 编译输出

`python -m policydsl compile <pack.json>` 输出 ConstraintSpec（见 `docs/architecture.md`）。
- `keyword_block` 关键词会**小写化 + 排序**（保证编译确定性）。
- `pattern_block` 的 `nfa.status` 在 W3 实现后更新为实际 NFA 描述。

## 设计约束

1. **确定性**：证明要求确定性重放。所有规则实现必须对相同输入产生相同判定。
2. **可切片**：违规定位到规则级，支持 W5 的「违规理由选择性披露」。
3. **可溯源**：ConstraintSpec 的 `sha256` 作为策略/电路绑定哈希进入合规证书。
