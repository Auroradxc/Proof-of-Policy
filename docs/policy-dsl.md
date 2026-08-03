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
| `pattern_block` | 响应不得匹配任一正则（re.search 语义） | `patterns: [str]` | W3 实现（NFA 路径验证） |
| `format_check` | 响应必须可解析为声明格式 | `format: str` | stub |
| `tool_arg_guard` | 工具调用参数不得含禁止字段 | `forbidden_fields: [str]` | stub |
| `budget_bound` | 累计调用/token 预算 | `budget: int` | stub |

## 语义

- `semantic="and"`：全部规则通过 → 合规；任一违反 → 违规并记录 `violations[].kind` 与证据。
- 正则语义采用 Python `re.search`（参考实现）与 SP1 内电路 NFA 路径验证对齐（W3 设计，W4 实现时交叉验证）。

## 编译输出

`python -m policydsl compile <pack.json>` 输出 ConstraintSpec（见 `docs/architecture.md`）。
- `keyword_block` 关键词会**小写化 + 排序**（保证编译确定性）。
- `pattern_block` 的 `nfa.status` 在 W3 实现后更新为实际 NFA 描述。

## 设计约束

1. **确定性**：证明要求确定性重放。所有规则实现必须对相同输入产生相同判定。
2. **可切片**：违规定位到规则级，支持 W5 的「违规理由选择性披露」。
3. **可溯源**：ConstraintSpec 的 `sha256` 作为策略/电路绑定哈希进入合规证书。
