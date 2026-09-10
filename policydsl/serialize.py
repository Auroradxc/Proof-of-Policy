"""把 ConstraintSpec 序列化为 Rust 侧 ProofRequest 的约束列表。

ConstraintSpec（由 ``compile_policy`` 产出）是跨层契约。本模块把其中的约束
映射为 serde 的「外部标签枚举」（externally-tagged）``pop_types::Constraint``
JSON，供 SP1 驱动与程序消费。

电路内规则类型（阶段一至三 MVP）：keyword_block、length_bound、pattern_block。
其它类型会抛 ``NotImplementedError`` —— 它们目前只存在于 Python 参考层，
尚未能在电路内证明。
"""

from __future__ import annotations

from typing import Dict, List


def spec_to_rust_constraints(spec: Dict) -> List[Dict]:
    """把 spec 的约束映射为 ``pop_types::Constraint`` serde 枚举 JSON。

    外部标签枚举：每个约束用一个 `{ "VariantName": {字段...} }` 的单键字典表示，
    键名（如 "KeywordBlock"）对应 Rust 端枚举变体，值即该变体的字段。
    """
    out: List[Dict] = []
    for c in spec["constraints"]:
        kind = c["kind"]
        name = c["name"]
        if kind == "keyword_block":
            out.append({"KeywordBlock": {"name": name, "keywords": c["keywords"]}})
        elif kind == "length_bound":
            out.append({"LengthBound": {"name": name, "min": c["min"], "max": c["max"]}})
        elif kind == "pattern_block":
            # 正则约束：附带编译好的 NFA 规格（specs）与匹配模式
            out.append({"PatternBlock": {
                "name": name,
                "patterns": c["patterns"],
                "specs": c["nfa"]["compiled"],
                "mode": c.get("mode", "pike"),
            }})
        elif kind == "format_check":
            out.append({"FormatCheck": {"name": name, "format": c["format"]}})
        elif kind == "tool_arg_guard":
            variant = {"name": name,
                       "forbidden_fields": c["forbidden_fields"],
                       "tools": c.get("tools", [])}
            out.append({"ToolArgGuard": variant})
        elif kind == "budget_bound":
            out.append({"BudgetBound": {"name": name, "budget": c["budget"],
                                        "unit": c.get("unit", "calls")}})
        else:
            # 未知/未实现类型：明确报错，不让其静默进入电路
            raise NotImplementedError(
                f"kind '{kind}' (rule '{name}') is not yet provable in-circuit "
                "(Phase 1-3 supports keyword_block/length_bound/pattern_block)")
    return out


def build_vectors(entries: List[Dict]) -> Dict:
    """把 [{name, response, constraints[]}] 列表包装成 vectors 文件字典。"""
    return {"vectors": entries}
