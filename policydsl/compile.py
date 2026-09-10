"""把 Policy 编译成可序列化的 ConstraintSpec（prover 侧契约）。

ConstraintSpec 是 SP1 程序（W4+）实际消费的数据结构。Python 层同时保留一份
参考评估实现（``evaluate.py``），这样电路内的判定逻辑可以与这份编译器输出
做交叉校验（cross-check）。

ConstraintSpec 结构::

    {
      "spec_version": "v1",
      "policy_id": "...", "policy_version": "...", "semantic": "and",
      "constraints": [
        {"kind": "keyword_block", "name": "...", "keywords": ["a", "b", ...]},
        {"kind": "length_bound",  "name": "...", "min": 1, "max": 2000},
        {"kind": "pattern_block", "name": "...", "patterns": [...], "nfa": {...}},
        ...
      ],
      "sha256": "..."   # 稳定字段的哈希，用于来源绑定（provenance binding）
    }
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from . import nfa
from .model import Policy, PolicyError

SPEC_VERSION = "v1"


def _canonical_hash(obj: Dict[str, Any]) -> str:
    """对字典做「规范化哈希」：按键排序、紧凑分隔符后求 SHA-256。

    规范化（canonical）保证：只要语义内容相同，无论键的插入顺序如何，
    得到的哈希都一致 —— 这是证书中 policy_hash 可被独立重算的前提。
    """
    body = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def compile_policy(policy: Policy) -> Dict[str, Any]:
    """把 Policy 编译为 ConstraintSpec 字典（含 sha256 绑定哈希）。

    流程：先校验策略 → 逐条规则映射为规范化的约束表示 → 计算稳定字段哈希。
    关键词/字段/工具名在编译期就做排序去重与小写化，保证跨层一致性。
    """
    policy.validate()
    constraints: list[Dict[str, Any]] = []
    for rule in policy.rules:
        if rule.kind == "keyword_block":
            # 关键词：排序去重 + 小写化，规避大小写/顺序差异导致的哈希漂移
            constraints.append({
                "kind": "keyword_block",
                "name": rule.name,
                "keywords": sorted({str(w).lower() for w in rule.params["keywords"]}),
            })
        elif rule.kind == "length_bound":
            # 长度边界：直接转 int（策略 JSON 里可能混入字符串形式的数字）
            constraints.append({
                "kind": "length_bound",
                "name": rule.name,
                "min": int(rule.params["min"]),
                "max": int(rule.params["max"]),
            })
        elif rule.kind == "pattern_block":
            # 把每条正则编译成可序列化的 NFA（跨层契约）。
            # 不支持的语法在编译期即快速失败，避免进入证明阶段才报错。
            pats = [str(p) for p in rule.params["patterns"]]
            specs = []
            for p in pats:
                try:
                    specs.append(nfa.compile_pattern(p))
                except nfa.RegexSyntaxError as exc:
                    raise PolicyError(
                        f"rule '{rule.name}': pattern {p!r} not supported by the "
                        f"NFA compiler ({exc})") from exc
            c = {
                "kind": "pattern_block",
                "name": rule.name,
                "patterns": pats,
                "nfa": {"compiled": specs},
            }
            # 只有显式声明 naive 才记录；缺省走 pike（电路内默认模式）
            if rule.params.get("match_mode") == "naive":
                c["mode"] = "naive"
            constraints.append(c)
        elif rule.kind == "format_check":
            # 格式校验：把声明格式透传给约束
            constraints.append({
                "kind": "format_check",
                "name": rule.name,
                "format": rule.params["format"],
            })
        elif rule.kind == "tool_arg_guard":
            # 工具参数防护：被禁字段排序去重；可选 tools 白名单也排序去重
            c = {
                "kind": "tool_arg_guard",
                "name": rule.name,
                "forbidden_fields": sorted(set(rule.params["forbidden_fields"])),
            }
            if rule.params.get("tools"):
                c["tools"] = sorted(set(rule.params["tools"]))
            constraints.append(c)
        elif rule.kind == "budget_bound":
            # 预算边界：记录上限值与计量单位
            constraints.append({
                "kind": "budget_bound",
                "name": rule.name,
                "budget": int(rule.params["budget"]),
                "unit": rule.params.get("unit", "calls"),
            })
        else:
            # 未知/未实现类型：打 stub 标记，说明参考评估器尚未实现
            constraints.append({
                "kind": rule.kind,
                "name": rule.name,
                "stub": True,
                "note": "not yet implemented in the reference evaluator",
            })

    # 稳定字段：参与哈希的「契约主体」，不含会随序列化方式变化的元信息
    stable = {
        "spec_version": SPEC_VERSION,
        "policy_id": policy.id,
        "policy_version": policy.version,
        "semantic": policy.semantic,
        "constraints": constraints,
    }
    spec = dict(stable)
    spec["sha256"] = _canonical_hash(stable)  # 绑定哈希：证书据此校验策略一致性
    return spec
