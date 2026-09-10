"""参考评估器（reference evaluator）：判定 ``target`` 是否满足 ``policy``。

这是**链外（off-circuit）golden 实现**。SP1 程序（W4+）在 zkVM 内复现同样的
判定逻辑；测试会对两者做交叉校验，保证「链上证明的结论」与「链下参考结论」
一致。

输入（``check`` 接受两种形式）：
- ``str`` —— 一段自由文本 agent 响应（只用于内容类规则）；
- ``Transcript`` —— 结构化轨迹，含 ``response``（内容类规则）、
  ``tool_calls``（``tool_arg_guard``）、可选 ``token_count``（``budget_bound``/tokens）。

关于确定性（determinism）的说明：证明要求判定必须是确定性的。此处内容类规则
对固定输入是确定的；``pattern_block`` 使用编译后的 NFA（``policydsl.nfa``），
与 SP1 程序消费的是同一份契约。
"""

from __future__ import annotations

import json
import re
from typing import List, Union

from . import nfa
from .model import CheckResult, Policy, PolicyError, Transcript, Violation

# check 可接受的输入类型：自由文本或结构化轨迹
Target = Union[str, Transcript]

# 规范子集 —— 必须与 `pop-types`（parse_int_ok/parse_float_ok/parse_json_ok）保持一致。
# 整数：可选正负号 + 最多 19 位数字（保证在 u64/i64 可表示范围内，避免溢出差异）。
_INT_RE = re.compile(r"[+-]?\d{1,19}\Z")


def _reject_json_constant(name: str):
    """拒绝非有限 JSON 常量（NaN/Infinity 等），保证 JSON 解析子集规范。"""
    raise ValueError(f"non-finite JSON constant not allowed: {name}")


def _parse_format(fmt: str, text: str) -> bool:
    """返回 ``text`` 能否按声明的 ``fmt`` 解析（规范子集，确定性）。

    - json : 用 json.loads 解析，且拒绝 NaN/Infinity 等非有限常量；
    - int  : 匹配 [+-]?\d{1,19}；
    - float: 有限、不含下划线、非 nan/inf 的十进制浮点。
    """
    if fmt == "json":
        try:
            json.loads(text, parse_constant=_reject_json_constant)
        except ValueError:
            return False
        return True
    if fmt == "int":
        return bool(_INT_RE.match(text.strip()))
    if fmt == "float":
        t = text.strip()
        if not t or "_" in t:
            return False
        low = t.lower()
        if "nan" in low or "inf" in low:
            return False
        try:
            float(t)
        except ValueError:
            return False
        return True
    raise PolicyError(f"unsupported format '{fmt}'")


def _to_transcript(target: Target) -> Transcript:
    """把输入统一规整为 Transcript：str → 只含 response 的 Transcript。"""
    if isinstance(target, Transcript):
        return target
    if isinstance(target, str):
        return Transcript(response=target)
    raise TypeError(f"expected str or Transcript, got {type(target).__name__}")


def check(policy: Policy, target: Target) -> CheckResult:
    """对 ``target`` 执行 ``policy`` 的全部规则，返回判定结果。

    语义为 "and"：任一条规则违规即整体不通过。逐条规则收集违规证据，
    最后统一打包进 CheckResult。
    """
    policy.validate()
    tx = _to_transcript(target)
    violations: List[Violation] = []

    for rule in policy.rules:
        if rule.kind == "keyword_block":
            # 关键词阻断：响应小写化后检查是否包含任意禁用词（不区分大小写）
            if tx.response is None:
                raise PolicyError(f"rule '{rule.name}' (keyword_block) needs a transcript response")
            text = tx.response.lower()
            hits = [w for w in rule.params["keywords"] if str(w).lower() in text]
            if hits:
                violations.append(Violation(rule, "keyword", hits))

        elif rule.kind == "length_bound":
            # 长度边界：len(response) 必须落在 [min, max]
            if tx.response is None:
                raise PolicyError(f"rule '{rule.name}' (length_bound) needs a transcript response")
            n = len(tx.response)
            lo, hi = int(rule.params["min"]), int(rule.params["max"])
            if not (lo <= n <= hi):
                violations.append(Violation(rule, "length", {"len": n, "min": lo, "max": hi}))

        elif rule.kind == "pattern_block":
            # 正则阻断：用编译后的 NFA 做搜索匹配，命中任意一条即违规（记录第一条）
            if tx.response is None:
                raise PolicyError(f"rule '{rule.name}' (pattern_block) needs a transcript response")
            for pat in rule.params["patterns"]:
                try:
                    matched = nfa.match_search(nfa.compile_pattern(str(pat)), tx.response)
                except nfa.RegexSyntaxError as exc:
                    raise PolicyError(f"rule '{rule.name}': {exc}") from exc
                if matched:
                    violations.append(Violation(rule, "pattern", pat))
                    break

        elif rule.kind == "format_check":
            # 格式校验：响应整体必须能按声明格式解析
            if tx.response is None:
                raise PolicyError(f"rule '{rule.name}' (format_check) needs a transcript response")
            fmt = rule.params["format"]
            if not _parse_format(fmt, tx.response):
                violations.append(Violation(
                    rule, "format", {"format": fmt, "len": len(tx.response)}))

        elif rule.kind == "tool_arg_guard":
            # 工具参数防护：检查（可选白名单限定后的）工具调用的参数里
            # 是否出现被禁字段；每个调用最多记一条违规。
            fields = rule.params["forbidden_fields"]
            allowed_tools = rule.params.get("tools")  # None => 约束所有工具
            for call in tx.tool_calls:
                if allowed_tools is not None and call.name not in allowed_tools:
                    continue
                for f in fields:
                    if f in call.args:
                        violations.append(Violation(
                            rule, "tool_arg", {"tool": call.name, "field": f}))
                        break  # 每个工具调用至多记一条违规

        elif rule.kind == "budget_bound":
            # 预算边界：按 calls 计 len(tool_calls)，按 tokens 计 token_count
            unit = rule.params.get("unit", "calls")
            budget = int(rule.params["budget"])
            if unit == "calls":
                total = len(tx.tool_calls)
            else:  # tokens
                if tx.token_count is None:
                    raise PolicyError(
                        f"rule '{rule.name}' (budget_bound/tokens) needs transcript.token_count")
                total = int(tx.token_count)
            if total > budget:
                violations.append(Violation(
                    rule, "budget", {"unit": unit, "total": total, "budget": budget}))

    # passed = 无任何违规（"and" 语义）
    return CheckResult(passed=not violations, violations=violations)
