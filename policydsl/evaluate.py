"""参考评估器（reference evaluator）：判定 ``target`` 是否满足 ``policy``。

这是**链外（off-circuit）golden 实现**。SP1 程序（W4+）在 zkVM 内复现同样的
判定逻辑；测试会对两者做交叉校验，保证「链上证明的结论」与「链下参考结论」
一致。

输入（``check`` 接受两种形式）：
- ``str`` —— 一段自由文本 agent 响应（只用于内容类规则）；
- ``Transcript`` —— 结构化轨迹，含 ``response``（内容类规则）与 ``receipts``
  （``tool_arg_guard`` / ``budget_bound``/calls）。``budget_bound``/tokens 不再
  读任何声明值，而是按 :func:`policydsl.trace.token_count` **现算**（P1-5）。

回执链是**网关签发**的（P1-5）：链结构不自洽时，工具类规则一律 fail-closed
（记 ``trace_unbound`` 违规），绝不退化成「读不出来就当作没有调用」。

关于确定性（determinism）的说明：证明要求判定必须是确定性的。此处内容类规则
对固定输入是确定的；``pattern_block`` 使用编译后的 NFA（``policydsl.nfa``），
与 SP1 程序消费的是同一份契约。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import List, Union

from . import nfa, trace
from .model import (
    CheckResult, DelegatedConstraint, Policy, PolicyError, Transcript, Violation,
)

# check 可接受的输入类型：自由文本或结构化轨迹
Target = Union[str, Transcript]


@dataclass
class _TraceRule:
    """**合成的**规则占位符：坏回执链的落点。

    它不是策略里的任何一条规则 —— 名字带尖括号，与策略规则名（标识符）
    不可能撞车。之所以要有它：一条只有内容规则的策略也可能配着一条自相矛盾
    的回执链出证，若此时不记违规，「链坏了」这件事在结果里就完全看不见了。
    与 ``pop_types::evaluate`` 里那个 ``rule: "<trace>"`` 逐字符对应。
    """

    name: str = "<trace>"
    kind: str = "trace_unbound"

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
    # 被委托给外部证明系统（ezkl）的约束 —— 本层与 SP1 电路一样**只登记、不判定**。
    delegated: List[DelegatedConstraint] = []

    # 回执链的**结构**校验，只做一次（tool_arg_guard / budget_bound/calls 都用）。
    # 空链合法 —— 一次工具都没调用是正常情形，不是「链坏了」。
    chain_ok, chain_why = trace.chain_ok(tx.receipts)
    # token 数现算（P1-5）：不再接受任何自填值。
    tokens = trace.token_count(tx.response or "")

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
            # 工具参数防护：检查（可选白名单限定后的）**回执**参数里是否出现
            # 被禁字段；每个调用最多记一条违规。链不自洽 ⇒ fail-closed：记一条
            # trace_unbound 并跳过本条规则 —— 而不是「链读不出来就当作没有调用」。
            if not chain_ok:
                violations.append(Violation(rule, "trace_unbound", chain_why))
                continue
            fields = rule.params["forbidden_fields"]
            allowed_tools = rule.params.get("tools")  # None => 约束所有工具
            for r in tx.receipts:
                if allowed_tools is not None and r.tool not in allowed_tools:
                    continue
                for f in fields:
                    if f in r.args:
                        violations.append(Violation(
                            rule, "tool_arg", {"tool": r.tool, "field": f}))
                        break  # 每个工具调用至多记一条违规

        elif rule.kind == "budget_bound":
            # 预算边界：按 calls 计回执条数，按 tokens 计**现算**的 token 数
            unit = rule.params.get("unit", "calls")
            budget = int(rule.params["budget"])
            if unit == "calls":
                if not chain_ok:
                    violations.append(Violation(rule, "trace_unbound", chain_why))
                    continue
                total = len(tx.receipts)
            else:  # tokens
                total = tokens
            if total > budget:
                violations.append(Violation(
                    rule, "budget", {"unit": unit, "total": total, "budget": budget}))

        elif rule.kind == "semantic_bound":
            # 语义规则：**参考层判不了**，如实登记为「已委托」，而不是猜一个结论。
            #
            # 这里判不了不是实现偷懒，是分工：判定要跑一遍 ONNX 前向，那是 ezkl
            # 的地盘；参考层既没有 ezkl 也不该有（它是纯标准库）。所以本层的角色
            # 与 SP1 电路一致：**登记委托**，结论由陪伴证明给。
            #
            # 三种错误做法，每一种都对应一个真实存在的漏洞形态：
            #   ① 当作通过（不记）—— 语义规则变成一个恒真的空壳；
            #   ② 记一条 violation —— `passed` 变 false，而「策略被违反」不是事实；
            #   ③ 在这里跑一遍 torch 前向 —— 那是一个**参考实现**，不是**证明**：
            #      它只能说明「我这台机器算出来是这样」，不能说明「出证方真的这么算的」。
            thr = int(rule.params["threshold_bp"])
            if not (0 <= thr <= 10000):
                raise PolicyError(
                    f"rule '{rule.name}': threshold_bp 必须在 [0,10000]，得到 {thr}")
            if rule.params["direction"] not in ("le", "ge"):
                raise PolicyError(
                    f"rule '{rule.name}': direction 必须是 le/ge，得到 "
                    f"{rule.params['direction']!r}")
            # 指纹在这里现解析（与 compile 同一口径）：参考层不信任策略里写的值，
            # 只把它当作「作者声明的目标」，实际比对交给 verify_cert。
            from .compile import _model_vkey
            from . import semantic as sem

            delegated.append(DelegatedConstraint(
                name=rule.name,
                system="ezkl-halo2",
                model_vkey=rule.params.get("model_vkey") or _model_vkey(),
                onnx_sha256=rule.params.get("onnx_sha256") or sem.onnx_sha256(),
                threshold_bp=thr,
                direction=rule.params["direction"],
            ))

    # 坏链即使没有任何工具规则「接住」它也要记一笔：否则一条只有内容规则的策略
    # 会带着一条明显自相矛盾的回执链通过判定，而结果里什么都看不出来。
    # 规则名用带尖括号的占位符，与策略里的规则名（标识符）不可能撞车。
    if not chain_ok and not any(v.evidence_kind == "trace_unbound"
                                for v in violations):
        violations.append(Violation(_TraceRule(), "trace_unbound", chain_why))

    # passed = 无任何违规（"and" 语义）。**注意**：`delegated` 非空时它只覆盖
    # 判得了的那部分，见 `CheckResult` 与 `DelegatedConstraint` 的 docstring。
    return CheckResult(passed=not violations, violations=violations, delegated=delegated)
