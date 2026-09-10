"""策略 DSL 的核心数据模型（Policy DSL core data model）。

本模块定义了 Proof-of-Policy 的策略领域模型：规则（Rule）、策略（Policy）、
违规（Violation）、判定结果（CheckResult），以及用于结构化评估的输入
（ToolCall / Transcript）。整个 Python 参考层都围绕这些数据结构展开。

规则类型（Rule kinds，阶段一范围）：
  keyword_block : 响应文本不得包含列出的任意关键词/短语
  length_bound  : 响应字符长度必须落在 [min, max] 区间内
  pattern_block : 响应文本不得匹配列出的任意正则模式
  format_check  : 响应必须能按声明的格式（json/int/float）解析
  tool_arg_guard: 工具调用的参数不得包含被禁止的字段
  budget_bound  : 累计调用/令牌预算必须满足上限

Python 层是「参考语义」（reference semantics）：单测与 SP1 程序都以它为目标。
``compile()`` 把 Policy 编译成 ConstraintSpec（JSON），后者是与电路内 prover
之间的唯一契约。

内容类规则（keyword/pattern/length/format）判定自由文本 ``response``；
``tool_arg_guard`` / ``budget_bound`` 判定结构化 ``Transcript``
（见 ``evaluate.check``）。
"""


from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class PolicyError(ValueError):
    """策略包（policy pack）格式非法时抛出的异常。

    继承自 ValueError，便于上层统一捕获策略解析/校验阶段的错误。
    """


@dataclass
class Rule:
    """单条规则：由类型 kind、名字 name、参数字典 params 三部分组成。

    kind 决定规则的语义；params 携带该类型所需的参数（如关键词列表、
    长度上下界、正则列表等）。规则本身不包含判定逻辑，判定由
    ``evaluate.check``（参考层）与 SP1 程序（电路内）各自实现。
    """

    kind: str
    name: str
    params: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        """校验本规则的参数是否合法，非法则抛出 PolicyError。

        每种 kind 有各自的合法参数约束，此处逐类型校验，做到「编译期快速失败」，
        避免非法策略进入后续编译/证明流程。
        """
        if self.kind == "keyword_block":
            # 关键词规则：keywords 必须是非空字符串列表
            words = self.params.get("keywords")
            if not isinstance(words, list) or not words:
                raise PolicyError(f"rule '{self.name}': keyword_block needs non-empty 'keywords'")
            if not all(isinstance(w, str) for w in words):
                raise PolicyError(f"rule '{self.name}': keywords must be strings")
        elif self.kind == "length_bound":
            # 长度规则：min/max 必须是整数，且 0 <= min <= max
            lo, hi = self.params.get("min"), self.params.get("max")
            if not (isinstance(lo, int) and isinstance(hi, int) and 0 <= lo <= hi):
                raise PolicyError(f"rule '{self.name}': length_bound needs ints 0 <= min <= max")
        elif self.kind == "pattern_block":
            # 正则规则：patterns 必须非空；可选 match_mode 只能是 pike/naive
            pats = self.params.get("patterns")
            if not isinstance(pats, list) or not pats:
                raise PolicyError(f"rule '{self.name}': pattern_block needs non-empty 'patterns'")
            mm = self.params.get("match_mode")
            if mm is not None and mm not in ("pike", "naive"):
                raise PolicyError(
                    f"rule '{self.name}': match_mode must be 'pike' or 'naive', got {mm!r}")
        elif self.kind == "format_check":
            # 格式规则：format 只能是 json/int/float 之一
            fmt = self.params.get("format")
            if fmt not in ("json", "int", "float"):
                raise PolicyError(
                    f"rule '{self.name}': format_check needs format in {{json,int,float}}, got {fmt!r}")
        elif self.kind == "tool_arg_guard":
            # 工具参数规则：forbidden_fields 必须非空且全为字符串；
            # 可选的 tools 若存在必须是字符串列表（用于限定只约束哪些工具）
            fields = self.params.get("forbidden_fields")
            if not isinstance(fields, list) or not fields or not all(
                isinstance(f, str) for f in fields
            ):
                raise PolicyError(
                    f"rule '{self.name}': tool_arg_guard needs non-empty 'forbidden_fields' strings")
            tools = self.params.get("tools")
            if tools is not None and (
                not isinstance(tools, list) or not all(isinstance(t, str) for t in tools)
            ):
                raise PolicyError(f"rule '{self.name}': optional 'tools' must be a list of str")
        elif self.kind == "budget_bound":
            # 预算规则：budget 是非负整数；unit 只能是 calls/tokens
            budget = self.params.get("budget")
            unit = self.params.get("unit", "calls")
            if not isinstance(budget, int) or budget < 0:
                raise PolicyError(f"rule '{self.name}': budget_bound needs int budget >= 0")
            if unit not in ("calls", "tokens"):
                raise PolicyError(f"rule '{self.name}': budget_bound unit must be 'calls' or 'tokens'")
        else:
            # 未知规则类型：直接拒绝，防止拼写错误悄悄变成「无操作」
            raise PolicyError(f"rule '{self.name}': unknown kind '{self.kind}'")

    def to_dict(self) -> Dict[str, Any]:
        """把规则序列化为可 JSON 化的字典。"""
        return {"kind": self.kind, "name": self.name, "params": self.params}


@dataclass
class Policy:
    """一个策略包：由若干规则组成，按语义组合判定。

    semantic 目前只支持 "and"（全部规则都要通过）；后续可扩展 or/优先级等。
    """

    id: str
    version: str
    description: str = ""
    rules: List[Rule] = field(default_factory=list)
    semantic: str = "and"  # "and"：每一条规则都必须通过

    def validate(self) -> None:
        """校验策略包本身及其全部规则。"""
        if not self.id or not self.version:
            raise PolicyError("policy needs 'id' and 'version'")
        if self.semantic != "and":
            raise PolicyError(f"unsupported semantic '{self.semantic}' (only 'and' for now)")
        for r in self.rules:
            r.validate()


@dataclass
class Violation:
    """一次违规：记录触发了哪条规则，以及违规的证据。

    evidence 按 evidence_kind 不同携带不同内容：
    - keyword : 命中的关键词列表
    - length  : {"len", "min", "max"}
    - pattern : 命中的正则模式串
    - format  : {"format", "len"}
    - tool_arg: {"tool", "field"}
    - budget  : {"unit", "total", "budget"}
    """

    rule: Rule
    evidence_kind: str        # "keyword" | "length" | "pattern" | ...
    evidence: Any = None      # 命中项 / 边界 / 命中的模式等

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的字典（用于证书/验证产物）。"""
        return {
            "rule": self.rule.name,
            "kind": self.rule.kind,
            "evidence_kind": self.evidence_kind,
            "evidence": self.evidence,
        }


@dataclass
class CheckResult:
    """一次判定结果：是否通过，以及（若不通过）违规列表与备注。

    passed 为 True 当且仅当 violations 为空（语义为 "and"）。
    """

    passed: bool
    violations: List[Violation] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的字典。"""
        return {
            "passed": self.passed,
            "violations": [v.to_dict() for v in self.violations],
            "notes": self.notes,
        }


@dataclass
class ToolCall:
    """agent 轨迹（trace）中的一次工具调用。"""

    name: str
    args: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Transcript:
    """用于参考评估的结构化输入。

    内容类规则（keyword/pattern/length/format）判定 ``response``；
    ``tool_arg_guard`` 判定 ``tool_calls``；``budget_bound`` 判定累计调用次数
    （``len(tool_calls)``），当 ``unit == "tokens"`` 时判定 ``token_count``。
    """

    response: Optional[str] = None
    tool_calls: List[ToolCall] = field(default_factory=list)
    token_count: Optional[int] = None
