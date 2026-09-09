"""Policy DSL core data model.

Rule kinds (Phase 1 scope):
  keyword_block : response must not contain any listed keyword/phrase
  length_bound  : response length (characters) within [min, max]
  pattern_block : response must not match any listed regex pattern
  format_check  : response must parse as the declared format
  tool_arg_guard: tool-call args must not contain forbidden fields
  budget_bound  : cumulative call/token budget must hold

The Python layer is the *reference* semantics: it is what tests and the SP1
program both target. ``compile()`` turns a Policy into the ConstraintSpec
JSON that is the contract with the in-circuit prover.

Content rules (keyword/pattern/length/format) judge a free-text ``response``;
``tool_arg_guard`` / ``budget_bound`` judge a structured ``Transcript``
(see ``evaluate.check``)."""


from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class PolicyError(ValueError):
    """Raised when a policy pack is malformed."""


@dataclass
class Rule:
    kind: str
    name: str
    params: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if self.kind == "keyword_block":
            words = self.params.get("keywords")
            if not isinstance(words, list) or not words:
                raise PolicyError(f"rule '{self.name}': keyword_block needs non-empty 'keywords'")
            if not all(isinstance(w, str) for w in words):
                raise PolicyError(f"rule '{self.name}': keywords must be strings")
        elif self.kind == "length_bound":
            lo, hi = self.params.get("min"), self.params.get("max")
            if not (isinstance(lo, int) and isinstance(hi, int) and 0 <= lo <= hi):
                raise PolicyError(f"rule '{self.name}': length_bound needs ints 0 <= min <= max")
        elif self.kind == "pattern_block":
            pats = self.params.get("patterns")
            if not isinstance(pats, list) or not pats:
                raise PolicyError(f"rule '{self.name}': pattern_block needs non-empty 'patterns'")
        elif self.kind == "format_check":
            fmt = self.params.get("format")
            if fmt not in ("json", "int", "float"):
                raise PolicyError(
                    f"rule '{self.name}': format_check needs format in {{json,int,float}}, got {fmt!r}")
        elif self.kind == "tool_arg_guard":
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
            budget = self.params.get("budget")
            unit = self.params.get("unit", "calls")
            if not isinstance(budget, int) or budget < 0:
                raise PolicyError(f"rule '{self.name}': budget_bound needs int budget >= 0")
            if unit not in ("calls", "tokens"):
                raise PolicyError(f"rule '{self.name}': budget_bound unit must be 'calls' or 'tokens'")
        else:
            raise PolicyError(f"rule '{self.name}': unknown kind '{self.kind}'")

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "name": self.name, "params": self.params}


@dataclass
class Policy:
    id: str
    version: str
    description: str = ""
    rules: List[Rule] = field(default_factory=list)
    semantic: str = "and"  # "and": every rule must pass

    def validate(self) -> None:
        if not self.id or not self.version:
            raise PolicyError("policy needs 'id' and 'version'")
        if self.semantic != "and":
            raise PolicyError(f"unsupported semantic '{self.semantic}' (only 'and' for now)")
        for r in self.rules:
            r.validate()


@dataclass
class Violation:
    rule: Rule
    evidence_kind: str        # "keyword" | "length" | "pattern" | ...
    evidence: Any = None      # hits / boundaries / matched pattern

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule.name,
            "kind": self.rule.kind,
            "evidence_kind": self.evidence_kind,
            "evidence": self.evidence,
        }


@dataclass
class CheckResult:
    passed: bool
    violations: List[Violation] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": [v.to_dict() for v in self.violations],
            "notes": self.notes,
        }


@dataclass
class ToolCall:
    """A single tool invocation inside an agent trace."""

    name: str
    args: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Transcript:
    """Structured input for reference evaluation.

    Content rules (keyword/pattern/length/format) judge ``response``;
    ``tool_arg_guard`` judges ``tool_calls``; ``budget_bound`` judges the
    cumulative call count (``len(tool_calls)``) or ``token_count`` when
    ``unit == "tokens"``.
    """

    response: Optional[str] = None
    tool_calls: List[ToolCall] = field(default_factory=list)
    token_count: Optional[int] = None
