"""Policy DSL core data model.

Rule kinds (MVP scope, W2-W3; extended later):
  keyword_block : response must not contain any listed keyword/phrase
  length_bound  : response length (characters) within [min, max]
  pattern_block : response must not match any listed regex pattern
  format_check  : response must parse as the declared format        [stub]
  tool_arg_guard: tool-call args must not contain forbidden fields  [stub]
  budget_bound  : cumulative call/token budget must hold            [stub]

The Python layer is the *reference* semantics: it is what tests and the SP1
program both target. ``compile()`` turns a Policy into the ConstraintSpec
JSON that is the contract with the in-circuit prover.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


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
        # stubs (format_check / tool_arg_guard / budget_bound): accepted for now,
        # flagged as not-implemented by the evaluator.

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
