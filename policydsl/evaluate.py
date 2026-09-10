"""Reference evaluator: does ``target`` satisfy ``policy``?

This is the *off-circuit* golden implementation. The SP1 program (W4+)
reproduces the same decision inside the zkVM; tests cross-check the two.

Inputs (``check`` accepts either):
- ``str`` — a free-text agent response (content rules only);
- ``Transcript`` — a structured trace with ``response`` (for content rules),
  ``tool_calls`` (for ``tool_arg_guard``), and optionally ``token_count``
  (for ``budget_bound``/tokens).

NOTE on determinism: proving requires deterministic evaluation. Content rules
judged here are deterministic for fixed inputs; ``pattern_block`` uses the
compiled NFA (``policydsl.nfa``), the same contract the SP1 program consumes.
"""

from __future__ import annotations

import json
import re
from typing import List, Union

from . import nfa
from .model import CheckResult, Policy, PolicyError, Transcript, Violation

Target = Union[str, Transcript]

# Canonical subsets — must match `pop-types` (parse_int_ok/parse_float_ok/parse_json_ok)
_INT_RE = re.compile(r"[+-]?\d{1,19}\Z")


def _reject_json_constant(name: str):
    raise ValueError(f"non-finite JSON constant not allowed: {name}")


def _parse_format(fmt: str, text: str) -> bool:
    """Return True if ``text`` parses as the declared ``fmt`` (canonical subset)."""
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
    if isinstance(target, Transcript):
        return target
    if isinstance(target, str):
        return Transcript(response=target)
    raise TypeError(f"expected str or Transcript, got {type(target).__name__}")


def check(policy: Policy, target: Target) -> CheckResult:
    policy.validate()
    tx = _to_transcript(target)
    violations: List[Violation] = []

    for rule in policy.rules:
        if rule.kind == "keyword_block":
            if tx.response is None:
                raise PolicyError(f"rule '{rule.name}' (keyword_block) needs a transcript response")
            text = tx.response.lower()
            hits = [w for w in rule.params["keywords"] if str(w).lower() in text]
            if hits:
                violations.append(Violation(rule, "keyword", hits))

        elif rule.kind == "length_bound":
            if tx.response is None:
                raise PolicyError(f"rule '{rule.name}' (length_bound) needs a transcript response")
            n = len(tx.response)
            lo, hi = int(rule.params["min"]), int(rule.params["max"])
            if not (lo <= n <= hi):
                violations.append(Violation(rule, "length", {"len": n, "min": lo, "max": hi}))

        elif rule.kind == "pattern_block":
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
            if tx.response is None:
                raise PolicyError(f"rule '{rule.name}' (format_check) needs a transcript response")
            fmt = rule.params["format"]
            if not _parse_format(fmt, tx.response):
                violations.append(Violation(
                    rule, "format", {"format": fmt, "len": len(tx.response)}))

        elif rule.kind == "tool_arg_guard":
            fields = rule.params["forbidden_fields"]
            allowed_tools = rule.params.get("tools")  # None => all tools
            for call in tx.tool_calls:
                if allowed_tools is not None and call.name not in allowed_tools:
                    continue
                for f in fields:
                    if f in call.args:
                        violations.append(Violation(
                            rule, "tool_arg", {"tool": call.name, "field": f}))
                        break  # at most one violation per tool call

        elif rule.kind == "budget_bound":
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

    return CheckResult(passed=not violations, violations=violations)
