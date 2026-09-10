"""Compile a Policy into a serializable ConstraintSpec (the prover-side contract).

The ConstraintSpec is what the SP1 program consumes (W4+). The Python layer
also keeps a reference evaluation (``evaluate.py``) so the in-circuit logic
can be cross-checked against this compiler output.

ConstraintSpec shape::

    {
      "spec_version": "v1",
      "policy_id": "...", "policy_version": "...", "semantic": "and",
      "constraints": [
        {"kind": "keyword_block", "name": "...", "keywords": ["a", "b", ...]},
        {"kind": "length_bound",  "name": "...", "min": 1, "max": 2000},
        {"kind": "pattern_block", "name": "...", "patterns": [...], "nfa": {...}},
        ...
      ],
      "sha256": "..."   # hash of the stable fields, for provenance binding
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
    body = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def compile_policy(policy: Policy) -> Dict[str, Any]:
    policy.validate()
    constraints: list[Dict[str, Any]] = []
    for rule in policy.rules:
        if rule.kind == "keyword_block":
            constraints.append({
                "kind": "keyword_block",
                "name": rule.name,
                "keywords": sorted({str(w).lower() for w in rule.params["keywords"]}),
            })
        elif rule.kind == "length_bound":
            constraints.append({
                "kind": "length_bound",
                "name": rule.name,
                "min": int(rule.params["min"]),
                "max": int(rule.params["max"]),
            })
        elif rule.kind == "pattern_block":
            # Compile each pattern to a serializable NFA (the cross-layer
            # contract). Unsupported regex syntax fails fast at compile time.
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
            if rule.params.get("match_mode") == "naive":
                c["mode"] = "naive"
            constraints.append(c)
        elif rule.kind == "format_check":
            constraints.append({
                "kind": "format_check",
                "name": rule.name,
                "format": rule.params["format"],
            })
        elif rule.kind == "tool_arg_guard":
            c = {
                "kind": "tool_arg_guard",
                "name": rule.name,
                "forbidden_fields": sorted(set(rule.params["forbidden_fields"])),
            }
            if rule.params.get("tools"):
                c["tools"] = sorted(set(rule.params["tools"]))
            constraints.append(c)
        elif rule.kind == "budget_bound":
            constraints.append({
                "kind": "budget_bound",
                "name": rule.name,
                "budget": int(rule.params["budget"]),
                "unit": rule.params.get("unit", "calls"),
            })
        else:
            constraints.append({
                "kind": rule.kind,
                "name": rule.name,
                "stub": True,
                "note": "not yet implemented in the reference evaluator",
            })

    stable = {
        "spec_version": SPEC_VERSION,
        "policy_id": policy.id,
        "policy_version": policy.version,
        "semantic": policy.semantic,
        "constraints": constraints,
    }
    spec = dict(stable)
    spec["sha256"] = _canonical_hash(stable)
    return spec
