"""Reference evaluator: does ``response`` satisfy ``policy``?

This is the *off-circuit* golden implementation. The SP1 program (W4+)
reproduces the same decision inside the zkVM; tests cross-check the two.

NOTE on determinism: proving requires deterministic evaluation. Python ``re``
is deterministic for a fixed pattern+input, which is all the reference needs.
"""

from __future__ import annotations

import re
from typing import List

from .model import Policy, CheckResult, Violation


def check(policy: Policy, response: str) -> CheckResult:
    policy.validate()
    violations: List[Violation] = []
    for rule in policy.rules:
        if rule.kind == "keyword_block":
            text = response.lower()
            hits = [w for w in rule.params["keywords"] if str(w).lower() in text]
            if hits:
                violations.append(Violation(rule, "keyword", hits))
        elif rule.kind == "length_bound":
            n = len(response)
            lo, hi = int(rule.params["min"]), int(rule.params["max"])
            if not (lo <= n <= hi):
                violations.append(Violation(rule, "length", {"len": n, "min": lo, "max": hi}))
        elif rule.kind == "pattern_block":
            for pat in rule.params["patterns"]:
                if re.search(str(pat), response):
                    violations.append(Violation(rule, "pattern", pat))
                    break
        else:
            violations.append(Violation(rule, "not_implemented", None))
    return CheckResult(passed=not violations, violations=violations)
