"""Private mode primitives: response commitments, selective disclosure, and
redaction-with-proof (VDR-style "differ only at masked positions").

This is the reference layer for the SP1 private-mode program
(``pop-types::evaluate_private``). Semantics are kept byte-for-byte compatible
with the Rust side:

- ``commitment`` / ``evidence_commitment``: SHA-256 over UTF-8 bytes, lowercase hex.
- keyword matching uses ASCII lower-casing (parity with the in-circuit matcher).
- violations use a canonical evidence string per kind:
    keyword_block -> the (first, spec-ordered) matched keyword
    length_bound  -> "len=<N>"
    pattern_block -> the pattern string
- redaction: same code-point length; masked indices hold the mask char (``*``),
  every other position is identical to the original.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Tuple

from . import nfa

MASK_CHAR = "*"


def _ascii_lower(s: str) -> str:
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def commitment(text: str) -> str:
    """SHA-256 of the UTF-8 bytes of ``text``, lowercase hex."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def evidence_commitment(evidence: str) -> str:
    """Commitment to a violation-evidence fragment (same hash as ``commitment``)."""
    return commitment(evidence)


def canonical_violations(spec: Dict, response: str,
                         tool_calls: Optional[List[Dict]] = None,
                         token_count: Optional[int] = None) -> List[Dict]:
    """Mirror ``pop-types::evaluate`` exactly, returning (rule, kind, evidence).

    ``tool_calls`` is a list of ``{"name": str, "args": {str: str}}``; evidence
    strings are byte-identical to the Rust side (needed for private-mode
    evidence commitments).
    """
    from .evaluate import _parse_format  # canonical subset parser

    lower = _ascii_lower(response)
    calls = tool_calls or []
    out: List[Dict] = []
    for c in spec["constraints"]:
        kind, name = c["kind"], c["name"]
        if kind == "keyword_block":
            hit = next((kw for kw in c["keywords"] if kw in lower), None)
            if hit is not None:
                out.append({"rule": name, "kind": "keyword_block", "evidence": hit})
        elif kind == "length_bound":
            n = len(response)
            if not (c["min"] <= n <= c["max"]):
                out.append({"rule": name, "kind": "length_bound", "evidence": f"len={n}"})
        elif kind == "pattern_block":
            for i, s in enumerate(c["nfa"]["compiled"]):
                if nfa.match_search(s, response):
                    out.append({"rule": name, "kind": "pattern_block",
                                "evidence": c["patterns"][i]})
                    break
        elif kind == "format_check":
            if not _parse_format(c["format"], response):
                out.append({"rule": name, "kind": "format_check", "evidence": c["format"]})
        elif kind == "tool_arg_guard":
            allowed = c.get("tools") or []
            for call in calls:
                cname = call["name"] if isinstance(call, dict) else call.name
                args = (call.get("args", {}) if isinstance(call, dict) else call.args)
                if allowed and cname not in allowed:
                    continue
                hit = next((f for f in c["forbidden_fields"] if f in args), None)
                if hit is not None:
                    out.append({"rule": name, "kind": "tool_arg_guard",
                                "evidence": f"{cname}:{hit}"})
                    break  # at most one violation per tool call
        elif kind == "budget_bound":
            unit = c.get("unit", "calls")
            total = len(calls) if unit == "calls" else int(token_count or 0)
            if total > c["budget"]:
                out.append({"rule": name, "kind": "budget_bound",
                            "evidence": f"{unit}={total}/{c['budget']}"})
        else:
            raise NotImplementedError(f"kind '{kind}' not provable in-circuit yet")
    return out


# --------------------------------------------------------------------------- #
# Redaction (selective disclosure)
# --------------------------------------------------------------------------- #

def mask_from_patterns(patterns: List[str], text: str) -> List[int]:
    """Sorted char indices covered by any match of the given regex patterns."""
    specs = [nfa.compile_pattern(p) for p in patterns]
    return nfa.mask_indices(specs, text)


def spec_spans(spec: Dict, text: str) -> List[Tuple[int, int]]:
    """Merged match spans across every pattern_block constraint in the spec."""
    spans: List[Tuple[int, int]] = []
    for c in spec["constraints"]:
        if c["kind"] == "pattern_block":
            for s in c["nfa"]["compiled"]:
                spans.extend(nfa.find_spans(s, text))
    return nfa.merge_spans(spans)


def spans_valid(spec: Dict, text: str, spans: List[Tuple[int, int]]) -> bool:
    """Every span must be a genuine full match of some pattern_block pattern."""
    comps = [s for c in spec["constraints"] if c["kind"] == "pattern_block"
             for s in c["nfa"]["compiled"]]
    for (lo, hi) in spans:
        if not any(nfa.anchored_full_match(s, text, lo, hi) for s in comps):
            return False
    return True


def mask_covered(mask: List[int], spans: List[Tuple[int, int]]) -> bool:
    """Every masked index lies inside some span (mask ⊆ spans)."""
    return all(any(lo <= m < hi for lo, hi in spans) for m in mask)


def redact(text: str, mask: List[int], char: str = MASK_CHAR) -> str:
    """Return ``text`` with the given indices replaced by ``char``."""
    ms = set(mask)
    return "".join(char if i in ms else ch for i, ch in enumerate(text))


def redaction_ok(response: str, redacted: str, mask: List[int],
                 char: str = MASK_CHAR) -> bool:
    """VDR-style check: equal length, masked positions hold ``char``, all other
    positions are unchanged. Returns False on any out-of-range mask index."""
    if len(response) != len(redacted):
        return False
    n = len(response)
    ms = set(mask)
    if any(i < 0 or i >= n for i in mask):
        return False
    for i, (a, b) in enumerate(zip(response, redacted)):
        if i in ms:
            if b != char:
                return False
        elif a != b:
            return False
    return True


def private_output(spec: Dict, response: str,
                   mask: Optional[List[int]] = None,
                   redacted: Optional[str] = None,
                   spans: Optional[List[Tuple[int, int]]] = None,
                   tool_calls: Optional[List[Dict]] = None,
                   token_count: Optional[int] = None) -> Dict:
    """Build the dict matching ``pop-types::PrivateOutput`` (golden).

    ``spans`` are witness match spans (char ranges) proving that masked
    positions are inside genuine pattern matches: ``mask_covered`` is true iff
    every span is a real match and every masked index lies in a span.
    """
    vs = canonical_violations(spec, response, tool_calls, token_count)
    violations = [{"rule": v["rule"], "kind": v["kind"],
                   "evidence_commitment": evidence_commitment(v["evidence"])} for v in vs]
    redaction = None
    if redacted is not None:
        m = sorted(mask or [])
        sp = [tuple(s) for s in (spans or [])]
        covered = spans_valid(spec, response, sp) and mask_covered(m, sp)
        redaction = {
            "redacted_commitment": commitment(redacted),
            "mask_count": len(m),
            "redaction_ok": redaction_ok(response, redacted, m),
            "mask_covered": covered,
        }
    return {
        "response_commitment": commitment(response),
        "passed": len(vs) == 0,
        "violations": violations,
        "redaction": redaction,
    }


# --------------------------------------------------------------------------- #
# Evidence opening (selective disclosure to an auditor)
# --------------------------------------------------------------------------- #

def open_evidence(commitment_hex: str, fragment: str) -> bool:
    """Verify that ``fragment`` opens ``commitment_hex`` (sha256 match)."""
    return evidence_commitment(fragment) == commitment_hex


def evidence_bundle(spec: Dict, response: str) -> List[Dict]:
    """Authorized full disclosure: each violation with its plaintext evidence and
    the matching commitment (so an auditor can check against the proof)."""
    out = []
    for v in canonical_violations(spec, response):
        out.append({
            "rule": v["rule"], "kind": v["kind"],
            "evidence": v["evidence"],
            "evidence_commitment": evidence_commitment(v["evidence"]),
        })
    return out


def verify_bundle(bundle: List[Dict]) -> bool:
    """Every entry's commitment must equal sha256(evidence)."""
    return all(open_evidence(e["evidence_commitment"], e["evidence"]) for e in bundle)
