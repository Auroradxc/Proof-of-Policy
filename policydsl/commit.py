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


def canonical_violations(spec: Dict, response: str) -> List[Dict]:
    """Mirror ``pop-types::evaluate`` exactly, returning (rule, kind, evidence).

    Used so the private-mode golden (with committed evidence) matches the
    in-circuit judging field-for-field.
    """
    lower = _ascii_lower(response)
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
                   redacted: Optional[str] = None) -> Dict:
    """Build the dict matching ``pop-types::PrivateOutput`` (golden)."""
    vs = canonical_violations(spec, response)
    violations = [{"rule": v["rule"], "kind": v["kind"],
                   "evidence_commitment": evidence_commitment(v["evidence"])} for v in vs]
    redaction = None
    if redacted is not None:
        m = sorted(mask or [])
        redaction = {
            "redacted_commitment": commitment(redacted),
            "mask_count": len(m),
            "redaction_ok": redaction_ok(response, redacted, m),
        }
    return {
        "response_commitment": commitment(response),
        "passed": len(vs) == 0,
        "violations": violations,
        "redaction": redaction,
    }
