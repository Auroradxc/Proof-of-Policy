"""PII patterns and check-digit validators (reference layer).

Patterns are expressed in the Proof-of-Policy NFA subset (ASCII semantics,
see ``policydsl.nfa``). The values here are the canonical source; a policy
pack can be generated from them (see ``scripts/`` / the ``pii_redaction_v1``
pack) so the strings never drift.

Check-digit validators (IBAN MOD-97) are pure algorithmic helpers: regex can
only capture *shape*, the checksum is a separate reference function. Wiring
checksum verification into a dedicated constraint kind is future work (not in
the Phase 1-3 MVP constraint set).
"""

from __future__ import annotations

from . import nfa

# Canonical PII patterns (all within the supported NFA subset).
PII_PATTERNS = {
    "email": r"[\w.+-]+@[\w-]+\.[\w.]+",
    "phone": r"\+?[0-9 ()-]{7,}",
    "secret_key": r"sk-[A-Za-z0-9]{16,}",
    "bearer_token": r"Bearer [A-Za-z0-9._~+/=-]{16,}",
}

# Eager compile-check: raise at import time if a pattern is not supported.
_NFA_CACHE = {name: nfa.compile_pattern(pat) for name, pat in PII_PATTERNS.items()}


def compiled_pattern(name: str) -> dict:
    """Return the cached compiled NFA spec for a named PII pattern."""
    if name not in _NFA_CACHE:
        raise KeyError(f"unknown PII pattern '{name}' (have {sorted(_NFA_CACHE)})")
    return _NFA_CACHE[name]


def contains(name: str, text: str) -> bool:
    """True if ``text`` contains a match of the named PII pattern."""
    return nfa.match_search(compiled_pattern(name), text)


def pattern_names() -> list[str]:
    return sorted(PII_PATTERNS)


# --------------------------------------------------------------------------- #
# Check-digit validators
# --------------------------------------------------------------------------- #

def iban_mod97(iban: str) -> int:
    """ISO 7064 MOD-97-10 of an IBAN; returns the remainder (0..96)."""
    s = iban.replace(" ", "").upper()
    if len(s) < 5:
        raise ValueError("IBAN too short")
    rearranged = s[4:] + s[:4]
    digits = "".join(str(ord(ch) - 55) if "A" <= ch <= "Z" else ch for ch in rearranged)
    if not digits.isdigit():
        raise ValueError("IBAN contains invalid characters")
    return int(digits) % 97


def is_valid_iban(iban: str) -> bool:
    """A valid IBAN has MOD-97 remainder 1."""
    try:
        return iban_mod97(iban) == 1
    except ValueError:
        return False
