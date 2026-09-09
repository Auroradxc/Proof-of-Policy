"""Serialize a ConstraintSpec into the Rust-side ProofRequest constraint list.

The ConstraintSpec (produced by ``compile_policy``) is the cross-layer
contract. This module maps its constraints to the serde externally-tagged
``pop_types::Constraint`` JSON consumed by the SP1 driver and program.

In-circuit rule kinds (Phase 1-3 MVP): keyword_block, length_bound,
pattern_block. Anything else raises ``NotImplementedError`` (it exists only in
the Python reference layer for now and is not provable in-circuit yet).
"""

from __future__ import annotations

from typing import Dict, List


def spec_to_rust_constraints(spec: Dict) -> List[Dict]:
    """Map spec constraints to ``pop_types::Constraint`` serde enum JSON."""
    out: List[Dict] = []
    for c in spec["constraints"]:
        kind = c["kind"]
        name = c["name"]
        if kind == "keyword_block":
            out.append({"KeywordBlock": {"name": name, "keywords": c["keywords"]}})
        elif kind == "length_bound":
            out.append({"LengthBound": {"name": name, "min": c["min"], "max": c["max"]}})
        elif kind == "pattern_block":
            out.append({"PatternBlock": {
                "name": name,
                "patterns": c["patterns"],
                "specs": c["nfa"]["compiled"],
            }})
        else:
            raise NotImplementedError(
                f"kind '{kind}' (rule '{name}') is not yet provable in-circuit "
                "(Phase 1-3 supports keyword_block/length_bound/pattern_block)")
    return out


def build_vectors(entries: List[Dict]) -> Dict:
    """Wrap list of {name, response, constraints[]} into a vectors file dict."""
    return {"vectors": entries}
