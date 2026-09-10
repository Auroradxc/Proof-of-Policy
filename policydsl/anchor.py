"""Append-only, tamper-evident anchor ledger for compliance certificates.

Each entry chains to the previous one:

    {"seq": n, "prev": <hash of previous entry|"genesis">, "digest": <cert digest>,
     "ts": "...", "meta": {...}, "hash": <hash of this entry without "hash">}

``verify_ledger`` recomputes the chain and detects any edit/reorder/deletion.
This is the executable stand-in for on-chain anchoring: an RPC backend can post
the same entry (see the ``anchor_on_chain`` hook) while the file backend keeps
local, testable behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .cert import canonical, sha256_hex, utc_now

GENESIS = "genesis"


def _entry_hash(entry: Dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return sha256_hex(canonical(body))


def read_ledger(path: Path) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    out: List[Dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def append_anchor(path: Path, digest: str, meta: Optional[Dict[str, Any]] = None,
                  ts: Optional[str] = None) -> Dict[str, Any]:
    """Append one anchor entry for ``digest`` and return it."""
    entries = read_ledger(path)
    prev = entries[-1]["hash"] if entries else GENESIS
    entry = {
        "seq": len(entries),
        "prev": prev,
        "digest": digest,
        "ts": ts or utc_now(),
        "meta": meta or {},
    }
    entry["hash"] = _entry_hash(entry)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def verify_ledger(path: Path) -> Tuple[bool, str]:
    """Recompute the chain; return (ok, reason)."""
    prev = GENESIS
    for i, e in enumerate(read_ledger(path)):
        if e.get("seq") != i:
            return False, f"entry {i}: bad seq {e.get('seq')}"
        if e.get("prev") != prev:
            return False, f"entry {i}: prev mismatch"
        if e.get("hash") != _entry_hash(e):
            return False, f"entry {i}: hash mismatch (tampered)"
        prev = e["hash"]
    return True, "ok"


def find_anchor(path: Path, digest: str) -> Optional[Dict[str, Any]]:
    for e in read_ledger(path):
        if e.get("digest") == digest:
            return e
    return None


def anchor_on_chain(digest: str, rpc_url: Optional[str] = None,
                    contract: Optional[str] = None) -> Dict[str, Any]:
    """Post the digest on-chain (stub).

    The file ledger is the default, offline-verifiable backend. A real
    deployment posts ``digest`` as calldata/an event of an anchor contract via
    ``rpc_url``; this hook raises a clear error until such a backend is wired,
    so callers do not silently believe an anchor happened.
    """
    raise NotImplementedError(
        "on-chain anchoring backend not configured: pass a chain adapter "
        "(RPC/contract) or use the file ledger backend for offline verification")
