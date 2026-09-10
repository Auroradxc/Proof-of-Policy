"""Compliance certificates for Proof-of-Policy.

A certificate binds, for one agent response/tool-call:

    policy (id/version) + policy_hash (ConstraintSpec sha256)
    + the committed outcome (ProofOutput / PrivateOutput)
    + the program vkey hash and the proof artifact hash
    + a timestamp, and the EU AI Act Art.12/13 claims

It is wrapped in a **DSSE-like envelope** (payloadType + base64 payload +
signatures). The default signer is HMAC-SHA256 (`demo-hmac-sha256`) — a
stdlib-only placeholder; swap for Ed25519 in deployment (the envelope structure
is unchanged).

Because the payload is deterministic (canonical JSON), the certificate hashes
to a stable ``cert_digest`` that can be anchored (see ``policydsl.anchor``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

CERT_VERSION = "v1"
PAYLOAD_TYPE = "application/vnd.proof-of-policy+json"
DEFAULT_KEYID = "demo-hmac-sha256"
# Shared demo signing key (stdlib HMAC). Replace with a real key/Ed25519 in deployment.
DEMO_KEY = b"proof-of-policy-demo-key"


def canonical(obj: Any) -> bytes:
    """Canonical JSON bytes (sorted keys, compact, UTF-8)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ai_act_claims(mode: str) -> Dict[str, Any]:
    """EU AI Act linkage carried by the certificate.

    Art.12 (record-keeping): each certificate is a tamper-evident, per-call
    audit record (anchored). Art.13 (transparency): the policy hash + mode +
    outcome make the system's declared behaviour verifiable by third parties.
    """
    return {
        "art12_record_keeping": {
            "per_call_record": True,
            "policy_hash_bound": True,
            "anchored": True,
        },
        "art13_transparency": {
            "policy_disclosed": True,
            "mode": mode,  # "public" (response public) | "private" (commitment only)
            "outcome_disclosed": True,
        },
    }


def build_payload(policy_id: str, policy_version: str, spec: Dict, mode: str,
                  outcome: Dict, vkey_hash: str,
                  proof_sha256: Optional[str] = None,
                  ts: Optional[str] = None) -> Dict[str, Any]:
    """Assemble the certificate payload (deterministic given inputs + ts)."""
    return {
        "cert_version": CERT_VERSION,
        "policy": {"id": policy_id, "version": policy_version},
        "policy_hash": spec["sha256"],
        "mode": mode,
        "outcome": outcome,
        "binding": {"vkey_hash": vkey_hash, "proof_sha256": proof_sha256},
        "ai_act": ai_act_claims(mode),
        "ts": ts or utc_now(),
    }


def cert_digest(payload: Dict[str, Any]) -> str:
    """Stable digest of the payload (the anchor value)."""
    return sha256_hex(canonical(payload))


def sign_payload(payload: Dict[str, Any], key: bytes,
                 keyid: str = DEFAULT_KEYID) -> Dict[str, Any]:
    """Wrap the payload in a DSSE-like envelope signed with HMAC-SHA256."""
    payload_bytes = canonical(payload)
    sig = hmac.new(key, payload_bytes, hashlib.sha256).digest()
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": [{"keyid": keyid, "sig": base64.b64encode(sig).decode("ascii")}],
    }


def envelope_keyid(env: Dict[str, Any]) -> Optional[str]:
    sigs = env.get("signatures") or []
    return sigs[0].get("keyid") if sigs else None


def envelope_payload(env: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(base64.b64decode(env["payload"]).decode("utf-8"))


def verify_envelope(env: Dict[str, Any], key: bytes) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Verify the envelope signature; return (ok, payload)."""
    try:
        payload_bytes = base64.b64decode(env["payload"])
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (KeyError, ValueError):
        return False, None
    sigs = env.get("signatures") or []
    if not sigs:
        return False, None
    expected = hmac.new(key, payload_bytes, hashlib.sha256).digest()
    got = base64.b64decode(sigs[0]["sig"])
    return hmac.compare_digest(expected, got), payload
