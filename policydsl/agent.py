"""Framework-agnostic agent instrumentation hooks for Proof-of-Policy.

An ``AgentMonitor`` wraps a policy and issues a compliance certificate for:
  - the **generation path** (``on_generate``): a response is judged by the
    in-circuit rule kinds (keyword/length/pattern) and a certificate is built;
  - the **tool-call path** (``on_tool_call``): a tool invocation is judged by the
    Python reference layer (tool_arg_guard / budget_bound) — not yet provable
    in-circuit, so those certificates are marked ``zk: false``.

Real frameworks (LangGraph / MCP) plug into these two hooks; see
``policydsl.langgraph_adapter``. ``mock_agent()`` yields a deterministic session
for demos/tests without any LLM dependency.
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import cert, commit
from .compile import compile_policy
from .evaluate import check
from .model import Policy, PolicyError, ToolCall, Transcript

DEFAULT_KEY = cert.DEMO_KEY


class AgentMonitor:
    def __init__(self, policy: Policy, mode: str = "public", key: bytes = DEFAULT_KEY,
                 keyid: str = cert.DEFAULT_KEYID):
        if mode not in ("public", "private"):
            raise ValueError("mode must be 'public' or 'private'")
        self.policy = policy
        self.mode = mode
        self.key = key
        self.keyid = keyid
        self.spec = compile_policy(policy)

    # -- generation path (in-circuit kinds) --
    def generate_outcome(self, response: str, mask: Optional[List[int]] = None,
                         redacted: Optional[str] = None,
                         spans: Optional[List[Tuple[int, int]]] = None) -> Dict[str, Any]:
        """The committed outcome (mirrors the SP1 public values)."""
        if self.mode == "public":
            vs = commit.canonical_violations(self.spec, response)
            return {"passed": len(vs) == 0,
                    "violations": [{"rule": v["rule"], "kind": v["kind"],
                                    "evidence": v["evidence"]} for v in vs]}
        return commit.private_output(self.spec, response, mask, redacted, spans)

    def on_generate(self, response: str, ts: Optional[str] = None,
                    vkey_hash: str = "unproven", proof_sha256: Optional[str] = None,
                    mask: Optional[List[int]] = None, redacted: Optional[str] = None,
                    spans: Optional[List[Tuple[int, int]]] = None,
                    extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        outcome = self.generate_outcome(response, mask, redacted, spans)
        payload = cert.build_payload(self.policy.id, self.policy.version, self.spec,
                                     self.mode, outcome, vkey_hash, proof_sha256, ts,
                                     extra=extra)
        return cert.sign_payload(payload, self.key, self.keyid)

    # -- tool-call path (Python reference kinds) --
    def tool_call_outcome(self, name: str, args: Dict[str, Any],
                          response: Optional[str] = None) -> Dict[str, Any]:
        """Judge a tool call. ``tool_arg_guard``/``budget_bound`` are now
        in-circuit rule kinds, so the outcome is marked ``zk: True``; whether a
        *proof* is attached is indicated separately by the certificate's
        ``binding.vkey_hash`` (``unproven`` when no proof was generated)."""
        tx = Transcript(response=response, tool_calls=[ToolCall(name, args)])
        try:
            res = check(self.policy, tx)
        except PolicyError as exc:
            raise PolicyError(f"tool-call check needs a response for content rules: {exc}") from exc
        return {"passed": res.passed, "zk": True,
                "violations": [{"rule": v.rule.name, "kind": v.rule.kind,
                                "evidence_kind": v.evidence_kind, "evidence": v.evidence}
                               for v in res.violations]}

    def on_tool_call(self, name: str, args: Dict[str, Any], ts: Optional[str] = None,
                     response: Optional[str] = None, vkey_hash: str = "unproven") -> Dict[str, Any]:
        outcome = self.tool_call_outcome(name, args, response)
        payload = cert.build_payload(self.policy.id, self.policy.version, self.spec,
                                     "tool-call", outcome, vkey_hash, None, ts)
        return cert.sign_payload(payload, self.key, self.keyid)


def mock_agent() -> Iterator[Tuple[str, Any]]:
    """A deterministic, LLM-free 'agent session': a tool call then a response."""
    yield ("tool_call", ("search_kb", {"query": "refund policy", "token": "sk-abcdefghijklmnopqrstuvwxyz"}))
    yield ("generate", "Here is the refund policy summary. Contact support for details.")
