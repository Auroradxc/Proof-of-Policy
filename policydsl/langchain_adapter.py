"""LangChain callback handler that issues Proof-of-Policy certificates.

LangChain and LangGraph share the same callback system
(``langchain_core.callbacks``), so this single handler instruments **both**:

  - LangChain: ``chain.invoke(x, config={"callbacks": [handler]})``
  - LangGraph: ``graph.invoke(state, config={"callbacks": [handler]})``

On every LLM completion it issues a certificate for the generation path
(``AgentMonitor.on_generate``); on every finished tool call it issues a tool-path
certificate (``AgentMonitor.on_tool_call``).

The handler works without LangChain installed (duck-typed base) so it can be
unit-tested offline; when LangChain is present it subclasses the real
``BaseCallbackHandler`` and can be passed straight into callbacks configs.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional

from .agent import AgentMonitor
from . import cert as _cert

try:  # real LangChain when available
    from langchain_core.callbacks import BaseCallbackHandler  # type: ignore

    HAVE_LANGCHAIN = True
except Exception:  # pragma: no cover - depends on env
    HAVE_LANGCHAIN = False

    class BaseCallbackHandler:  # minimal duck-typed fallback
        raise_error = False


def langchain_available() -> bool:
    return HAVE_LANGCHAIN


def langgraph_available() -> bool:
    try:
        import langgraph  # noqa: F401

        return True
    except Exception:
        return False


def _extract_text(response: Any) -> str:
    """Best-effort text from an LLMResult / generations structure."""
    try:
        generations = getattr(response, "generations", None) or []
        if generations and generations[0]:
            gen = generations[0][0]
            text = getattr(gen, "text", None)
            if isinstance(text, str) and text:
                return text
            msg = getattr(gen, "message", None)
            if msg is not None:
                content = getattr(msg, "content", None)
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    parts = [p.get("text", "") if isinstance(p, dict) else str(p) for p in content]
                    return "".join(parts)
    except Exception:
        pass
    return ""


def _tool_name(serialized: Any, kwargs: Dict[str, Any]) -> str:
    if isinstance(serialized, dict) and serialized.get("name"):
        return str(serialized["name"])
    return str(kwargs.get("name") or "tool")


def _parse_args(input_str: Any) -> Dict[str, Any]:
    if isinstance(input_str, dict):
        return input_str
    if isinstance(input_str, str):
        try:
            val = ast.literal_eval(input_str)
            if isinstance(val, dict):
                return {str(k): v for k, v in val.items()}
        except (ValueError, SyntaxError):
            pass
        return {"input": input_str}
    return {"input": input_str}


class PoPCallbackHandler(BaseCallbackHandler):
    """Issue certificates on LLM end and tool end events.

    Streaming ("incremental") certificates: with ``stream_check=True`` (default),
    ``on_llm_new_token`` accumulates the response prefix and, whenever the
    compliance verdict *changes* (e.g. a secret pattern completes mid-stream),
    emits a **partial** certificate (``streaming.partial = true``) so a monitor
    can flag/stop early. The certificate emitted at ``on_llm_end`` remains the
    authoritative one.
    """

    def __init__(self, monitor: AgentMonitor, vkey_hash: str = "unproven",
                 proof_sha256: Optional[str] = None, on_cert=None,
                 stream_check: bool = True, stream_every: int = 1,
                 on_stream_cert=None, stop_on_violation: bool = False,
                 on_early_stop=None):
        super().__init__()
        self.monitor = monitor
        self.vkey_hash = vkey_hash
        self.proof_sha256 = proof_sha256
        self.on_cert = on_cert
        self.certificates: List[Dict[str, Any]] = []
        self._tool_starts: Dict[str, Dict[str, Any]] = {}
        # streaming state
        self.stream_check = stream_check
        self.stream_every = max(1, stream_every)
        self.on_stream_cert = on_stream_cert
        self.stop_on_violation = stop_on_violation
        self.on_early_stop = on_early_stop
        self.stream_certificates: List[Dict[str, Any]] = []
        self.stream_chains: Dict[str, List[str]] = {}   # run_id -> [payload digests]
        self._sbuf: Dict[str, str] = {}
        self._scount: Dict[str, int] = {}
        self._sverdict: Dict[str, bool] = {}
        self._sstopped: Dict[str, bool] = {}

    # -- helpers --
    def _emit(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        self.certificates.append(envelope)
        if self.on_cert is not None:
            self.on_cert(envelope)
        return envelope

    def stream_chain(self, run_id: str) -> List[str]:
        """Payload digests of the run's streaming certificate chain."""
        return list(self.stream_chains.get(run_id, []))

    def _stream_cert(self, run_id: str, text: str, partial: bool, extra_stream: Dict[str, Any]):
        """Emit a streaming cert linking to the previous one (chain)."""
        chain = self.stream_chains.setdefault(run_id, [])
        index = len(chain)
        prev = chain[-1] if chain else "genesis"
        stream = {"partial": partial, "tokens": self._scount.get(run_id, 0),
                  "chain": {"index": index, "prev": prev}}
        stream.update(extra_stream)
        env = self.monitor.on_generate(text, vkey_hash=self.vkey_hash,
                                       proof_sha256=self.proof_sha256,
                                       extra={"streaming": stream})
        chain.append(_cert_digest(env))
        return env

    # -- LLM (generation path) --
    def on_llm_new_token(self, token: str, **kwargs: Any) -> None:
        """Accumulate the streaming prefix; emit chained partial certs on verdict
        change, and (optionally) an early-stop cert on the first violation."""
        run_id = str(kwargs.get("run_id") or "")
        if self._sstopped.get(run_id):
            return  # early-stopped: ignore further tokens
        self._sbuf[run_id] = self._sbuf.get(run_id, "") + (token or "")
        self._scount[run_id] = self._scount.get(run_id, 0) + 1
        if not self.stream_check or self._scount[run_id] % self.stream_every != 0:
            return
        outcome = self.monitor.generate_outcome(self._sbuf[run_id])
        verdict = bool(outcome["passed"])
        prev = self._sverdict.get(run_id)
        if prev is None or prev != verdict:
            env = self._stream_cert(run_id, self._sbuf[run_id], partial=True, extra_stream={})
            self.stream_certificates.append(env)
            if self.on_stream_cert is not None:
                self.on_stream_cert(env)
            self._sverdict[run_id] = verdict
            if verdict is False and self.stop_on_violation:
                idx = len(self.stream_chains[run_id]) - 1
                stop_env = self._stream_cert(
                    run_id, self._sbuf[run_id], partial=False,
                    extra_stream={"stop": {"reason": "violation",
                                           "at_index": idx,
                                           "chain_head": self.stream_chains[run_id][idx]}})
                self.stream_certificates.append(stop_env)
                if self.on_early_stop is not None:
                    self.on_early_stop(stop_env)
                self._sstopped[run_id] = True

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        run_id = str(kwargs.get("run_id") or "")
        # prefer the streamed buffer (exact tokens seen); fall back to extraction
        text = self._sbuf.get(run_id) or _extract_text(response)
        self._sbuf.pop(run_id, None)
        self._scount.pop(run_id, None)
        self._sverdict.pop(run_id, None)
        self._sstopped.pop(run_id, None)
        if text:
            self._emit(self.monitor.on_generate(text, vkey_hash=self.vkey_hash,
                                                proof_sha256=self.proof_sha256))

    # -- Tools (tool-call path) --
    def on_tool_start(self, serialized: Any, input_str: Any, **kwargs: Any) -> None:
        run_id = str(kwargs.get("run_id") or "")
        self._tool_starts[run_id] = {"name": _tool_name(serialized, kwargs),
                                     "args": _parse_args(input_str)}

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        run_id = str(kwargs.get("run_id") or "")
        rec = self._tool_starts.pop(run_id, None) or {"name": _tool_name(None, kwargs), "args": {}}
        self._emit(self.monitor.on_tool_call(rec["name"], rec["args"],
                                             vkey_hash=self.vkey_hash))


def verify_certificates(handler: "PoPCallbackHandler", key: bytes = _cert.DEMO_KEY) -> bool:
    """All certificates emitted so far verify against ``key``."""
    return all(_cert.verify_envelope(env, key)[0] for env in handler.certificates)


def _cert_digest(env: Dict[str, Any]) -> str:
    return _cert.cert_digest(_cert.envelope_payload(env))


def verify_chain(certs: List[Dict[str, Any]]) -> bool:
    """Verify a streaming certificate chain (index sequence + prev linkage).

    Each certificate must carry ``streaming.chain = {index, prev}`` where index
    is its position and prev is the digest of the previous certificate
    (``"genesis"`` for the first). Detects reordering, insertion and tampering.
    """
    prev = "genesis"
    for i, env in enumerate(certs):
        payload = _cert.envelope_payload(env)
        chain = (payload.get("streaming") or {}).get("chain")
        if not chain or chain.get("index") != i or chain.get("prev") != prev:
            return False
        prev = _cert.cert_digest(payload)
    return True
