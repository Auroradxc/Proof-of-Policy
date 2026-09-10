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
    """Issue certificates on LLM end and tool end events."""

    def __init__(self, monitor: AgentMonitor, vkey_hash: str = "unproven",
                 proof_sha256: Optional[str] = None, on_cert=None):
        super().__init__()
        self.monitor = monitor
        self.vkey_hash = vkey_hash
        self.proof_sha256 = proof_sha256
        self.on_cert = on_cert
        self.certificates: List[Dict[str, Any]] = []
        self._tool_starts: Dict[str, Dict[str, Any]] = {}

    # -- helpers --
    def _emit(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        self.certificates.append(envelope)
        if self.on_cert is not None:
            self.on_cert(envelope)
        return envelope

    # -- LLM (generation path) --
    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        text = _extract_text(response)
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
