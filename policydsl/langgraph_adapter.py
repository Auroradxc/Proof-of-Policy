"""LangGraph integration for Proof-of-Policy.

Two supported wiring styles (both exercise the same ``AgentMonitor``):

1. **Callbacks** (no graph edits): LangGraph routes LangChain callbacks, so:

       handler = attach(monitor)                       # PoPCallbackHandler
       graph.invoke(state, config={"callbacks": [handler]})
       # handler.certificates now holds one cert per LLM/tool event

2. **Node wrapping** (explicit, framework-native): wrap a generation or tool
   node so its output is judged and the certificate is added to the state:

       generate = guard_node(monitor, my_generate_node, kind="generate", key="output")
       tool     = guard_node(monitor, my_tool_node, kind="tool")

LangGraph itself is optional; ``require_langgraph()`` raises a clear error when
it is needed but absent, and the helpers below work on plain callables so they
can be unit-tested without LangGraph.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .agent import AgentMonitor
from .langchain_adapter import PoPCallbackHandler, langgraph_available  # noqa: F401


def require_langgraph() -> Any:
    """Import langgraph or fail with an actionable message."""
    try:
        import langgraph  # noqa: F401

        return langgraph
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            "LangGraph is not installed. Install with `pip install langgraph langchain` "
            "(see requirements-frameworks.txt); the AgentMonitor hooks and the "
            "guard_node/attach helpers need no adapter rewrite."
        ) from exc


def attach(monitor: AgentMonitor, graph: Any = None, **handler_kwargs: Any) -> PoPCallbackHandler:
    """Return a callback handler for ``graph.invoke(..., config={"callbacks":[h]})``.

    ``graph`` is accepted for readability but not mutated (compiled LangGraph
    graphs are immutable); callers pass the handler in the invoke config.
    """
    return PoPCallbackHandler(monitor, **handler_kwargs)


def guard_node(monitor: AgentMonitor, node: Callable[..., Any], kind: str = "generate",
               key: str = "output", certs_key: str = "certificates",
               vkey_hash: str = "unproven", proof_sha256: Optional[str] = None,
               tool_name_key: str = "name", tool_args_key: str = "args") -> Callable[..., Dict[str, Any]]:
    """Wrap a LangGraph node so its result is judged and certified.

    kind="generate": reads ``result[key]`` as the response text.
    kind="tool":     reads ``result[tool_name_key]`` / ``result[tool_args_key]``.
    The returned dict is the original node result plus ``certs_key`` (list).
    """

    def wrapped(state: Any, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        result = node(state, *args, **kwargs)
        if not isinstance(result, dict):
            result = {key: result}
        certs: List[Dict[str, Any]] = list(result.get(certs_key, []))
        if kind == "generate":
            raw = result.get(key, "")
            text = raw if isinstance(raw, str) else str(raw)
            certs.append(monitor.on_generate(text, vkey_hash=vkey_hash,
                                             proof_sha256=proof_sha256))
        elif kind == "tool":
            name = str(result.get(tool_name_key, "tool"))
            targs = result.get(tool_args_key, {}) or {}
            certs.append(monitor.on_tool_call(name, targs, vkey_hash=vkey_hash))
        else:
            raise ValueError("kind must be 'generate' or 'tool'")
        out = dict(result)
        out[certs_key] = certs
        return out

    return wrapped


class LangGraphGuard:
    """Convenience wrapper binding one monitor to node factories."""

    def __init__(self, monitor: AgentMonitor, **handler_kwargs: Any):
        self.monitor = monitor
        self._handler_kwargs = handler_kwargs

    def callbacks(self) -> PoPCallbackHandler:
        return attach(self.monitor, **self._handler_kwargs)

    def generate_node(self, node: Callable[..., Any], **kw: Any) -> Callable[..., Dict[str, Any]]:
        return guard_node(self.monitor, node, kind="generate", **kw)

    def tool_node(self, node: Callable[..., Any], **kw: Any) -> Callable[..., Dict[str, Any]]:
        return guard_node(self.monitor, node, kind="tool", **kw)
