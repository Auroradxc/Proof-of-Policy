"""Optional LangGraph adapter for Proof-of-Policy.

The monitor hooks (``AgentMonitor.on_generate`` / ``on_tool_call``) are
framework-agnostic. For a real LangGraph graph, wire them where the graph
produces content:

    from policydsl.agent import AgentMonitor
    monitor = AgentMonitor(policy, mode="public")

    def generate_node(state):
        text = llm(state["messages"])
        cert = monitor.on_generate(text, vkey_hash=VKEY, proof_sha256=PROOF_HASH)
        state["certificates"].append(cert)
        return {"output": text, **state}

    def tool_node(state):
        call = state["tool_call"]
        cert = monitor.on_tool_call(call["name"], call["args"])
        ...

LangGraph is NOT a dependency of this repo; ``attach`` fails with a clear
message so the absence is never mistaken for a working integration.
"""

from __future__ import annotations

from typing import Any


def attach(monitor: Any, graph: Any) -> Any:
    """Best-effort attach for a LangGraph graph (documented wiring only)."""
    try:
        import langgraph  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            "LangGraph is not installed (pip install langgraph, network required). "
            "The AgentMonitor hooks are framework-agnostic — call "
            "monitor.on_generate / monitor.on_tool_call from your own graph nodes."
        ) from exc
    raise NotImplementedError(
        "LangGraph is installed, but this repository ships the hooks (AgentMonitor) "
        "rather than a pinned graph adapter. Wire on_generate/on_tool_call into the "
        "generation and tool nodes as shown in this module's docstring."
    )
