"""MCP (Model Context Protocol) guard for Proof-of-Policy.

Wraps a real MCP client session so that every tool invocation is judged by the
policy **before** it runs and certified:

    guard = MCPGuard(monitor, block_on_violation=True)
    result, cert = await guard.call_tool(session, "search_kb", {"query": "x"})

- arguments are checked via ``AgentMonitor.on_tool_call`` (tool_arg_guard /
  budget_bound) and a certificate is produced for each call;
- with ``block_on_violation=True`` a violating call is rejected *before* it
  reaches the server (pre-flight guard), raising ``MCPBlocked``;
- the same class works with any object exposing ``async call_tool(name, args)``
  (the real ``mcp.ClientSession`` or a fake in tests).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Tuple

from .agent import AgentMonitor


class MCPBlocked(Exception):
    """Raised when a tool call violates policy and blocking is enabled."""

    def __init__(self, tool: str, violations: List[Dict[str, Any]]):
        super().__init__(f"tool '{tool}' blocked by policy: {violations}")
        self.tool = tool
        self.violations = violations


class MCPGuard:
    def __init__(self, monitor: AgentMonitor, vkey_hash: str = "unproven",
                 block_on_violation: bool = False, on_cert=None):
        self.monitor = monitor
        self.vkey_hash = vkey_hash
        self.block_on_violation = block_on_violation
        self.on_cert = on_cert
        self.certificates: List[Dict[str, Any]] = []

    def check(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Judge arguments and return the certificate envelope (no tool call)."""
        env = self.monitor.on_tool_call(name, arguments or {}, vkey_hash=self.vkey_hash)
        self.certificates.append(env)
        if self.on_cert is not None:
            self.on_cert(env)
        return env

    @staticmethod
    def _violations(env: Dict[str, Any]) -> List[Dict[str, Any]]:
        from .cert import envelope_payload

        return envelope_payload(env)["outcome"]["violations"]

    async def call_tool(self, session: Any, name: str,
                        arguments: Optional[Dict[str, Any]] = None) -> Tuple[Any, Dict[str, Any]]:
        """Certify then run the tool through ``session``. Returns (result, cert)."""
        env = self.check(name, arguments)
        if self.block_on_violation:
            violations = self._violations(env)
            if violations:
                raise MCPBlocked(name, violations)
        result = await session.call_tool(name, arguments or {})
        return result, env

    def call_tool_sync(self, session: Any, name: str,
                       arguments: Optional[Dict[str, Any]] = None) -> Tuple[Any, Dict[str, Any]]:
        """Sync convenience wrapper (no running event loop required)."""
        return asyncio.run(self.call_tool(session, name, arguments))
