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
import json
from typing import Any, Dict, List, Optional, Tuple

from .agent import AgentMonitor


class MCPBlocked(Exception):
    """Raised when a tool call/result violates policy and blocking is enabled."""

    def __init__(self, tool: str, violations: List[Dict[str, Any]], phase: str = "args"):
        super().__init__(f"tool '{tool}' blocked by policy at {phase}: {violations}")
        self.tool = tool
        self.violations = violations
        self.phase = phase


def extract_result_text(result: Any) -> str:
    """Best-effort text from an MCP CallToolResult / content list / plain value."""
    content = getattr(result, "content", None)
    if content is None and isinstance(result, dict):
        content = result.get("content")
    if content is not None:
        parts: List[str] = []
        for item in content:
            if isinstance(item, dict):
                if item.get("type") == "text" and isinstance(item.get("text"), str):
                    parts.append(item["text"])
            else:
                text = getattr(item, "text", None)
                if isinstance(text, str):
                    parts.append(text)
        if parts:
            return "".join(parts)
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception:
        return str(result)


class MCPGuard:
    """Certify MCP tool calls (arguments) and, optionally, their results.

    ``result_monitor`` (a content-policy ``AgentMonitor``) judges the tool's
    *returned text* and issues a ``tool-result`` certificate; with
    ``block_on_result_violation=True`` a violating result is rejected after the
    call (raising ``MCPBlocked`` with ``phase="result"``).
    """

    def __init__(self, monitor: AgentMonitor, vkey_hash: str = "unproven",
                 block_on_violation: bool = False, on_cert=None,
                 result_monitor: Optional[AgentMonitor] = None,
                 block_on_result_violation: bool = False, on_result_cert=None):
        self.monitor = monitor
        self.vkey_hash = vkey_hash
        self.block_on_violation = block_on_violation
        self.on_cert = on_cert
        self.certificates: List[Dict[str, Any]] = []
        self.result_monitor = result_monitor
        self.block_on_result_violation = block_on_result_violation
        self.on_result_cert = on_result_cert
        self.result_certificates: List[Dict[str, Any]] = []

    def check(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Judge arguments and return the certificate envelope (no tool call)."""
        env = self.monitor.on_tool_call(name, arguments or {}, vkey_hash=self.vkey_hash)
        self.certificates.append(env)
        if self.on_cert is not None:
            self.on_cert(env)
        return env

    def judge_result(self, name: str, result: Any) -> Optional[Dict[str, Any]]:
        """Judge the tool's returned text (if a result monitor is configured)."""
        if self.result_monitor is None:
            return None
        text = extract_result_text(result)
        env = self.result_monitor.on_generate(
            text, vkey_hash=self.vkey_hash,
            extra={"tool": {"name": name, "phase": "result"}})
        self.result_certificates.append(env)
        if self.on_result_cert is not None:
            self.on_result_cert(env)
        return env

    @staticmethod
    def _violations(env: Dict[str, Any]) -> List[Dict[str, Any]]:
        from .cert import envelope_payload

        return envelope_payload(env)["outcome"]["violations"]

    async def call_tool(self, session: Any, name: str,
                        arguments: Optional[Dict[str, Any]] = None) -> Tuple[Any, Dict[str, Any]]:
        """Certify args, run the tool, then certify the result text.

        Returns ``(result, args_cert)``; the result certificate (if any) is in
        ``self.result_certificates``.
        """
        env = self.check(name, arguments)
        if self.block_on_violation:
            violations = self._violations(env)
            if violations:
                raise MCPBlocked(name, violations, phase="args")
        result = await session.call_tool(name, arguments or {})
        renv = self.judge_result(name, result)
        if renv is not None and self.block_on_result_violation:
            violations = self._violations(renv)
            if violations:
                raise MCPBlocked(name, violations, phase="result")
        return result, env

    def call_tool_sync(self, session: Any, name: str,
                       arguments: Optional[Dict[str, Any]] = None) -> Tuple[Any, Dict[str, Any]]:
        """Sync convenience wrapper (no running event loop required)."""
        return asyncio.run(self.call_tool(session, name, arguments))
