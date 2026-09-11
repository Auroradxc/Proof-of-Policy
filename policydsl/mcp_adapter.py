"""Proof-of-Policy 的 MCP（Model Context Protocol）守护。

包装一个真实 MCP 客户端会话，使每次工具调用在**执行前**就被策略判定并签发证书：

    guard = MCPGuard(monitor, block_on_violation=True)
    result, cert = await guard.call_tool(session, "search_kb", {"query": "x"})

- 参数经由 ``AgentMonitor.on_tool_call`` 检查（tool_arg_guard / budget_bound），
  每次调用产出一张证书；
- 当 ``block_on_violation=True`` 时，违规调用会在到达服务器**之前**被拒绝
  （飞行前守护），并抛出 ``MCPBlocked``；
- 该类对任何暴露 ``async call_tool(name, args)`` 的对象都适用
  （真实的 ``mcp.ClientSession`` 或测试里的 fake）。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional, Tuple

from .agent import AgentMonitor


class MCPBlocked(Exception):
    """当工具调用/结果违反策略且启用拦截时抛出。"""

    def __init__(self, tool: str, violations: List[Dict[str, Any]], phase: str = "args"):
        super().__init__(f"tool '{tool}' blocked by policy at {phase}: {violations}")
        self.tool = tool
        self.violations = violations
        self.phase = phase


def extract_result_text(result: Any) -> str:
    """从 MCP CallToolResult / content 列表 / 普通值里尽力提取文本。"""
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
    """为 MCP 工具调用（参数）及（可选的）其结果签发证书。

    ``result_monitor``（一个内容策略 ``AgentMonitor``）判定工具的*返回文本*，
    并签发 ``tool-result`` 证书；当 ``block_on_result_violation=True`` 时，
    违规结果在调用后被拒绝（抛 ``MCPBlocked``，``phase="result"``）。
    """

    def __init__(self, monitor: AgentMonitor, vkey_hash: str = "unproven",
                 block_on_violation: bool = False, on_cert=None,
                 result_monitor: Optional[AgentMonitor] = None,
                 block_on_result_violation: bool = False, on_result_cert=None,
                 proof_mode: Optional[str] = None):
        self.monitor = monitor
        self.vkey_hash = vkey_hash
        # 诚实标注（P0-4）：本 guard 签出的证书属于哪一档证明模式；
        # None → build_payload 按「未附工件」记 unproven。
        self.proof_mode = proof_mode
        self.block_on_violation = block_on_violation
        self.on_cert = on_cert
        self.certificates: List[Dict[str, Any]] = []
        self.result_monitor = result_monitor
        self.block_on_result_violation = block_on_result_violation
        self.on_result_cert = on_result_cert
        self.result_certificates: List[Dict[str, Any]] = []

    def check(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """判定参数并返回证书信封（不真正调用工具）。"""
        env = self.monitor.on_tool_call(name, arguments or {}, vkey_hash=self.vkey_hash,
                                        proof_mode=self.proof_mode)
        self.certificates.append(env)
        if self.on_cert is not None:
            self.on_cert(env)
        return env

    def judge_result(self, name: str, result: Any) -> Optional[Dict[str, Any]]:
        """判定工具返回文本（仅在配置了 result_monitor 时）。"""
        if self.result_monitor is None:
            return None
        text = extract_result_text(result)
        env = self.result_monitor.on_generate(
            text, vkey_hash=self.vkey_hash, proof_mode=self.proof_mode,
            extra={"tool": {"name": name, "phase": "result"}})
        self.result_certificates.append(env)
        if self.on_result_cert is not None:
            self.on_result_cert(env)
        return env

    @staticmethod
    def _violations(env: Dict[str, Any]) -> List[Dict[str, Any]]:
        """从证书信封里取出违规列表。"""
        from .cert import envelope_payload

        return envelope_payload(env)["outcome"]["violations"]

    async def call_tool(self, session: Any, name: str,
                        arguments: Optional[Dict[str, Any]] = None) -> Tuple[Any, Dict[str, Any]]:
        """签参数证书 → 真正调用工具 → 签结果证书。

        返回 ``(result, args_cert)``；结果证书（若有）在
        ``self.result_certificates`` 里。
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
        """同步便捷封装（无需运行中的事件循环）。"""
        return asyncio.run(self.call_tool(session, name, arguments))
