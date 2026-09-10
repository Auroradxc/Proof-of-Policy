"""Tests for the MCP tool guard (policydsl.mcp_adapter).

Offline tests use a fake session; the real test spawns a genuine MCP server over
stdio (tests/mcp_echo_server.py) and is skipped if the `mcp` SDK is absent.
"""

import asyncio
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import cert  # noqa: E402
from policydsl.agent import AgentMonitor  # noqa: E402
from policydsl.mcp_adapter import MCPBlocked, MCPGuard  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
SERVER = Path(__file__).resolve().parent / "mcp_echo_server.py"


def load_pack(name: str) -> Policy:
    data = json.loads((REPO / "policy_packs" / name).read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r["name"], params=r.get("params", {})) for r in data["rules"]]
    return Policy(data["id"], data.get("version", "0.1.0"), rules=rules)


def mcp_available() -> bool:
    try:
        import mcp  # noqa: F401

        return True
    except Exception:
        return False


class FakeSession:
    def __init__(self, result_text: str = None):
        self.calls = []
        self.result_text = result_text

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments))
        text = self.result_text if self.result_text is not None else f"ok:{name}"
        return {"content": [{"type": "text", "text": text}]}


class TestMCPGuardOffline(unittest.TestCase):
    def setUp(self):
        self.monitor = AgentMonitor(load_pack("agent_tool_v1.json"))

    def test_clean_call_certifies_and_runs(self):
        guard = MCPGuard(self.monitor, vkey_hash="vk")
        session = FakeSession()
        result, env = asyncio.run(guard.call_tool(session, "search_kb", {"query": "refund"}))
        self.assertEqual(len(session.calls), 1)
        ok, payload = cert.verify_envelope(env, cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertEqual(payload["mode"], "tool-call")
        self.assertTrue(payload["outcome"]["passed"])

    def test_blocking_prevents_violating_call(self):
        guard = MCPGuard(self.monitor, block_on_violation=True)
        session = FakeSession()
        with self.assertRaises(MCPBlocked) as ctx:
            asyncio.run(guard.call_tool(session, "search_kb", {"query": "x", "token": "secret"}))
        self.assertEqual(len(session.calls), 0, "violating call must not reach the tool")
        self.assertEqual(ctx.exception.violations[0]["rule"], "no_secret_args")
        # a certificate was still produced (documenting the blocked attempt)
        ok, payload = cert.verify_envelope(guard.certificates[0], cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertFalse(payload["outcome"]["passed"])

    def test_check_without_calling(self):
        guard = MCPGuard(self.monitor)
        env = guard.check("search_kb", {"api_key": "k"})
        _, payload = cert.verify_envelope(env, cert.DEMO_KEY)
        self.assertFalse(payload["outcome"]["passed"])


class TestMCPResultOffline(unittest.TestCase):
    """Result-side judging: certify the tool's returned text (content policy)."""

    def setUp(self):
        self.args_monitor = AgentMonitor(load_pack("agent_tool_v1.json"))
        self.result_monitor = AgentMonitor(load_pack("agent_content_v1.json"))

    def test_result_certificate_flags_secret(self):
        guard = MCPGuard(self.args_monitor, result_monitor=self.result_monitor, vkey_hash="vk")
        session = FakeSession(result_text="config api_key=sk-abcdefghijklmnopqrstuvwxyz")
        result, env = asyncio.run(guard.call_tool(session, "dump_config", {}))
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(len(guard.result_certificates), 1)
        _, payload = cert.verify_envelope(guard.result_certificates[0], cert.DEMO_KEY)
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret")
        self.assertEqual(payload["tool"], {"name": "dump_config", "phase": "result"})

    def test_clean_result_passes(self):
        guard = MCPGuard(self.args_monitor, result_monitor=self.result_monitor)
        session = FakeSession(result_text="ok:refund policy summary")
        asyncio.run(guard.call_tool(session, "search_kb", {"query": "refund"}))
        _, payload = cert.verify_envelope(guard.result_certificates[0], cert.DEMO_KEY)
        self.assertTrue(payload["outcome"]["passed"])

    def test_block_on_result_violation(self):
        guard = MCPGuard(self.args_monitor, result_monitor=self.result_monitor,
                         block_on_result_violation=True)
        session = FakeSession(result_text="token sk-abcdefghijklmnopqrstuvwxyz")
        with self.assertRaises(MCPBlocked) as ctx:
            asyncio.run(guard.call_tool(session, "dump_config", {}))
        self.assertEqual(ctx.exception.phase, "result")
        self.assertEqual(ctx.exception.violations[0]["rule"], "no_secret")
        self.assertEqual(len(session.calls), 1)  # the call happened; the result is rejected

    def test_no_result_monitor_skips(self):
        guard = MCPGuard(self.args_monitor)
        session = FakeSession(result_text="sk-abcdefghijklmnopqrstuvwxyz")
        asyncio.run(guard.call_tool(session, "dump_config", {}))
        self.assertEqual(guard.result_certificates, [])


@unittest.skipUnless(mcp_available(), "mcp SDK not installed")
class TestRealMCP(unittest.TestCase):
    def test_real_stdio_tool_call_is_certified(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        monitor = AgentMonitor(load_pack("agent_tool_v1.json"))
        guard = MCPGuard(monitor, vkey_hash="vk-real")

        async def run():
            params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    names = [t.name for t in tools.tools]
                    result, env = await guard.call_tool(
                        session, "search_kb", {"query": "refund", "token": "secret"})
                    return names, result, env

        names, result, env = asyncio.run(run())
        self.assertIn("search_kb", names)
        ok, payload = cert.verify_envelope(env, cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertEqual(payload["mode"], "tool-call")
        self.assertFalse(payload["outcome"]["passed"])  # 'token' is forbidden
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret_args")
        self.assertIsNotNone(result)

    def test_real_result_side_certificate(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        args_monitor = AgentMonitor(load_pack("agent_tool_v1.json"))
        result_monitor = AgentMonitor(load_pack("agent_content_v1.json"))
        guard = MCPGuard(args_monitor, result_monitor=result_monitor, vkey_hash="vk-real")

        async def run():
            params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await guard.call_tool(session, "dump_config", {})

        result, env = asyncio.run(run())
        self.assertEqual(len(guard.result_certificates), 1)
        ok, payload = cert.verify_envelope(guard.result_certificates[0], cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertFalse(payload["outcome"]["passed"])  # server returns sk-… secret
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret")


if __name__ == "__main__":
    unittest.main()
