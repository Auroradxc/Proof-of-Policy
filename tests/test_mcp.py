"""MCP 工具守护（policydsl.mcp_adapter）的测试。

离线用例用假的 session（鸭子类型）跑，不依赖 mcp SDK；真实用例会通过 stdio
拉起一个货真价实的 MCP 服务器（tests/mcp_echo_server.py），未安装 `mcp` SDK
时整类 skip。真实会话用例是这套守护「能接进真实生态」的关键证据。
"""

import asyncio
import json
import sys
import types
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
    """从 policy_packs/ 读取策略包 JSON 并构造 Policy（测试共用的最小加载器）。"""
    data = json.loads((REPO / "policy_packs" / name).read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r["name"], params=r.get("params", {})) for r in data["rules"]]
    return Policy(data["id"], data.get("version", "0.1.0"), rules=rules)


def ring_of(*objs):
    """把这些对象所用 monitor 的**公钥**收成一个验签 keyring（P0-3）。

    测试也照第三方的规矩来：只拿公钥，拿不到私钥。能识别 AgentMonitor 本身、
    callback handler（``monitor``）、MCP guard（``monitor``/``result_monitor``）、
    LangGraph guard / event certifier（``monitor``/``tool_monitor``/``stream_handler``）。
    """
    kr = {}
    for o in objs:
        for m in _monitors_of(o):
            kr.update(cert.keyring(m.signer.public_key))
    return kr


def _monitors_of(o):
    """从一个对象上找出它持有的所有 AgentMonitor（浅一层）。"""
    if hasattr(o, "signer"):          # 本身就是 AgentMonitor
        return [o]
    out = []
    for attr in ("monitor", "tool_monitor", "args_monitor", "result_monitor"):
        m = getattr(o, attr, None)
        if m is not None and hasattr(m, "signer"):
            out.append(m)
    sh = getattr(o, "stream_handler", None)
    if sh is not None:
        out.extend(_monitors_of(sh))
    return out


def mcp_available() -> bool:
    """探测 mcp SDK 是否可导入，供 skipUnless 决定是否跑真实会话用例。"""
    try:
        import mcp  # noqa: F401

        return True
    except Exception:
        return False


class FakeSession:
    """鸭子类型的假 MCP 会话：实现 ``async call_tool`` 与 ``async list_tools``，
    并记录收到的调用。

    有了 calls 列表，就能断言拦截确实发生在「到达工具之前」。
    """

    def __init__(self, result_text: str = None, tools: "list" = None):
        self.calls = []
        self.result_text = result_text
        #: ``list_tools()`` 要报的工具名。缺省给两个 —— 让「发现」有东西可发现。
        self.tools = ["search_kb", "dump_config"] if tools is None else tools

    async def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments))
        text = self.result_text if self.result_text is not None else f"ok:{name}"
        return {"content": [{"type": "text", "text": text}]}

    async def list_tools(self):
        """鸭子类型的 ``tools/list``：返回带 ``.name`` 的对象列表（同真实 SDK 形状）。"""
        return types.SimpleNamespace(
            tools=[types.SimpleNamespace(name=n) for n in self.tools])


class TestMCPGuardOffline(unittest.TestCase):
    """参数侧守护（离线）：干净调用放行并出证，违规调用在飞行前被拦。"""

    def setUp(self):
        self.monitor = AgentMonitor(load_pack("agent_tool_v1.json"))

    # 干净调用：工具真的被执行了一次，且证书可验证、判定为通过
    def test_clean_call_certifies_and_runs(self):
        guard = MCPGuard(self.monitor, vkey_hash="vk")
        session = FakeSession()
        result, env = asyncio.run(guard.call_tool(session, "search_kb", {"query": "refund"}))
        self.assertEqual(len(session.calls), 1)
        ok, payload = cert.verify_envelope(env, ring_of(guard))
        self.assertTrue(ok)
        self.assertEqual(payload["mode"], "tool-call")
        self.assertTrue(payload["outcome"]["passed"])

    # 拦截语义：违规调用绝不能到达服务器（calls 为空），但仍留一张证书作存证
    def test_blocking_prevents_violating_call(self):
        guard = MCPGuard(self.monitor, block_on_violation=True)
        session = FakeSession()
        with self.assertRaises(MCPBlocked) as ctx:
            asyncio.run(guard.call_tool(session, "search_kb", {"query": "x", "token": "secret"}))
        self.assertEqual(len(session.calls), 0, "violating call must not reach the tool")
        self.assertEqual(ctx.exception.violations[0]["rule"], "no_secret_args")
        # 证书仍被签出：被拦下的尝试同样要留痕，而非静默丢弃
        ok, payload = cert.verify_envelope(guard.certificates[0], ring_of(guard))
        self.assertTrue(ok)
        self.assertFalse(payload["outcome"]["passed"])

    # 只判不调（干跑）也须出证：用于在真正执行前预演策略结论
    def test_check_without_calling(self):
        guard = MCPGuard(self.monitor)
        env = guard.check("search_kb", {"api_key": "k"})
        _, payload = cert.verify_envelope(env, ring_of(guard))
        self.assertFalse(payload["outcome"]["passed"])


class TestMCPToolDiscovery(unittest.TestCase):
    """工具清单**问服务器要**（``tools/list``），不写死（dev-plan §5.1.2 第 5 条）。

    写死的名字在服务器改名之后不会报错，只会静默地跑成另一次调用 —— 这个项目
    最反对的就是「看起来通过了」。发现之后，未声明的工具在执行前被拦下。
    """

    def setUp(self):
        self.monitor = AgentMonitor(load_pack("agent_tool_v1.json"))

    def test_discover_lists_sorted_names(self):
        guard = MCPGuard(self.monitor)
        session = FakeSession(tools=["dump_config", "search_kb"])
        names = asyncio.run(guard.discover_tools(session))
        self.assertEqual(names, ["dump_config", "search_kb"])
        self.assertEqual(guard.tool_names, names)

    def test_unknown_tool_is_blocked_before_execution(self):
        guard = MCPGuard(self.monitor, block_on_violation=True)
        session = FakeSession(tools=["search_kb"])
        asyncio.run(guard.discover_tools(session))
        with self.assertRaises(MCPBlocked) as ctx:
            asyncio.run(guard.call_tool(session, "dump_config", {}))
        self.assertEqual(ctx.exception.phase, "unknown-tool")
        self.assertEqual(len(session.calls), 0, "不存在的工具绝不能到达服务器")
        # 与「策略违规」分开报：这条不是「调用不合规」，是「调用不存在」
        self.assertIn("is not advertised", str(ctx.exception))
        self.assertEqual(guard.certificates, [], "拦的是不存在的调用，不该为它出证")

    def test_known_tool_still_passes(self):
        # 非恒真对照：发现之后，**声明过**的工具照常放行 —— 否则上面那条只是在说
        # 「发现之后什么都拦」，跟存在性检查没关系。
        guard = MCPGuard(self.monitor, block_on_violation=True)
        session = FakeSession(tools=["search_kb"])
        asyncio.run(guard.discover_tools(session))
        asyncio.run(guard.call_tool(session, "search_kb", {"query": "refund"}))
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(len(guard.certificates), 1)

    def test_no_discovery_means_no_existence_check(self):
        # 没问过服务器就不做存在性检查 —— 把「还没问」当成「一个都没有」会把
        # 所有调用都拦掉，那是把缺省值当成了事实。
        guard = MCPGuard(self.monitor)
        session = FakeSession(tools=["search_kb"])
        asyncio.run(guard.call_tool(session, "whatever", {"query": "refund"}))
        self.assertEqual(len(session.calls), 1)


class TestMCPResultOffline(unittest.TestCase):
    """结果侧判定（离线）：对工具**返回的文本**按内容策略签发证书。

    参数合法不代表返回内容安全（例如外部数据源被投毒），故结果侧需独立把关。
    """

    def setUp(self):
        self.args_monitor = AgentMonitor(load_pack("agent_tool_v1.json"))
        self.result_monitor = AgentMonitor(load_pack("agent_content_v1.json"))

    # 返回值里出现密钥时，结果证书必须判定失败，并以 phase=result 标注阶段
    def test_result_certificate_flags_secret(self):
        guard = MCPGuard(self.args_monitor, result_monitor=self.result_monitor, vkey_hash="vk")
        session = FakeSession(result_text="config api_key=sk-abcdefghijklmnopqrstuvwxyz")
        result, env = asyncio.run(guard.call_tool(session, "dump_config", {}))
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(len(guard.result_certificates), 1)
        _, payload = cert.verify_envelope(guard.result_certificates[0], ring_of(guard))
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret")
        self.assertEqual(payload["tool"], {"name": "dump_config", "phase": "result"})

    # 干净的返回内容不应被误报（避免结果侧判定过严）
    def test_clean_result_passes(self):
        guard = MCPGuard(self.args_monitor, result_monitor=self.result_monitor)
        session = FakeSession(result_text="ok:refund policy summary")
        asyncio.run(guard.call_tool(session, "search_kb", {"query": "refund"}))
        _, payload = cert.verify_envelope(guard.result_certificates[0], ring_of(guard))
        self.assertTrue(payload["outcome"]["passed"])

    # 开启结果侧拦截后：调用已发生，但违规结果被拒（phase 应为 result）
    def test_block_on_result_violation(self):
        guard = MCPGuard(self.args_monitor, result_monitor=self.result_monitor,
                         block_on_result_violation=True)
        session = FakeSession(result_text="token sk-abcdefghijklmnopqrstuvwxyz")
        with self.assertRaises(MCPBlocked) as ctx:
            asyncio.run(guard.call_tool(session, "dump_config", {}))
        self.assertEqual(ctx.exception.phase, "result")
        self.assertEqual(ctx.exception.violations[0]["rule"], "no_secret")
        self.assertEqual(len(session.calls), 1)  # 调用已发出，被拒的是返回结果

    # 未配置 result_monitor 时不产生任何结果证书（结果侧检查按需启用）
    def test_no_result_monitor_skips(self):
        guard = MCPGuard(self.args_monitor)
        session = FakeSession(result_text="sk-abcdefghijklmnopqrstuvwxyz")
        asyncio.run(guard.call_tool(session, "dump_config", {}))
        self.assertEqual(guard.result_certificates, [])


@unittest.skipUnless(mcp_available(), "mcp SDK not installed")
class TestRealMCP(unittest.TestCase):
    """真实 MCP 会话：stdio 拉起 tests/mcp_echo_server.py，验证守护在真实协议下可用。"""

    # 参数侧端到端：真实握手/列工具/调用，违规参数仍被策略判定并出证
    def test_real_stdio_tool_call_is_certified(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        monitor = AgentMonitor(load_pack("agent_tool_v1.json"))
        guard = MCPGuard(monitor, vkey_hash="vk-real")

        async def run():
            # 用当前解释器把 echo server 作为子进程拉起，走标准 stdio 传输
            params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    # 走 guard 自己的发现路径（而不是手抄一遍 list_tools）：
                    # 这样「真实 SDK 的返回形状喂得进 discover_tools」也被验到了
                    names = await guard.discover_tools(session)
                    result, env = await guard.call_tool(
                        session, "search_kb", {"query": "refund", "token": "secret"})
                    return names, result, env

        names, result, env = asyncio.run(run())
        # 名单来自服务器，不是写死的：echo server 声明的两个工具都得在里面
        self.assertEqual(set(names), {"search_kb", "dump_config"})
        ok, payload = cert.verify_envelope(env, ring_of(guard))
        self.assertTrue(ok)
        self.assertEqual(payload["mode"], "tool-call")
        self.assertFalse(payload["outcome"]["passed"])  # 'token' 属于禁用字段
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret_args")
        self.assertIsNotNone(result)

    # 结果侧端到端：服务器真实返回的密钥文本被内容策略抓到并出证
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
        ok, payload = cert.verify_envelope(guard.result_certificates[0], ring_of(guard))
        self.assertTrue(ok)
        self.assertFalse(payload["outcome"]["passed"])  # 服务器返回了 sk-… 密钥
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret")


class TestMCPGuardProofMode(unittest.TestCase):
    """MCP 守护把证据档位（P0-4）带到它签的两条路径：参数侧与结果侧。

    与 `test_frameworks.py::TestProofModePlumbingOffline` 同构 —— 适配器只是载体，
    校验只认载荷里的 `binding.proof_mode`，所以两处都得真的落下去。
    """

    def setUp(self):
        self.tools = AgentMonitor(load_pack("agent_tool_v1.json"))
        self.content = AgentMonitor(load_pack("agent_content_v1.json"))

    def test_mode_reaches_args_and_result_certificates(self):
        guard = MCPGuard(self.tools, result_monitor=self.content, proof_mode="core")
        args_env = guard.check("search_kb", {"query": "refund"})
        result_env = guard.judge_result("search_kb", "a safe tool output")
        self.assertIsNotNone(result_env, "结果侧未出证，用例前提不成立")
        for env in (args_env, result_env):
            self.assertEqual(cert.envelope_payload(env)["binding"]["proof_mode"], "core")

    def test_default_is_unproven(self):
        guard = MCPGuard(self.tools)
        env = guard.check("search_kb", {"query": "refund"})
        self.assertEqual(cert.envelope_payload(env)["binding"]["proof_mode"],
                         cert.PROOF_MODE_UNPROVEN)


if __name__ == "__main__":
    unittest.main()
