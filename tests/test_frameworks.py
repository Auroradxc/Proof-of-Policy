"""LangChain / LangGraph 适配层的测试。

离线用例用鸭子类型的假对象（SimpleNamespace 等）构造回调入参，因此无需安装
框架即可运行；真实框架用例仅在 langchain/langgraph 可导入时才跑（否则 skip）。
两层都保留，是为了在「无依赖环境仍能回归」与「真框架下确实接得上」之间兼顾。
"""

import json
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import cert  # noqa: E402
from policydsl.agent import AgentMonitor  # noqa: E402
from policydsl.langchain_adapter import (  # noqa: E402
    PoPCallbackHandler, langchain_available, verify_certificates, verify_chain,
)
from policydsl import langgraph_adapter as lg  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def load_pack(name: str) -> Policy:
    """从 policy_packs/ 读取策略包 JSON 并构造 Policy（测试共用的最小加载器）。"""
    data = json.loads((REPO / "policy_packs" / name).read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r["name"], params=r.get("params", {})) for r in data["rules"]]
    return Policy(data["id"], data.get("version", "0.1.0"), rules=rules)


def fake_llm_result(text: str):
    """伪造 LLMResult 的最小形状（generations -> [generation])，避免依赖真实框架。"""
    gen = types.SimpleNamespace(text=text)
    return types.SimpleNamespace(generations=[[gen]])


class TestCallbackHandlerOffline(unittest.TestCase):
    """回调处理器（离线）：模拟 LangChain 回调时机，检查证书的签发与内容判定。"""

    def setUp(self):
        self.content = AgentMonitor(load_pack("agent_content_v1.json"))
        self.tools = AgentMonitor(load_pack("agent_tool_v1.json"))

    # LLM 结束回调即签发一张可验证且判定通过的生成证书
    def test_llm_end_issues_certificate(self):
        h = PoPCallbackHandler(self.content, vkey_hash="vk1")
        h.on_llm_end(fake_llm_result("A safe, plain reply."), run_id="r1")
        self.assertEqual(len(h.certificates), 1)
        ok, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])
        self.assertTrue(verify_certificates(h))

    # 模型输出里出现密钥时，回调签发的证书应标记违规（no_secret）
    def test_llm_end_detects_violation(self):
        h = PoPCallbackHandler(self.content)
        h.on_llm_end(fake_llm_result("Leak sk-abcdefghijklmnopqrstuvwxyz"), run_id="r1")
        _, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret")

    # 聊天模型的 content 是分块列表时，也应能拼出文本并正常出证（兼容两种形态）
    def test_chat_generation_list_content(self):
        msg = types.SimpleNamespace(content=[{"type": "text", "text": "hello "},
                                             {"type": "text", "text": "world"}])
        gen = types.SimpleNamespace(message=msg)
        h = PoPCallbackHandler(self.content)
        h.on_llm_end(types.SimpleNamespace(generations=[[gen]]), run_id="r1")
        self.assertEqual(len(h.certificates), 1)

    # 工具调用需等 on_tool_end 才出证（start 记录参数、end 汇总判定）
    def test_tool_events_issue_certificate(self):
        h = PoPCallbackHandler(self.tools)
        h.on_tool_start({"name": "search_kb"}, "{'q': 'x', 'token': 'secret'}", run_id="t1")
        h.on_tool_end("result", run_id="t1")
        self.assertEqual(len(h.certificates), 1)
        _, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertEqual(payload["mode"], "tool-call")
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret_args")

    # 干净的工具参数不应被误判为违规
    def test_tool_clean(self):
        h = PoPCallbackHandler(self.tools)
        h.on_tool_start({"name": "search_kb"}, "{'q': 'refund'}", run_id="t1")
        h.on_tool_end("ok", run_id="t1")
        _, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertTrue(payload["outcome"]["passed"])

    # on_cert 回调钩子：外部观察者应能在证书生成时立即收到（用于落库/上链等）
    def test_on_cert_callback(self):
        seen = []
        h = PoPCallbackHandler(self.content, on_cert=seen.append)
        h.on_llm_end(fake_llm_result("fine"), run_id="r1")
        self.assertEqual(len(seen), 1)


class TestLangGraphHelpersOffline(unittest.TestCase):
    """LangGraph 图包装（离线）：guard_node/attach/LangGraphGuard 的包装语义。"""

    def setUp(self):
        self.content = AgentMonitor(load_pack("agent_content_v1.json"))
        self.tools = AgentMonitor(load_pack("agent_tool_v1.json"))

    # guard_node 包装生成节点：原节点返回值保留，并额外挂上 certificates 字段
    def test_guard_generate_node(self):
        def node(state):
            return {"output": "A safe reply."}

        g = lg.guard_node(self.content, node, kind="generate", vkey_hash="vk1")
        out = g({})
        self.assertIn("certificates", out)
        ok, payload = cert.verify_envelope(out["certificates"][0], cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])

    # guard_node 包装工具节点：节点返回的 (name, args) 形状会被送进策略判定
    def test_guard_tool_node(self):
        def node(state):
            return {"name": "search_kb", "args": {"q": "x", "api_key": "k"}}

        g = lg.guard_node(self.tools, node, kind="tool")
        out = g({})
        _, payload = cert.verify_envelope(out["certificates"][0], cert.DEMO_KEY)
        self.assertFalse(payload["outcome"]["passed"])

    # attach 是 LangGraph 侧推荐入口，返回的应是可传入 config 的回调处理器
    def test_attach_returns_handler(self):
        h = lg.attach(self.content, vkey_hash="vk9")
        self.assertIsInstance(h, PoPCallbackHandler)
        self.assertEqual(h.vkey_hash, "vk9")

    # LangGraphGuard 类封装：便捷地生成受守护的节点工厂
    def test_guard_class(self):
        guard = lg.LangGraphGuard(self.content)
        n = guard.generate_node(lambda s: {"output": "ok"})
        self.assertIn("certificates", n({}))

    # 缺少 langgraph 时 require_langgraph 必须显式报错，而不是让后续静默失效
    def test_require_langgraph_raises_without_dep(self):
        if lg.langgraph_available():  # pragma: no cover
            self.skipTest("langgraph installed")
        with self.assertRaises(RuntimeError):
            lg.require_langgraph()


@unittest.skipUnless(langchain_available(), "langchain not installed")
class TestRealLangChain(unittest.TestCase):
    """真实 LangChain：用官方 LLMResult / FakeListChatModel 走完整回调链路。"""

    # 直接以真实的 LLMResult 对象触发回调，验证对真实数据结构的兼容性
    def test_real_llm_result(self):
        from langchain_core.outputs import Generation, LLMResult

        monitor = AgentMonitor(load_pack("agent_content_v1.json"))
        h = PoPCallbackHandler(monitor, vkey_hash="vk-real")
        h.on_llm_end(LLMResult(generations=[[Generation(text="A safe reply.")]]), run_id="r1")
        self.assertEqual(len(h.certificates), 1)
        ok, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])

    def _fake_llm(self, text):
        """构造返回固定文本的假聊天模型，避免测试触网/依赖真实模型凭据。"""
        from langchain_core.language_models.fake_chat_models import FakeListChatModel

        return FakeListChatModel(responses=[text])

    # 端到端：把 handler 通过 config={"callbacks": [...]} 交给真实模型调用链
    def test_real_llm_end_to_end_callback(self):
        monitor = AgentMonitor(load_pack("agent_content_v1.json"))
        h = PoPCallbackHandler(monitor, vkey_hash="vk-e2e")
        self._fake_llm("A safe reply.").invoke("hi", config={"callbacks": [h]})
        self.assertEqual(len(h.certificates), 1)
        ok, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])
        self.assertEqual(payload["mode"], "public")

    # 端到端（违规）：同一链路下含密钥的输出应被判违规
    def test_real_llm_end_to_end_violation(self):
        monitor = AgentMonitor(load_pack("agent_content_v1.json"))
        h = PoPCallbackHandler(monitor)
        self._fake_llm("Leak sk-abcdefghijklmnopqrstuvwxyz").invoke(
            "hi", config={"callbacks": [h]})
        _, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret")

    # 端到端（真实 @tool）：工具回调确实会触发，且禁用参数被工具侧证书抓到
    def test_real_tool_end_to_end_callback(self):
        try:
            from langchain_core.tools import tool
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"langchain tool API unavailable: {exc}")

        @tool
        def search_kb(query: str, token: str = "") -> str:
            """Search the knowledge base."""
            return "ok"

        monitor = AgentMonitor(load_pack("agent_tool_v1.json"))
        h = PoPCallbackHandler(monitor)
        search_kb.invoke({"query": "refund", "token": "secret"}, config={"callbacks": [h]})
        self.assertTrue(h.certificates, "tool callbacks did not fire")
        _, payload = cert.verify_envelope(h.certificates[-1], cert.DEMO_KEY)
        self.assertEqual(payload["mode"], "tool-call")
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret_args")


class TestStreamingOffline(unittest.TestCase):
    """流式（离线）：逐 token 判定，只在结论*翻转*时出增量证书，避免刷屏。"""

    def setUp(self):
        self.monitor = AgentMonitor(load_pack("agent_content_v1.json"))

    def _feed(self, handler, text, run_id="s1"):
        """逐字符模拟 on_llm_new_token，逼近真实流式回调的粒度。"""
        for ch in text:
            handler.on_llm_new_token(ch, run_id=run_id)

    # 全程判定不变时应只有一张增量证书（首次 None -> True），不逐 token 出证
    def test_clean_prefix_emits_single_partial_cert(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "A safe reply")
        # 判定一直为 True -> 恰好一张增量证书（None -> True），不产生冗余
        self.assertEqual(len(h.stream_certificates), 1)
        ok, payload = cert.verify_envelope(h.stream_certificates[0], cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertTrue(payload["streaming"]["partial"])
        self.assertTrue(payload["outcome"]["passed"])

    # 违规是在流中途才可判定的：密钥模式凑齐的瞬间应立刻翻转并出证
    def test_stream_detects_violation_midstream(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "x sk-abcdefghijklmnopqrstuvwxyz")
        # None->True，随后密钥模式匹配完成时 True->False
        self.assertGreaterEqual(len(h.stream_certificates), 2)
        _, last = cert.verify_envelope(h.stream_certificates[-1], cert.DEMO_KEY)
        self.assertFalse(last["outcome"]["passed"])
        self.assertEqual(last["outcome"]["violations"][0]["rule"], "no_secret")
        self.assertTrue(last["streaming"]["partial"])

    # 关闭流式检查后不再产生增量证书（留给 on_llm_end 做最终判定）
    def test_stream_check_disabled(self):
        h = PoPCallbackHandler(self.monitor, stream_check=False)
        self._feed(h, "x sk-abcdefghijklmnopqrstuvwxyz")
        self.assertEqual(h.stream_certificates, [])

    # on_llm_end 出最终（权威）证书，并清空流式缓冲，防止跨请求串状态
    def test_on_llm_end_clears_stream_state(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "A safe reply")
        h.on_llm_end(types.SimpleNamespace(generations=[]), run_id="s1")
        self.assertEqual(len(h.certificates), 1)          # 最终（权威）证书
        self.assertEqual(h._sbuf, {})                     # 流式状态已清空


class TestStreamingChain(unittest.TestCase):
    """增量证书的哈希链：把流式的多张证书串成可被篡改检测的序列。"""

    def setUp(self):
        self.monitor = AgentMonitor(load_pack("agent_content_v1.json"))

    def _feed(self, handler, text, run_id="s1"):
        """逐字符模拟 on_llm_new_token，逼近真实流式回调的粒度。"""
        for ch in text:
            handler.on_llm_new_token(ch, run_id=run_id)

    # 正常链：链接完整可验，且按 run_id 取回的子链与总量一致
    def test_chain_links_and_verifies(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "x sk-abcdefghijklmnopqrstuvwxyz")
        self.assertTrue(verify_chain(h.stream_certificates))
        self.assertEqual(len(h.stream_chain("s1")), len(h.stream_certificates))

    # 篡改/重排链中某张（即便证书本身验签有效）也必须被 verify_chain 识破
    def test_tamper_breaks_chain(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "x sk-abcdefghijklmnopqrstuvwxyz")
        certs = list(h.stream_certificates)
        # 用一张重排后的证书替换中间那张（单张仍可验签，但破坏链序）
        certs[1] = certs[2] if len(certs) > 2 else certs[0]
        self.assertFalse(verify_chain(certs))

    # 违规即早停：发一张 stop 证书并中止流，后续 token 不再入链（省算力/防泄漏）
    def test_early_stop_on_violation(self):
        seen = []
        h = PoPCallbackHandler(self.monitor, stop_on_violation=True,
                               on_early_stop=seen.append)
        self._feed(h, "x sk-abcdefghijklmnopqrstuvwxyz MORE TOKENS IGNORED")
        # 已发出 stop 证书且流式判定被中止
        self.assertEqual(len(seen), 1)
        _, stop = cert.verify_envelope(h.stream_certificates[-1], cert.DEMO_KEY)
        self.assertFalse(stop["streaming"]["partial"])
        self.assertEqual(stop["streaming"]["stop"]["reason"], "violation")
        self.assertFalse(stop["outcome"]["passed"])
        self.assertTrue(verify_chain(h.stream_certificates))
        # 停止之后的 token 没有继续延长证书链
        self.assertLess(len(h.stream_certificates), len("x sk-abcdefghijklmnopqrstuvwxyz MORE TOKENS IGNORED"))

    # 干净流只产生单张证书，链依然自洽（退化情形不能误判为断链）
    def test_clean_chain_single_link(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "A safe reply")
        self.assertEqual(len(h.stream_certificates), 1)
        self.assertTrue(verify_chain(h.stream_certificates))


@unittest.skipUnless(langchain_available(), "langchain not installed")
class TestRealStreaming(unittest.TestCase):
    """真实流式：用 GenericFakeChatModel 触发 LangChain 的逐 token 回调。"""

    # 真实流式链路：增量证书可验证，且最终证书仍给出权威的违规结论
    def test_generic_fake_model_streams_and_certifies(self):
        try:
            from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
            from langchain_core.messages import AIMessage
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"GenericFakeChatModel unavailable: {exc}")

        monitor = AgentMonitor(load_pack("agent_content_v1.json"))
        h = PoPCallbackHandler(monitor, vkey_hash="vk-stream")
        llm = GenericFakeChatModel(messages=iter(
            [AIMessage(content="Leak sk-abcdefghijklmnopqrstuvwxyz")]))
        for _ in llm.stream("hi", config={"callbacks": [h]}):
            pass
        # 流式过程中确实发出了增量证书
        self.assertGreaterEqual(len(h.stream_certificates), 1)
        for env in h.stream_certificates + h.certificates:
            ok, _ = cert.verify_envelope(env, cert.DEMO_KEY)
            self.assertTrue(ok)
        # 最终（权威）证书标记了违规
        _, final = cert.verify_envelope(h.certificates[-1], cert.DEMO_KEY)
        self.assertFalse(final["outcome"]["passed"])


@unittest.skipUnless(lg.langgraph_available(), "langgraph not installed")
class TestRealLangGraph(unittest.TestCase):
    """真实 LangGraph：状态图里同时跑 LLM 与工具节点，全程自动签发证书。"""

    def _graph_app(self):
        """搭一张 gen -> tool -> END 的最小状态图，作为被守护的真实图。"""
        from typing import TypedDict
        from langgraph.graph import StateGraph, END
        from langchain_core.language_models.fake_chat_models import FakeListChatModel
        from langchain_core.tools import tool

        llm = FakeListChatModel(responses=["A safe reply."])

        @tool
        def search_kb(query: str, token: str = "") -> str:
            """Search the knowledge base."""
            return "ok"

        class S(TypedDict):
            output: str
            tool_out: str
            certificates: list

        def gen_node(state, config=None):
            msg = llm.invoke("hi", config=config)
            return {"output": msg.content}

        def tool_node(state, config=None):
            res = search_kb.invoke({"query": "refund", "token": "secret"}, config=config)
            return {"tool_out": str(res)}

        g = StateGraph(S)
        g.add_node("gen", gen_node)
        g.add_node("tool", tool_node)
        g.set_entry_point("gen")
        g.add_edge("gen", "tool")
        g.add_edge("tool", END)
        return g.compile()

    # 用 guard_node 包装节点编译成图并 invoke，证书应随 state 一起流回调用方
    def test_state_graph_with_guard(self):
        from typing import TypedDict
        from langgraph.graph import StateGraph, END

        monitor = AgentMonitor(load_pack("agent_content_v1.json"))

        class S(TypedDict):
            output: str
            certificates: list

        graph = StateGraph(S)
        graph.add_node("gen", lg.guard_node(monitor, lambda s: {"output": "A safe reply."},
                                            kind="generate", vkey_hash="vk-lg"))
        graph.set_entry_point("gen")
        graph.add_edge("gen", END)
        app = graph.compile()
        out = app.invoke({"output": "", "certificates": []})
        self.assertEqual(len(out["certificates"]), 1)
        ok, _ = cert.verify_envelope(out["certificates"][0], cert.DEMO_KEY)
        self.assertTrue(ok)

    # 最高层集成：借助 astream_events 同时捕获聊天模型与工具事件，两条路径都出证
    def test_astream_events_full_certification(self):
        content = AgentMonitor(load_pack("agent_content_v1.json"))
        tools = AgentMonitor(load_pack("agent_tool_v1.json"))
        stream_h = PoPCallbackHandler(content, vkey_hash="vk-ev")
        certifier = lg.LangGraphEventCertifier(content, tool_monitor=tools, vkey_hash="vk-ev",
                                               stream_handler=stream_h)
        certs = certifier.run_sync(self._graph_app(), {"output": "", "tool_out": "", "certificates": []})
        self.assertTrue(certs, "no certificates from astream_events")
        modes = set()
        for env in certs:
            ok, payload = cert.verify_envelope(env, cert.DEMO_KEY)
            self.assertTrue(ok)
            modes.add(payload["mode"])
        self.assertIn("public", modes)      # 聊天模型生成
        self.assertIn("tool-call", modes)   # 工具调用（违规：含禁用字段 'token'）
        # 工具侧证书标记了禁用字段
        tool_cert = [c for c in certs if cert.envelope_payload(c)["mode"] == "tool-call"][0]
        self.assertFalse(cert.envelope_payload(tool_cert)["outcome"]["passed"])
        self.assertTrue(any("chat_model" in e or "tool" in e for e in certifier.events))


if __name__ == "__main__":
    unittest.main()
