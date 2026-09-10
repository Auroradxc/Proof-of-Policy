"""Tests for LangChain / LangGraph adapters.

Offline tests use duck-typed fakes so they run without the frameworks installed.
Real-framework tests are skipped unless langchain/langgraph are importable.
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
    data = json.loads((REPO / "policy_packs" / name).read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r["name"], params=r.get("params", {})) for r in data["rules"]]
    return Policy(data["id"], data.get("version", "0.1.0"), rules=rules)


def fake_llm_result(text: str):
    gen = types.SimpleNamespace(text=text)
    return types.SimpleNamespace(generations=[[gen]])


class TestCallbackHandlerOffline(unittest.TestCase):
    def setUp(self):
        self.content = AgentMonitor(load_pack("agent_content_v1.json"))
        self.tools = AgentMonitor(load_pack("agent_tool_v1.json"))

    def test_llm_end_issues_certificate(self):
        h = PoPCallbackHandler(self.content, vkey_hash="vk1")
        h.on_llm_end(fake_llm_result("A safe, plain reply."), run_id="r1")
        self.assertEqual(len(h.certificates), 1)
        ok, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])
        self.assertTrue(verify_certificates(h))

    def test_llm_end_detects_violation(self):
        h = PoPCallbackHandler(self.content)
        h.on_llm_end(fake_llm_result("Leak sk-abcdefghijklmnopqrstuvwxyz"), run_id="r1")
        _, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret")

    def test_chat_generation_list_content(self):
        msg = types.SimpleNamespace(content=[{"type": "text", "text": "hello "},
                                             {"type": "text", "text": "world"}])
        gen = types.SimpleNamespace(message=msg)
        h = PoPCallbackHandler(self.content)
        h.on_llm_end(types.SimpleNamespace(generations=[[gen]]), run_id="r1")
        self.assertEqual(len(h.certificates), 1)

    def test_tool_events_issue_certificate(self):
        h = PoPCallbackHandler(self.tools)
        h.on_tool_start({"name": "search_kb"}, "{'q': 'x', 'token': 'secret'}", run_id="t1")
        h.on_tool_end("result", run_id="t1")
        self.assertEqual(len(h.certificates), 1)
        _, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertEqual(payload["mode"], "tool-call")
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret_args")

    def test_tool_clean(self):
        h = PoPCallbackHandler(self.tools)
        h.on_tool_start({"name": "search_kb"}, "{'q': 'refund'}", run_id="t1")
        h.on_tool_end("ok", run_id="t1")
        _, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertTrue(payload["outcome"]["passed"])

    def test_on_cert_callback(self):
        seen = []
        h = PoPCallbackHandler(self.content, on_cert=seen.append)
        h.on_llm_end(fake_llm_result("fine"), run_id="r1")
        self.assertEqual(len(seen), 1)


class TestLangGraphHelpersOffline(unittest.TestCase):
    def setUp(self):
        self.content = AgentMonitor(load_pack("agent_content_v1.json"))
        self.tools = AgentMonitor(load_pack("agent_tool_v1.json"))

    def test_guard_generate_node(self):
        def node(state):
            return {"output": "A safe reply."}

        g = lg.guard_node(self.content, node, kind="generate", vkey_hash="vk1")
        out = g({})
        self.assertIn("certificates", out)
        ok, payload = cert.verify_envelope(out["certificates"][0], cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])

    def test_guard_tool_node(self):
        def node(state):
            return {"name": "search_kb", "args": {"q": "x", "api_key": "k"}}

        g = lg.guard_node(self.tools, node, kind="tool")
        out = g({})
        _, payload = cert.verify_envelope(out["certificates"][0], cert.DEMO_KEY)
        self.assertFalse(payload["outcome"]["passed"])

    def test_attach_returns_handler(self):
        h = lg.attach(self.content, vkey_hash="vk9")
        self.assertIsInstance(h, PoPCallbackHandler)
        self.assertEqual(h.vkey_hash, "vk9")

    def test_guard_class(self):
        guard = lg.LangGraphGuard(self.content)
        n = guard.generate_node(lambda s: {"output": "ok"})
        self.assertIn("certificates", n({}))

    def test_require_langgraph_raises_without_dep(self):
        if lg.langgraph_available():  # pragma: no cover
            self.skipTest("langgraph installed")
        with self.assertRaises(RuntimeError):
            lg.require_langgraph()


@unittest.skipUnless(langchain_available(), "langchain not installed")
class TestRealLangChain(unittest.TestCase):
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
        from langchain_core.language_models.fake_chat_models import FakeListChatModel

        return FakeListChatModel(responses=[text])

    def test_real_llm_end_to_end_callback(self):
        monitor = AgentMonitor(load_pack("agent_content_v1.json"))
        h = PoPCallbackHandler(monitor, vkey_hash="vk-e2e")
        self._fake_llm("A safe reply.").invoke("hi", config={"callbacks": [h]})
        self.assertEqual(len(h.certificates), 1)
        ok, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])
        self.assertEqual(payload["mode"], "public")

    def test_real_llm_end_to_end_violation(self):
        monitor = AgentMonitor(load_pack("agent_content_v1.json"))
        h = PoPCallbackHandler(monitor)
        self._fake_llm("Leak sk-abcdefghijklmnopqrstuvwxyz").invoke(
            "hi", config={"callbacks": [h]})
        _, payload = cert.verify_envelope(h.certificates[0], cert.DEMO_KEY)
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret")

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
    def setUp(self):
        self.monitor = AgentMonitor(load_pack("agent_content_v1.json"))

    def _feed(self, handler, text, run_id="s1"):
        for ch in text:
            handler.on_llm_new_token(ch, run_id=run_id)

    def test_clean_prefix_emits_single_partial_cert(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "A safe reply")
        # verdict stays True -> exactly one partial cert (None -> True), no spam
        self.assertEqual(len(h.stream_certificates), 1)
        ok, payload = cert.verify_envelope(h.stream_certificates[0], cert.DEMO_KEY)
        self.assertTrue(ok)
        self.assertTrue(payload["streaming"]["partial"])
        self.assertTrue(payload["outcome"]["passed"])

    def test_stream_detects_violation_midstream(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "x sk-abcdefghijklmnopqrstuvwxyz")
        # None->True, then True->False when the secret pattern completes
        self.assertGreaterEqual(len(h.stream_certificates), 2)
        _, last = cert.verify_envelope(h.stream_certificates[-1], cert.DEMO_KEY)
        self.assertFalse(last["outcome"]["passed"])
        self.assertEqual(last["outcome"]["violations"][0]["rule"], "no_secret")
        self.assertTrue(last["streaming"]["partial"])

    def test_stream_check_disabled(self):
        h = PoPCallbackHandler(self.monitor, stream_check=False)
        self._feed(h, "x sk-abcdefghijklmnopqrstuvwxyz")
        self.assertEqual(h.stream_certificates, [])

    def test_on_llm_end_clears_stream_state(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "A safe reply")
        h.on_llm_end(types.SimpleNamespace(generations=[]), run_id="s1")
        self.assertEqual(len(h.certificates), 1)          # final (authoritative) cert
        self.assertEqual(h._sbuf, {})                     # state cleared


class TestStreamingChain(unittest.TestCase):
    def setUp(self):
        self.monitor = AgentMonitor(load_pack("agent_content_v1.json"))

    def _feed(self, handler, text, run_id="s1"):
        for ch in text:
            handler.on_llm_new_token(ch, run_id=run_id)

    def test_chain_links_and_verifies(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "x sk-abcdefghijklmnopqrstuvwxyz")
        self.assertTrue(verify_chain(h.stream_certificates))
        self.assertEqual(len(h.stream_chain("s1")), len(h.stream_certificates))

    def test_tamper_breaks_chain(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "x sk-abcdefghijklmnopqrstuvwxyz")
        certs = list(h.stream_certificates)
        # replace the middle certificate with a re-signed but reordered one
        certs[1] = certs[2] if len(certs) > 2 else certs[0]
        self.assertFalse(verify_chain(certs))

    def test_early_stop_on_violation(self):
        seen = []
        h = PoPCallbackHandler(self.monitor, stop_on_violation=True,
                               on_early_stop=seen.append)
        self._feed(h, "x sk-abcdefghijklmnopqrstuvwxyz MORE TOKENS IGNORED")
        # a stop certificate was emitted and streaming halted
        self.assertEqual(len(seen), 1)
        _, stop = cert.verify_envelope(h.stream_certificates[-1], cert.DEMO_KEY)
        self.assertFalse(stop["streaming"]["partial"])
        self.assertEqual(stop["streaming"]["stop"]["reason"], "violation")
        self.assertFalse(stop["outcome"]["passed"])
        self.assertTrue(verify_chain(h.stream_certificates))
        # tokens after the stop did not extend the chain
        self.assertLess(len(h.stream_certificates), len("x sk-abcdefghijklmnopqrstuvwxyz MORE TOKENS IGNORED"))

    def test_clean_chain_single_link(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "A safe reply")
        self.assertEqual(len(h.stream_certificates), 1)
        self.assertTrue(verify_chain(h.stream_certificates))


@unittest.skipUnless(langchain_available(), "langchain not installed")
class TestRealStreaming(unittest.TestCase):
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
        # incremental certs were emitted during streaming
        self.assertGreaterEqual(len(h.stream_certificates), 1)
        for env in h.stream_certificates + h.certificates:
            ok, _ = cert.verify_envelope(env, cert.DEMO_KEY)
            self.assertTrue(ok)
        # final (authoritative) certificate flags the violation
        _, final = cert.verify_envelope(h.certificates[-1], cert.DEMO_KEY)
        self.assertFalse(final["outcome"]["passed"])


@unittest.skipUnless(lg.langgraph_available(), "langgraph not installed")
class TestRealLangGraph(unittest.TestCase):
    def _graph_app(self):
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
        self.assertIn("public", modes)      # chat model completion
        self.assertIn("tool-call", modes)   # tool call (violating: forbidden 'token')
        # tool certificate flags the forbidden field
        tool_cert = [c for c in certs if cert.envelope_payload(c)["mode"] == "tool-call"][0]
        self.assertFalse(cert.envelope_payload(tool_cert)["outcome"]["passed"])
        self.assertTrue(any("chat_model" in e or "tool" in e for e in certifier.events))


if __name__ == "__main__":
    unittest.main()
