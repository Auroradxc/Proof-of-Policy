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
    PoPCallbackHandler, langchain_available, verify_certificates,
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


@unittest.skipUnless(lg.langgraph_available(), "langgraph not installed")
class TestRealLangGraph(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
