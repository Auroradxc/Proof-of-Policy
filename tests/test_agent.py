"""Tests for agent instrumentation hooks (policydsl.agent)."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policydsl import agent, cert  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def load_pack(name: str) -> Policy:
    data = json.loads((REPO / "policy_packs" / name).read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r["name"], params=r.get("params", {})) for r in data["rules"]]
    return Policy(data["id"], data.get("version", "0.1.0"), rules=rules)


class TestGeneratePath(unittest.TestCase):
    def setUp(self):
        self.policy = load_pack("agent_content_v1.json")

    def test_public_certificate_pass_and_fail(self):
        m = agent.AgentMonitor(self.policy, mode="public")
        ok_env = m.on_generate("A plain, safe reply.", ts="T", vkey_hash="vk1")
        ok, payload = cert.verify_envelope(ok_env, m.key)
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])
        self.assertEqual(payload["policy_hash"], compile_policy(self.policy)["sha256"])

        bad_env = m.on_generate("Leak sk-abcdefghijklmnopqrstuvwxyz now", ts="T")
        _, bad = cert.verify_envelope(bad_env, m.key)
        self.assertFalse(bad["outcome"]["passed"])
        self.assertEqual(bad["outcome"]["violations"][0]["rule"], "no_secret")

    def test_private_certificate_hides_content(self):
        m = agent.AgentMonitor(self.policy, mode="private")
        env = m.on_generate("Leak sk-abcdefghijklmnopqrstuvwxyz now", ts="T")
        _, payload = cert.verify_envelope(env, m.key)
        self.assertEqual(payload["mode"], "private")
        out = payload["outcome"]
        self.assertIn("response_commitment", out)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", json.dumps(payload))


class TestToolPath(unittest.TestCase):
    def setUp(self):
        self.policy = load_pack("agent_tool_v1.json")

    def test_forbidden_field_and_clean(self):
        m = agent.AgentMonitor(self.policy)
        env = m.on_tool_call("search_kb", {"q": "x", "token": "secret"}, ts="T")
        _, payload = cert.verify_envelope(env, m.key)
        self.assertEqual(payload["mode"], "tool-call")
        self.assertFalse(payload["outcome"]["passed"])
        self.assertFalse(payload["outcome"]["zk"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret_args")

        clean = m.tool_call_outcome("search_kb", {"q": "x"})
        self.assertTrue(clean["passed"])


class TestMockSession(unittest.TestCase):
    def test_session_produces_verifiable_certificates(self):
        content = agent.AgentMonitor(load_pack("agent_content_v1.json"))
        tools = agent.AgentMonitor(load_pack("agent_tool_v1.json"))
        certs = []
        for kind, payload in agent.mock_agent():
            if kind == "generate":
                certs.append(content.on_generate(payload, ts="T"))
            else:
                name, args = payload
                certs.append(tools.on_tool_call(name, args, ts="T"))
        self.assertEqual(len(certs), 2)
        for env in certs:
            ok, _ = cert.verify_envelope(env, agent.DEFAULT_KEY)
            self.assertTrue(ok)


class TestLangGraphAdapter(unittest.TestCase):
    def test_attach_returns_handler_and_require_raises(self):
        from policydsl import langgraph_adapter as lg
        from policydsl.langchain_adapter import PoPCallbackHandler
        monitor = agent.AgentMonitor(load_pack("agent_content_v1.json"))
        self.assertIsInstance(lg.attach(monitor), PoPCallbackHandler)
        if not lg.langgraph_available():  # pragma: no branch
            with self.assertRaises(RuntimeError):
                lg.require_langgraph()


if __name__ == "__main__":
    unittest.main()
