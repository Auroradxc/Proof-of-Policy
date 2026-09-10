"""policydsl.agent 插桩钩子的测试。

AgentMonitor 是「生成路径」与「工具调用路径」的统一入口：它把一次模型输出或
一次工具调用送进策略引擎，并签发出可独立验证的证书。这里覆盖公开/私有两种
模式下证书的可见性差异，以及证书确实由策略哈希绑定（不可张冠李戴）。
"""

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
    """从 policy_packs/ 读取策略包 JSON 并构造 Policy（测试共用的最小加载器）。"""
    data = json.loads((REPO / "policy_packs" / name).read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r["name"], params=r.get("params", {})) for r in data["rules"]]
    return Policy(data["id"], data.get("version", "0.1.0"), rules=rules)


class TestGeneratePath(unittest.TestCase):
    """生成路径（模型输出）的证书：公开模式揭示内容，私密模式只留承诺值。"""

    def setUp(self):
        self.policy = load_pack("agent_content_v1.json")

    # 公开模式下证书需可验证、能如实区分通过/违规，并且绑定策略哈希
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

    # 私密模式的关键性质：原始输出（含密钥）绝不出现在证书里，只留内容承诺
    def test_private_certificate_hides_content(self):
        m = agent.AgentMonitor(self.policy, mode="private")
        env = m.on_generate("Leak sk-abcdefghijklmnopqrstuvwxyz now", ts="T")
        _, payload = cert.verify_envelope(env, m.key)
        self.assertEqual(payload["mode"], "private")
        out = payload["outcome"]
        self.assertIn("response_commitment", out)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", json.dumps(payload))


class TestToolPath(unittest.TestCase):
    """工具调用路径：参数里的禁用字段应被判违规，干净参数则放行。"""

    def setUp(self):
        self.policy = load_pack("agent_tool_v1.json")

    # 验证 mode 标记、违规规则名，以及（不依赖证明是否附带的）判定结果本身
    def test_forbidden_field_and_clean(self):
        m = agent.AgentMonitor(self.policy)
        env = m.on_tool_call("search_kb", {"q": "x", "token": "secret"}, ts="T")
        _, payload = cert.verify_envelope(env, m.key)
        self.assertEqual(payload["mode"], "tool-call")
        self.assertFalse(payload["outcome"]["passed"])
        # 工具规则现已是电路内（in-circuit）规则；是否附带*证明*另由
        # binding.vkey_hash 单独记录，故此处只断言 zk 标记而不校验证明
        self.assertTrue(payload["outcome"]["zk"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret_args")

        clean = m.tool_call_outcome("search_kb", {"q": "x"})
        self.assertTrue(clean["passed"])


class TestMockSession(unittest.TestCase):
    """模拟整段 agent 会话：生成与工具两条路径产出的证书都应可独立验证。"""

    # 走 mock_agent() 的事件流，确认两条路径的证书都使用默认密钥且验证通过
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
        # 每张证书都应对默认密钥验签通过
        for env in certs:
            ok, _ = cert.verify_envelope(env, agent.DEFAULT_KEY)
            self.assertTrue(ok)


class TestLangGraphAdapter(unittest.TestCase):
    """LangGraph 适配层：attach 复用 LangChain 回调，缺依赖时 require 应报错。"""

    # attach 返回的必须就是 LangChain 的 handler（两者共享回调系统）；
    # 未安装 langgraph 时 require_langgraph 应抛出 RuntimeError 而非静默失败
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
