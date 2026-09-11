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

from policydsl import agent, cert, trace  # noqa: E402
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
        ok, payload = cert.verify_envelope(ok_env, m.signer.public_key)
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])
        self.assertEqual(payload["policy_hash"], compile_policy(self.policy)["sha256"])

        bad_env = m.on_generate("Leak sk-abcdefghijklmnopqrstuvwxyz now", ts="T")
        _, bad = cert.verify_envelope(bad_env, m.signer.public_key)
        self.assertFalse(bad["outcome"]["passed"])
        self.assertEqual(bad["outcome"]["violations"][0]["rule"], "no_secret")

    # 私密模式的关键性质：原始输出（含密钥）绝不出现在证书里，只留内容承诺
    def test_private_certificate_hides_content(self):
        m = agent.AgentMonitor(self.policy, mode="private")
        env = m.on_generate("Leak sk-abcdefghijklmnopqrstuvwxyz now", ts="T")
        _, payload = cert.verify_envelope(env, m.signer.public_key)
        self.assertEqual(payload["mode"], "private")
        out = payload["outcome"]
        self.assertIn("response_commitment", out)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", json.dumps(payload))


class TestToolPath(unittest.TestCase):
    """工具调用路径：参数里的禁用字段应被判违规，干净参数则放行。"""

    def setUp(self):
        self.policy = load_pack("agent_tool_v1.json")

    # 验证 mode 标记、违规规则名，以及（不依赖证明是否附带的）判定结果本身。
    # P1-5：工具调用路径收的是**网关签发的回执**，不再是自报的 {name, args}。
    def test_forbidden_field_and_clean(self):
        m = agent.AgentMonitor(self.policy)
        gw = trace.ToolGateway(ts="T")
        env = m.on_tool_call(gw.issue("search_kb", {"q": "x", "token": "secret"},
                                      result="leaked"), ts="T")
        _, payload = cert.verify_envelope(env, m.signer.public_key)
        self.assertEqual(payload["mode"], "tool-call")
        self.assertFalse(payload["outcome"]["passed"])
        # 工具规则现已是电路内（in-circuit）规则；是否附带*证明*另由
        # binding.vkey_hash 单独记录，故此处只断言 zk 标记而不校验证明
        self.assertTrue(payload["outcome"]["zk"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret_args")
        # 回执链尾摘要进证书 —— 验证方可拿网关侧回执重算比对
        self.assertEqual(payload["outcome"]["trace_root"], gw.trace_root)

        # 判第二次调用时要带上**整条链**：回执是链中间的一条，结构校验要求
        # 从 seq=0 起逐条相连，且 trace_root 要落在真实链尾上（见 tool_call_outcome）。
        # 注意判定范围是整条链 —— 上面那条带了 token，所以这张也只能是失败：
        gw.issue("search_kb", {"q": "x"}, result="ok")
        dirty = m.tool_call_outcome(gw.receipts[-1], chain=gw.receipts)
        self.assertFalse(dirty["passed"], "链上有违规，后续调用证书不得判通过")
        self.assertEqual(dirty["trace_root"], gw.trace_root)
        # 反面：只拿链中间那一条（不给链）会 fail-closed —— 不能退化成「只看内容」
        self.assertFalse(m.tool_call_outcome(gw.receipts[-1])["passed"])

        # 干净的一次会话：新网关（新链），同一条干净调用必须判通过
        gw2 = trace.ToolGateway(ts="T")
        gw2.issue("search_kb", {"q": "x"}, result="ok")
        clean = m.tool_call_outcome(gw2.receipts[-1], chain=gw2.receipts)
        self.assertTrue(clean["passed"])
        self.assertEqual(clean["trace_root"], gw2.trace_root)


class TestMockSession(unittest.TestCase):
    """模拟整段 agent 会话：生成与工具两条路径产出的证书都应可独立验证。"""

    # 走 mock_agent() 的事件流，确认两条路径的证书都使用默认密钥且验证通过
    def test_session_produces_verifiable_certificates(self):
        signer = cert.Ed25519Signer.generate()   # 两条路径共用一把出证方密钥
        content = agent.AgentMonitor(load_pack("agent_content_v1.json"), signer=signer)
        tools = agent.AgentMonitor(load_pack("agent_tool_v1.json"), signer=signer)
        gw = trace.ToolGateway(ts="T")   # 工具网关：回执由它签发（P1-5）
        certs = []
        for kind, payload in agent.mock_agent():
            if kind == "generate":
                certs.append(content.on_generate(payload, ts="T",
                                                 receipts=gw.receipts))
            else:
                name, args = payload
                certs.append(tools.on_tool_call(gw.issue(name, args, result="ok"),
                                                ts="T"))
        self.assertEqual(len(certs), 2)
        # 每张证书都应对**出证方公钥**验签通过（P0-3：验证方只有公钥）
        ring = cert.keyring(signer.public_key)
        for env in certs:
            ok, _ = cert.verify_envelope(env, ring)
            self.assertTrue(ok)
        # 反面：换成别的公钥就必须失败 —— 否则上面的断言是恒真的
        self.assertFalse(cert.verify_envelope(certs[0], cert.Ed25519Signer.generate().public_key)[0])


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
