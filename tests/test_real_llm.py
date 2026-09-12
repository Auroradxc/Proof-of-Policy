"""``--model``：真模型客户端接进回调层（``policydsl.llm`` + 早停）。

分三层，各自的门槛不同：

1. **规格解析与报错**（:class:`TestModelSpec`）：纯离线，不装任何东西也能跑 ——
   没装 provider 包、没配 key、名字写错，都必须给一句能照着做的提示，
   而不是让 ``ImportError`` / ``ValidationError`` 从三层调用栈底下冒出来。
2. **真实客户端 + 本地 SSE 桩**（:class:`TestRealClientHardStop`）：**默认跑**。
   验的是「真实的 ``langchain_openai`` 客户端与真实 HTTP 传输接进
   ``PoPCallbackHandler`` 之后，真早停是否还能把流掐断」。桩（
   ``tests/openai_sse_stub.py``）实现的是**协议**，不是某家 provider 的行为 ——
   所以这一段不需要网络、不需要真 key，也就不进 ``POP_TEST_LLM`` 门控。
3. **真 provider**（:class:`TestRealProvider`）：``POP_TEST_LLM=1`` 才跑，
   需要真 key + 网络。CI 默认跳过。

``--model`` 缺省**不是**这些 —— 缺省是 demo_e2e.py 里的离线桩（写死的响应），
那条路一行都没动，由 ``tests/test_demo_e2e.py`` 继续守着。
"""

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import openai_sse_stub as stub  # noqa: E402

from policydsl import llm  # noqa: E402
from policydsl.agent import AgentMonitor  # noqa: E402
from policydsl.langchain_adapter import EarlyStop, PoPCallbackHandler  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


def load_pack(name: str) -> Policy:
    data = json.loads((REPO / "policy_packs" / name).read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r["name"], params=r.get("params", {})) for r in data["rules"]]
    return Policy(data["id"], data.get("version", "0.1.0"), rules=rules)


def _openai_available() -> bool:
    try:
        import langchain_openai  # noqa: F401

        return True
    except Exception:
        return False


#: 桩吐出的分片。密钥在**第二片**才完整出现 —— 早停必须停在流的中间，
#: 停在第一片（还没出密钥）或最后一片（已经吐完）都证明不了掐断。
STUB_CHUNKS = ["A safe ", "reply sk-abcdefghijklmnopqrstuvwxyz ", "and more ", "text"]
STUB_SECRET = "sk-abcdefghijklmnopqrstuvwxyz"
#: 含密钥的那个分片的下标（0 起）
VIOLATION_AT = 1


def _make_client(base_url: str):
    from langchain_openai import ChatOpenAI

    # stream_usage=False：桩不发 usage 那一块，关掉免得客户端等它。
    # 与「早停能不能掐断」无关 —— 开着的默认值走的是同一条回调路径。
    return ChatOpenAI(model="stub-model", base_url=base_url, api_key="stub-key",
                      stream_usage=False, temperature=0)


class TestModelSpec(unittest.TestCase):
    """``--model`` 规格：拆得开、报错报得清楚。全程离线。"""

    def test_bare_name_defaults_to_openai(self):
        self.assertEqual(llm.parse_spec("gpt-4o-mini"), ("openai", "gpt-4o-mini"))

    def test_explicit_provider(self):
        self.assertEqual(llm.parse_spec("anthropic:claude-sonnet-5"),
                         ("anthropic", "claude-sonnet-5"))
        self.assertEqual(llm.parse_spec("openai:gpt-4o-mini"), ("openai", "gpt-4o-mini"))

    def test_unknown_provider_is_refused(self):
        # 不认识就拒绝 —— 猜一个 provider 比说不认识更糟（会把请求发到别处）
        with self.assertRaises(llm.ModelSpecError) as ctx:
            llm.parse_spec("gemini:flash")
        self.assertIn("gemini", str(ctx.exception))

    def test_empty_model_name_is_refused(self):
        with self.assertRaises(llm.ModelSpecError):
            llm.parse_spec("openai:")
        with self.assertRaises(llm.ModelSpecError):
            llm.parse_spec("")

    def test_missing_key_says_which_variable(self):
        # key 没配时**当场**说清楚是哪一个，别等 SDK 在第一次请求时抛
        saved = os.environ.pop("OPENAI_API_KEY", None)
        try:
            with self.assertRaises(llm.ModelSpecError) as ctx:
                llm.build_chat_model("openai:gpt-4o-mini")
            self.assertIn("OPENAI_API_KEY", str(ctx.exception))
        finally:
            if saved is not None:
                os.environ["OPENAI_API_KEY"] = saved

    def test_missing_key_error_points_at_the_offline_default(self):
        # 报错必须同时告诉使用者「不想配 key 就别传 --model」
        saved = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with self.assertRaises(llm.ModelSpecError) as ctx:
                llm.build_chat_model("anthropic:claude-sonnet-5")
            self.assertIn("--model", str(ctx.exception))
        finally:
            if saved is not None:
                os.environ["ANTHROPIC_API_KEY"] = saved

    def test_does_not_use_the_harness_credentials(self):
        # ANTHROPIC_AUTH_TOKEN / ANTHROPIC_BASE_URL 是 Claude Code 自己的凭据。
        # 本模块**刻意不认**：演示的真模型调用该用使用者显式配的 key。
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", repr(llm._ENV_KEY))
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", repr(llm._ENV_BASE.values()))

    def test_describe_appends_base_url_when_set(self):
        saved = os.environ.get("OPENAI_BASE_URL")
        os.environ["OPENAI_BASE_URL"] = "http://127.0.0.1:9/v1"
        try:
            self.assertEqual(llm.describe("openai:x"),
                             "openai:x @ http://127.0.0.1:9/v1")
        finally:
            if saved is None:
                os.environ.pop("OPENAI_BASE_URL", None)
            else:
                os.environ["OPENAI_BASE_URL"] = saved


@unittest.skipUnless(_openai_available(), "langchain_openai not installed")
class TestRealClientHardStop(unittest.TestCase):
    """真实 ``ChatOpenAI`` 客户端 + 本地 SSE 桩：早停是否在**传输层**真的掐断。

    这是 #97 那条修法的跨层证据。离线用例（``test_frameworks.py`` 的
    ``TestRealHardStop``）用的是 ``GenericFakeChatModel`` —— 它压根不走 HTTP，
    所以「截断」只发生在 Python 的循环里。这里把真的 HTTP 客户端接上去，
    再由**服务器侧**数它到底写出去了几个分片。
    """

    def setUp(self):
        self.monitor = AgentMonitor(load_pack("agent_content_v1.json"))

    def _run(self, handler, server):
        seen = []
        aborted = False
        try:
            for chunk in _make_client(server.base_url).stream(
                    "hi", config={"callbacks": [handler]}):
                seen.append(chunk.content or "")
        except EarlyStop:
            aborted = True
        return aborted, "".join(seen)

    def test_early_stop_severs_the_transport(self):
        handler = PoPCallbackHandler(self.monitor, vkey_hash="unproven",
                                     stop_on_violation=True, hard_stop=True)
        with stub.StubServer(STUB_CHUNKS) as server:
            with self.assertLogs("langchain_core.callbacks.manager", level="WARNING"):
                aborted, delivered = self._run(handler, server)

        self.assertTrue(aborted, "违规了却没有掐断")
        # 交付给调用方的是**完整响应的一个真前缀**，且**必须更短** ——
        # 「更短」才是掐断，等长只说明它只是把该吐的吐完了。
        self.assertTrue("".join(STUB_CHUNKS).startswith(delivered), delivered)
        self.assertLess(len(delivered), len("".join(STUB_CHUNKS)))
        self.assertNotIn(STUB_SECRET, delivered, "密钥到达了调用方")

        # **传输层**证据：服务器写出去的分片数少于它打算写的总数，
        # 说明是真的断开了连接，而不是「我们这边不再 append 了」。
        total = len(STUB_CHUNKS) + 1  # +1 = 收尾那个 finish chunk
        self.assertLess(server.sent_chunks, total,
                        f"服务器把 {server.sent_chunks}/{total} 片全写完了 —— "
                        "流没有被真正切断")

    def test_stream_stop_certificate_says_partial_prefix(self):
        handler = PoPCallbackHandler(self.monitor, vkey_hash="unproven",
                                     stop_on_violation=True, hard_stop=True)
        with stub.StubServer(STUB_CHUNKS) as server:
            with self.assertLogs("langchain_core.callbacks.manager", level="WARNING"):
                self._run(handler, server)

        from policydsl import cert

        stop = cert.envelope_payload(handler.stream_certificates[-1])
        self.assertEqual(stop["streaming"]["stop"]["reason"], "violation")
        # 口径：判的是**截至此点的前缀**，不是整段生成
        self.assertEqual(stop["streaming"]["stop"]["scope"], "partial-prefix")
        # 被掐断的那次生成没有 on_llm_end ⇒ **没有**权威 llm 证书。
        # 这不是缺陷：它的结论就是那张停止证书。
        self.assertEqual(handler.certificates, [])

    def test_without_hard_stop_the_whole_stream_is_delivered(self):
        # 非恒真对照：同一个桩、同一条策略，只是关掉 hard_stop ——
        # 服务器应当把**每一片**都写出去，调用方拿到完整响应。
        # 没有这一条，上面的 sent_chunks 断言可能只是在说「桩本来就是短的」。
        handler = PoPCallbackHandler(self.monitor, vkey_hash="unproven",
                                     stop_on_violation=True, hard_stop=False)
        with stub.StubServer(STUB_CHUNKS) as server:
            aborted, delivered = self._run(handler, server)

        self.assertFalse(aborted)
        self.assertEqual(delivered, "".join(STUB_CHUNKS))
        self.assertEqual(server.sent_chunks, len(STUB_CHUNKS) + 1)
        self.assertIn(STUB_SECRET, delivered)  # 软停**不**拦内容 —— 这是它的定义

    def test_clean_stream_is_untouched(self):
        # 干净流上早停不该发作（否则「违规就停」等于「什么都停」）。
        # 注意干净那条**也有**流式证书：适配器在首个判定沿上出一张部分证书
        # （`partial=true`），这是链的起点，不是停止信号。要检的是**没有**
        # `streaming.stop`，以及流完整跑完。
        from policydsl import cert

        clean = ["A safe reply ", "about the refund policy."]
        handler = PoPCallbackHandler(self.monitor, vkey_hash="unproven",
                                     stop_on_violation=True, hard_stop=True)
        with stub.StubServer(clean) as server:
            aborted, delivered = self._run(handler, server)
            self.assertEqual(server.sent_chunks, len(clean) + 1, "干净流被截断了")

        self.assertFalse(aborted)
        self.assertEqual(delivered, "".join(clean))
        stops = [c for c in handler.stream_certificates
                 if "stop" in cert.envelope_payload(c)["streaming"]]
        self.assertEqual(stops, [], "干净流上不该有停止证书")
        # 干净那条**跑完了** ⇒ 有权威 llm 证书（与被掐断那条相反）
        self.assertEqual(len(handler.certificates), 1)


@unittest.skipUnless(os.environ.get("POP_TEST_LLM") == "1",
                     "set POP_TEST_LLM=1 (needs a real key + network)")
class TestRealProvider(unittest.TestCase):
    """真 provider 端到端（``POP_TEST_LLM=1``）：证书链在真模型下走通。

    **不**断言模型一定会违规 —— 那是赌 provider 的服从性。只断言结构：
    一次干净生成产出可验签的证书，且 `passed` 与策略判定一致。
    """

    SPEC = os.environ.get("POP_TEST_MODEL", "openai:gpt-4o-mini")

    def test_clean_generation_is_certified(self):
        from policydsl import cert

        model = llm.build_chat_model(self.SPEC)
        monitor = AgentMonitor(load_pack("agent_content_v1.json"))
        handler = PoPCallbackHandler(monitor, vkey_hash="unproven",
                                     stop_on_violation=True, hard_stop=True)
        seen = []
        for chunk in model.stream("Say exactly: hello", config={"callbacks": [handler]}):
            seen.append(chunk.content or "")
        self.assertTrue("".join(seen), "模型没有返回任何内容")
        self.assertTrue(handler.certificates, "干净生成没有产出权威证书")
        ok, payload = cert.verify_envelope(
            handler.certificates[-1], cert.keyring(monitor.signer.public_key))
        self.assertTrue(ok)
        self.assertEqual(payload["outcome"]["passed"], True)


if __name__ == "__main__":
    unittest.main()
