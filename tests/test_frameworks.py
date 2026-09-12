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
    EarlyStop, PoPCallbackHandler, langchain_available, verify_certificates, verify_chain,
)
from policydsl import langgraph_adapter as lg  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402

REPO = Path(__file__).resolve().parents[1]


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
        ok, payload = cert.verify_envelope(h.certificates[0], ring_of(h))
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])
        self.assertTrue(verify_certificates(h))

    # 模型输出里出现密钥时，回调签发的证书应标记违规（no_secret）
    def test_llm_end_detects_violation(self):
        h = PoPCallbackHandler(self.content)
        h.on_llm_end(fake_llm_result("Leak sk-abcdefghijklmnopqrstuvwxyz"), run_id="r1")
        _, payload = cert.verify_envelope(h.certificates[0], ring_of(h))
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
        _, payload = cert.verify_envelope(h.certificates[0], ring_of(h))
        self.assertEqual(payload["mode"], "tool-call")
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["outcome"]["violations"][0]["rule"], "no_secret_args")

    # 干净的工具参数不应被误判为违规
    def test_tool_clean(self):
        h = PoPCallbackHandler(self.tools)
        h.on_tool_start({"name": "search_kb"}, "{'q': 'refund'}", run_id="t1")
        h.on_tool_end("ok", run_id="t1")
        _, payload = cert.verify_envelope(h.certificates[0], ring_of(h))
        self.assertTrue(payload["outcome"]["passed"])

    # on_cert 回调钩子：外部观察者应能在证书生成时立即收到（用于落库/上链等）
    def test_on_cert_callback(self):
        seen = []
        h = PoPCallbackHandler(self.content, on_cert=seen.append)
        h.on_llm_end(fake_llm_result("fine"), run_id="r1")
        self.assertEqual(len(seen), 1)


class TestErrorCallbacksOffline(unittest.TestCase):
    """失败也要留痕：``on_llm_error`` / ``on_tool_error``（离线）。

    这是一组**反歧义**用例。此前的回调集只有四个（``on_llm_new_token`` /
    ``on_llm_end`` / ``on_tool_start`` / ``on_tool_end``）—— 模型超时、限流、
    内容拦截时**一张证书都不签**，于是产物上「会话失败了」与「会话干净」完全
    同形。而这三件事对真模型而言是**常态**，不是边角。

    修法不是「出错时补个日志」，是**照常签一张证书**，并在载荷**顶层**附
    ``error`` 块（不进 ``outcome``，因为 ``outcome`` 是证明公开值的镜像，
    电路里没有这个字段）。每个正向用例都配一条**非恒真对照**。
    """

    def setUp(self):
        self.content = AgentMonitor(load_pack("agent_content_v1.json"))
        self.tools = AgentMonitor(load_pack("agent_tool_v1.json"))

    # 模型报错（且没有任何 token 到达）→ 仍有一张可验证的证书
    def test_llm_error_still_issues_a_certificate(self):
        h = PoPCallbackHandler(self.content)
        h.on_llm_error(TimeoutError("upstream timed out"), run_id="r1")
        self.assertEqual(len(h.certificates), 1)
        ok, payload = cert.verify_envelope(h.certificates[0], ring_of(h))
        self.assertTrue(ok, "出错签的证书也必须是签名有效的")
        err = payload["error"]
        self.assertEqual(err["phase"], "llm")
        self.assertEqual(err["type"], "TimeoutError")
        self.assertEqual(err["scope"], "partial-prefix")
        self.assertEqual(err["tokens"], 0)
        self.assertEqual(err["text_len"], 0)

    # 反歧义的正题：会话有没有出错，只看 certificates 分不出来 → errors 分得出
    def test_error_and_clean_session_are_distinguishable(self):
        clean = PoPCallbackHandler(self.content)
        clean.on_llm_end(fake_llm_result("A safe, plain reply."), run_id="r1")
        failed = PoPCallbackHandler(self.content)
        failed.on_llm_error(RuntimeError("rate limited"), run_id="r1")
        # 两者都恰好一张证书 —— 这正是「无证书 vs 干净」之外的第二重歧义
        self.assertEqual(len(clean.certificates), len(failed.certificates))
        # 区分靠的是 error 块与 errors 清单，而不是「有没有证书」
        self.assertIsNone(cert.envelope_payload(clean.certificates[0]).get("error"))
        self.assertIsNotNone(cert.envelope_payload(failed.certificates[0]).get("error"))
        self.assertEqual(clean.errors, [])
        self.assertEqual(len(failed.errors), 1)

    # 异常消息**不进**证书（可能带 prompt 片段/请求头/密钥），只留类型名与哈希
    def test_error_message_is_hashed_not_published(self):
        import hashlib
        secret_msg = "401 Unauthorized: Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz"
        h = PoPCallbackHandler(self.content)
        h.on_llm_error(RuntimeError(secret_msg), run_id="r1")
        blob = json.dumps(h.certificates[0])
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", blob)
        self.assertNotIn("Bearer", blob)
        err = cert.envelope_payload(h.certificates[0])["error"]
        self.assertEqual(err["message_sha256"],
                         hashlib.sha256(secret_msg.encode("utf-8")).hexdigest())

    # 流中途出错：判的是**实际收到的前缀**，不是「本次生成」
    def test_midstream_error_judges_the_prefix_actually_received(self):
        h = PoPCallbackHandler(self.content)
        # 密钥被拆在两个 token 之间 —— 它是靠**累积前缀**才补全的
        h.on_llm_new_token("Leak sk-abcdefghij", run_id="r1")
        h.on_llm_new_token("klmnopqrstuvwxyz", run_id="r1")
        h.on_llm_error(ConnectionResetError("stream closed"), run_id="r1")
        payload = cert.envelope_payload(h.certificates[-1])
        # 前缀里已经有完整密钥 → 判定为违规（而不是因为「没正常结束」就记成干净）
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["error"]["tokens"], 2)
        self.assertEqual(payload["error"]["text_len"],
                         len("Leak sk-abcdefghijklmnopqrstuvwxyz"))
        # scope 把判定范围钉死：这张证书**没有**说「本次生成合规」
        self.assertEqual(payload["error"]["scope"], "partial-prefix")

    # 出错后流状态要清干净（否则下一轮会接着上一轮的缓冲累积）
    def test_error_clears_stream_state(self):
        h = PoPCallbackHandler(self.content)
        h.on_llm_new_token("partial ", run_id="r1")
        h.on_llm_error(RuntimeError("boom"), run_id="r1")
        # 清干净了才会只有新一轮的内容；没清就会是 "partial next round "
        self.assertEqual(h._sbuf, {})
        h.on_llm_new_token("next round", run_id="r1")
        self.assertEqual(h._sbuf["r1"], "next round")

    # 工具报错：照常签回执（失败也是这次调用的结果），并在顶层记 error
    def test_tool_error_still_issues_receipt_and_certificate(self):
        h = PoPCallbackHandler(self.tools)
        h.on_tool_start({"name": "search_kb"}, "{'q': 'x'}", run_id="t1")
        h.on_tool_error(RuntimeError("tool blew up"), run_id="t1")
        self.assertEqual(len(h.gateway.receipts), 1, "失败也是这次调用的结果，要留回执")
        self.assertEqual(len(h.certificates), 1)
        payload = cert.envelope_payload(h.certificates[0])
        self.assertEqual(payload["mode"], "tool-call")
        self.assertEqual(payload["error"]["phase"], "tool")
        self.assertTrue(verify_certificates(h))

    # 出错的工具回执**明文不进链**：回执里只有摘要（错误消息可能含敏感内容）
    def test_tool_error_text_is_not_published(self):
        h = PoPCallbackHandler(self.tools)
        h.on_tool_start({"name": "search_kb"}, "{'q': 'x'}", run_id="t1")
        h.on_tool_error(RuntimeError("leaked sk-abcdefghijklmnopqrstuvwxyz"), run_id="t1")
        rec = h.gateway.receipts[0].to_dict()
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", json.dumps(rec))
        self.assertTrue(rec["result_digest"])


class TestHardStopOffline(unittest.TestCase):
    """真早停（``hard_stop=True``）：把「不再出证」变成「真的把流掐断」。

    修理的是一句名不副实的话：``stop_on_violation`` 此前只做到「后续 token 不再
    出证」（``_sstopped`` 置位后忽略），**流仍然把违规内容吐完**。对真模型这不只是
    观感问题 —— 那些 token 照常计费，而早停本该是最直接的省钱手段。

    真掐断要跨过两道默认行为：① 回调抛异常会被 LangChain **吞掉**
    （``BaseCallbackHandler.raise_error`` 缺省 ``False``，只记 warning），所以
    handler 必须把它置 ``True``；② 流被掐断后 LangChain 会把这次「失败」路由到
    ``on_llm_error``，那里要**跳过** ``EarlyStop``，否则一次早停产出两张证书。
    """

    def setUp(self):
        self.content = AgentMonitor(load_pack("agent_content_v1.json"))

    def test_hard_stop_raises_and_carries_the_stop_certificate(self):
        h = PoPCallbackHandler(self.content, stop_on_violation=True, hard_stop=True)
        self.assertTrue(h.raise_error, "不置 raise_error，异常连流都出不去")
        h.on_llm_new_token("Leak sk-", run_id="r1")
        with self.assertRaises(EarlyStop) as cm:
            h.on_llm_new_token("abcdefghijklmnopqrstuvwxyz", run_id="r1")
        # 异常上带着那张 stop 证书 —— 抛出去之后本 run 的流式状态已被清掉
        payload = cert.envelope_payload(cm.exception.certificate)
        self.assertFalse(payload["outcome"]["passed"])
        stop = payload["streaming"]["stop"]
        self.assertEqual(stop["reason"], "violation")
        # 停止证书判的是**前缀**，不是完整生成 —— 早停本来就停在中途。
        # 钉死这个口径，是因为 ``partial=False`` 很容易被读成「判了全文」。
        self.assertEqual(stop["scope"], "partial-prefix")
        # 停止证书挂在链末、指向前一张（判定翻转那张）—— 它判的是那条链上的前缀。
        self.assertEqual(stop["at_index"], 1)
        self.assertEqual(payload["streaming"]["chain"]["index"], 2)
        self.assertTrue(verify_chain(h.stream_certificates),
                        "停止证书本身也要是链上合规的一环")

    def test_default_is_soft_stop(self):
        # 非恒真对照：不打开 hard_stop 时**不许**抛（这会让既有集成当场炸掉，
        # 所以它是显式选择项，不能靠升级悄悄改掉）。
        h = PoPCallbackHandler(self.content, stop_on_violation=True)
        self.assertFalse(h.raise_error)
        h.on_llm_new_token("Leak sk-abcdefghijklmnopqrstuvwxyz", run_id="r1")  # 不抛
        self.assertTrue(h._sstopped["r1"])

    def test_early_stop_does_not_produce_a_second_error_certificate(self):
        # 掐断是我们自己干的，不是模型故障；把 EarlyStop 记成模型错误是误导，
        # 也会让「一次早停 = 一张 stop 证书」这个计数对不上。
        h = PoPCallbackHandler(self.content, stop_on_violation=True, hard_stop=True)
        esc = EarlyStop("aborted", certificate={"payload": {}})
        before = len(h.certificates)
        h.on_llm_error(esc, run_id="r1")
        self.assertEqual(len(h.certificates), before, "EarlyStop 不该再签一张")
        self.assertEqual(h.errors, [esc], "但要留在 errors 清单里，否则这次中断就消失了")

    def test_other_errors_still_produce_a_certificate(self):
        # 对照：不是 EarlyStop 的异常照常出证（否则上面那条把 on_llm_error 关了）
        h = PoPCallbackHandler(self.content, stop_on_violation=True, hard_stop=True)
        h.on_llm_error(RuntimeError("rate limited"), run_id="r1")
        self.assertEqual(len(h.certificates), 1)


@unittest.skipUnless(langchain_available(), "langchain not installed")
class TestRealHardStop(unittest.TestCase):
    """真实 LangChain 流式管线上的真早停：流**确实**在违规处断了。

    离线用例只能证明「回调抛了异常」；这一条证明的是**异常真的走出了回调系统**
    （``raise_error`` 那一步没有白设），并且调用方看到的 chunk 比完整响应少。
    """

    def test_stream_is_actually_aborted(self):
        from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
        from langchain_core.messages import AIMessage

        content = AgentMonitor(load_pack("agent_content_v1.json"))
        h = PoPCallbackHandler(content, stop_on_violation=True, hard_stop=True,
                               stream_every=1)
        # GenericFakeChatModel 按空白切分：['Leak', ' ', 'sk-…', ' ', 'now']
        # 密钥在**第 3 个** chunk 才补全 —— 早停应当恰好停在这里。
        model = GenericFakeChatModel(
            messages=iter([AIMessage(content="Leak sk-abcdefghijklmnopqrstuvwxyz now")]))
        seen = []
        # LangChain 在把异常继续抛出去之前会自己记一条 warning
        # （``langchain_core.callbacks.manager``："Error in X.y callback"），
        # 那行噪声会被 unittest 原样打到 stderr、看起来像测试挂了。这里把它
        # 接住并**断言它确实发生了** —— 这条日志本身就是「异常真的走出了回调
        # 系统」的旁证（缺了它，异常可能只是被吞掉后我们碰巧没看见）。
        with self.assertLogs("langchain_core.callbacks.manager", level="WARNING"):
            with self.assertRaises(EarlyStop):
                for chunk in model.stream("hi", config={"callbacks": [h]}):
                    seen.append(chunk.content)
        delivered = "".join(seen)
        # 关键的那条：违规内容**没有**到达调用方。LangChain 先跑回调再吐 chunk，
        # 所以判出违规的那个分片本身就被截住了 —— 早停点比「不再出证」更靠前。
        self.assertNotIn("sk-abc", delivered,
                         f"泄露的密钥仍然被吐给了调用方：{delivered!r}")
        self.assertTrue("Leak sk-abcdefghijklmnopqrstuvwxyz now".startswith(delivered)
                        and len(delivered) < len("Leak sk-abcdefghijklmnopqrstuvwxyz now"),
                        f"应当是完整响应的真前缀且确实被截短，实为 {delivered!r}")
        # 早停证书在异常上，且不带权威的 llm 证书（那次生成没有正常结束）
        self.assertIsNotNone(h.stream_certificates[-1])
        self.assertEqual(len(h.certificates), 0)


class TestProofModePlumbingOffline(unittest.TestCase):
    """适配器把证据档位（P0-4）一路带到载荷：构造参数 → 每条签发路径。

    `proof_mode` 与 `vkey_hash` 是一对：只说「绑了哪个程序」而不说「这档证据
    隐藏了什么」，第三方就无从判断「响应内容被隐藏」是否成立。因此每条适配器
    路径都要能把它传下去 —— 这里逐条锁住（含流式证书，它是最容易漏的一条）。
    """

    def setUp(self):
        self.content = AgentMonitor(load_pack("agent_content_v1.json"))
        self.tools = AgentMonitor(load_pack("agent_tool_v1.json"))

    def _mode_of(self, env) -> str:
        return cert.envelope_payload(env)["binding"]["proof_mode"]

    def test_handler_threads_mode_to_generate_and_tool_paths(self):
        h = PoPCallbackHandler(self.content, proof_mode="core")
        h.on_llm_end(fake_llm_result("A safe, plain reply."), run_id="r1")   # 权威证书
        h.on_llm_new_token("A safe", run_id="r2")                            # 流式部分证书
        assert h.stream_certificates, "流式路径未产出证书，用例前提不成立"

        tools_h = PoPCallbackHandler(self.tools, proof_mode="compressed")
        tools_h.on_tool_start({"name": "search_kb"}, "{'q': 'refund'}", run_id="t1")
        tools_h.on_tool_end("ok", run_id="t1")

        for env in h.certificates + h.stream_certificates:
            self.assertEqual(self._mode_of(env), "core")
        self.assertEqual(self._mode_of(tools_h.certificates[0]), "compressed")

    def test_default_is_unproven_not_a_guess(self):
        # 不给模式、也不给工件 ⇒ 只能标 unproven（而不是默默算成某一档证据）。
        h = PoPCallbackHandler(self.content)
        h.on_llm_end(fake_llm_result("fine"), run_id="r1")
        self.assertEqual(self._mode_of(h.certificates[0]), cert.PROOF_MODE_UNPROVEN)


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
        ok, payload = cert.verify_envelope(out["certificates"][0], ring_of(self.content))
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])

    # guard_node 包装工具节点：节点返回的 (name, args) 形状会被送进策略判定
    def test_guard_tool_node(self):
        def node(state):
            return {"name": "search_kb", "args": {"q": "x", "api_key": "k"}}

        g = lg.guard_node(self.tools, node, kind="tool")
        out = g({})
        _, payload = cert.verify_envelope(out["certificates"][0], ring_of(self.tools))
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

    def test_guard_class_shares_one_gateway(self):
        """回调与节点必须绑**同一条**轨迹（dev-plan §5.1.2 第 1 条）。

        缺省各建一把网关时，`callbacks()` 出的内容证书与 `tool_node()` 出的工具
        证书会落在两条不同的链上 —— 与 `demo_e2e.py` 里那处缝是同一个。
        """
        # 用**工具策略**的 monitor：它同时判得动工具回执与生成文本，所以
        # 「一次会话走两条链」这件事能在同一个 guard 上真的跑一遍。
        guard = lg.LangGraphGuard(self.tools)
        h = guard.callbacks()
        self.assertIs(h.gateway, guard.gateway)
        tool = guard.tool_node(lambda s: {"name": "search_kb", "args": {"q": "refund"}})
        tool({"certificates": []})
        gen = guard.generate_node(lambda s: {"output": "A safe reply."})
        out = gen({"certificates": []})
        # 两次调用后链上有了那条工具回执，内容证书必须封在同一条链上
        seal = cert.envelope_payload(out["certificates"][-1])["trace_seal"]
        self.assertEqual(seal["keyid"], guard.gateway.signer.keyid)
        self.assertEqual(seal["count"], len(guard.gateway.receipts))
        self.assertEqual(seal["trace_root"], guard.gateway.trace_root)

    def test_guard_class_accepts_an_outer_gateway(self):
        # 要接进外层已有的会话（例如 MCPGuard 那把），必须能注入而不是被迫新建
        from policydsl.trace import ToolGateway
        outer = ToolGateway()
        guard = lg.LangGraphGuard(self.content, gateway=outer)
        self.assertIs(guard.gateway, outer)
        self.assertIs(guard.callbacks().gateway, outer)

    def test_guard_node_threads_proof_mode(self):
        # P0-4：guard_node 的 proof_mode 必须落到它签发的每张证书上（两条 kind 都验）。
        gen = lg.guard_node(self.content, lambda s: {"output": "A safe reply."},
                            kind="generate", proof_mode="groth16")(
            {"certificates": []})
        tool = lg.guard_node(self.tools,
                             lambda s: {"name": "search_kb", "args": {"q": "refund"}},
                             kind="tool", proof_mode="groth16")(
            {"certificates": []})
        for out in (gen, tool):
            self.assertEqual(cert.envelope_payload(out["certificates"][-1])["binding"]["proof_mode"],
                             "groth16")

    def test_guard_node_default_is_unproven(self):
        out = lg.guard_node(self.content, lambda s: {"output": "ok"}, kind="generate")(
            {"certificates": []})
        self.assertEqual(cert.envelope_payload(out["certificates"][-1])["binding"]["proof_mode"],
                         cert.PROOF_MODE_UNPROVEN)

    # 缺少 langgraph 时 require_langgraph 必须显式报错，而不是让后续静默失效
    def test_require_langgraph_raises_without_dep(self):
        if lg.langgraph_available():  # pragma: no cover
            self.skipTest("langgraph installed")
        with self.assertRaises(RuntimeError):
            lg.require_langgraph()


class TestLangGraphErrorEventsOffline(unittest.TestCase):
    """`LangGraphEventCertifier` 的错误事件（离线，直接喂事件）。

    与 :class:`TestErrorCallbacksOffline` 同一件事的另一半：回调式插桩有
    ``on_llm_error``，而事件式插桩是**手写路由**（``_handle`` 按事件名分发），
    它不会自动继承那边的新分支 —— 少了这个分支，一次失败的图运行同样会
    「一张证书都不留」。所以这条路由要单独锁住。
    """

    def setUp(self):
        self.content = AgentMonitor(load_pack("agent_content_v1.json"))
        self.tools = AgentMonitor(load_pack("agent_tool_v1.json"))

    def _err_event(self, name, **kw):
        ev = {"event": name, "run_id": "r1", "name": "m"}
        ev.update(kw)
        return ev

    def test_chat_model_error_issues_error_certificate(self):
        c = lg.LangGraphEventCertifier(self.content, vkey_hash="vk1")
        err = TimeoutError("model timed out")
        c._handle(self._err_event("on_chat_model_error", data={"error": err}))
        self.assertEqual(len(c.certificates), 1)
        ok, payload = cert.verify_envelope(c.certificates[0], ring_of(self.content))
        self.assertTrue(ok)
        self.assertEqual(payload["error"]["phase"], "llm")
        self.assertEqual(payload["error"]["type"], "TimeoutError")
        self.assertEqual(c.errors, [err])

    def test_llm_error_alias_is_routed_too(self):
        # astream_events v2 对聊天模型用 on_chat_model_error；纯 LLM 用 on_llm_error。
        # 两条都要认，否则「哪种模型」会决定「出错有没有留痕」。
        c = lg.LangGraphEventCertifier(self.content)
        c._handle(self._err_event("on_llm_error", data={"error": RuntimeError("x")}))
        self.assertEqual(len(c.certificates), 1)

    def test_model_error_judges_the_partial_prefix(self):
        # 出错前流式 handler 已经收到分片 → 判的是**实际收到的前缀**，不是空串。
        h = PoPCallbackHandler(self.content)
        h.on_llm_new_token("Leak sk-abcdefghijklmnopqrstuvwxyz", run_id="r1")
        c = lg.LangGraphEventCertifier(self.content, stream_handler=h)
        c._handle(self._err_event("on_chat_model_error", data={"error": RuntimeError("boom")}))
        payload = cert.envelope_payload(c.certificates[-1])
        self.assertFalse(payload["outcome"]["passed"])
        self.assertEqual(payload["error"]["scope"], "partial-prefix")
        self.assertEqual(payload["error"]["text_len"], len("Leak sk-abcdefghijklmnopqrstuvwxyz"))

    def test_tool_error_still_issues_receipt_and_certificate(self):
        c = lg.LangGraphEventCertifier(self.content, tool_monitor=self.tools)
        err = RuntimeError("tool blew up")
        c._handle(self._err_event("on_tool_error", data={"error": err, "input": {"q": "x"}}))
        self.assertEqual(len(c.gateway.receipts), 1)
        self.assertEqual(len(c.certificates), 1)
        payload = cert.envelope_payload(c.certificates[0])
        self.assertEqual(payload["mode"], "tool-call")
        self.assertEqual(payload["error"]["phase"], "tool")

    # 非恒真对照：没有错误事件时，errors 必须是空的（否则上面几条不说明问题）
    def test_clean_run_has_no_errors(self):
        c = lg.LangGraphEventCertifier(self.content)
        c._handle({"event": "on_chat_model_end", "run_id": "r1",
                   "data": {"output": types.SimpleNamespace(
                       content="A safe, plain reply.")}})
        self.assertEqual(len(c.certificates), 1)
        self.assertEqual(c.errors, [])
        self.assertIsNone(cert.envelope_payload(c.certificates[0]).get("error"))


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
        ok, payload = cert.verify_envelope(h.certificates[0], ring_of(h))
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
        ok, payload = cert.verify_envelope(h.certificates[0], ring_of(h))
        self.assertTrue(ok)
        self.assertTrue(payload["outcome"]["passed"])
        self.assertEqual(payload["mode"], "public")

    # 端到端（违规）：同一链路下含密钥的输出应被判违规
    def test_real_llm_end_to_end_violation(self):
        monitor = AgentMonitor(load_pack("agent_content_v1.json"))
        h = PoPCallbackHandler(monitor)
        self._fake_llm("Leak sk-abcdefghijklmnopqrstuvwxyz").invoke(
            "hi", config={"callbacks": [h]})
        _, payload = cert.verify_envelope(h.certificates[0], ring_of(h))
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
        _, payload = cert.verify_envelope(h.certificates[-1], ring_of(h))
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
        ok, payload = cert.verify_envelope(h.stream_certificates[0], ring_of(h))
        self.assertTrue(ok)
        self.assertTrue(payload["streaming"]["partial"])
        self.assertTrue(payload["outcome"]["passed"])

    # 违规是在流中途才可判定的：密钥模式凑齐的瞬间应立刻翻转并出证
    def test_stream_detects_violation_midstream(self):
        h = PoPCallbackHandler(self.monitor)
        self._feed(h, "x sk-abcdefghijklmnopqrstuvwxyz")
        # None->True，随后密钥模式匹配完成时 True->False
        self.assertGreaterEqual(len(h.stream_certificates), 2)
        _, last = cert.verify_envelope(h.stream_certificates[-1], ring_of(h))
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
        _, stop = cert.verify_envelope(h.stream_certificates[-1], ring_of(h))
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
            ok, _ = cert.verify_envelope(env, ring_of(h))
            self.assertTrue(ok)
        # 最终（权威）证书标记了违规
        _, final = cert.verify_envelope(h.certificates[-1], ring_of(h))
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
        ok, _ = cert.verify_envelope(out["certificates"][0], ring_of(monitor))
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
            ok, payload = cert.verify_envelope(env, ring_of(certifier))
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
