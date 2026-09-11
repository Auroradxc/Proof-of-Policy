"""LangChain 回调处理器：为 Proof-of-Policy 签发证书。

LangChain 与 LangGraph 共享同一套回调系统（``langchain_core.callbacks``），
因此这一个 handler 同时插桩**两者**：

  - LangChain: ``chain.invoke(x, config={"callbacks": [handler]})``
  - LangGraph: ``graph.invoke(state, config={"callbacks": [handler]})``

每次 LLM 完成时，为生成路径签发证书（``AgentMonitor.on_generate``）；
每次工具调用结束时，为工具路径签发证书（``AgentMonitor.on_tool_call``）。

该 handler 在未安装 LangChain 时也能工作（鸭子类型的基类），因此可以离线
单测；当 LangChain 存在时，它继承真正的 ``BaseCallbackHandler``，可直接传入
callbacks 配置。
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional

from .agent import AgentMonitor
from . import cert as _cert
from .trace import ToolGateway, extract_result_text

try:  # 有 LangChain 时用真实基类
    from langchain_core.callbacks import BaseCallbackHandler  # type: ignore

    HAVE_LANGCHAIN = True
except Exception:  # pragma: no cover - 取决于环境
    HAVE_LANGCHAIN = False

    class BaseCallbackHandler:  # 极简鸭子类型回退
        raise_error = False


def langchain_available() -> bool:
    """LangChain 是否可用。"""
    return HAVE_LANGCHAIN


def langgraph_available() -> bool:
    """LangGraph 是否可用（延迟 import 探测）。"""
    try:
        import langgraph  # noqa: F401

        return True
    except Exception:
        return False


def _extract_text(response: Any) -> str:
    """从 LLMResult / generations 结构里尽力提取文本。

    LangChain 不同版本返回结构各异（text / message.content / content parts），
    这里做多分支兼容，取不到就返回空串。
    """
    try:
        generations = getattr(response, "generations", None) or []
        if generations and generations[0]:
            gen = generations[0][0]
            text = getattr(gen, "text", None)
            if isinstance(text, str) and text:
                return text
            msg = getattr(gen, "message", None)
            if msg is not None:
                content = getattr(msg, "content", None)
                if isinstance(content, str):
                    return content
                if isinstance(content, list):
                    parts = [p.get("text", "") if isinstance(p, dict) else str(p) for p in content]
                    return "".join(parts)
    except Exception:
        pass
    return ""


def _tool_name(serialized: Any, kwargs: Dict[str, Any]) -> str:
    """从序列化信息/回调 kwargs 里提取工具名。"""
    if isinstance(serialized, dict) and serialized.get("name"):
        return str(serialized["name"])
    return str(kwargs.get("name") or "tool")


def _parse_args(input_str: Any) -> Dict[str, Any]:
    """把工具调用的输入规整成参数字典。

    可能已是 dict、可能是 JSON/字面量字符串、也可能是任意对象。
    """
    if isinstance(input_str, dict):
        return input_str
    if isinstance(input_str, str):
        try:
            val = ast.literal_eval(input_str)
            if isinstance(val, dict):
                return {str(k): v for k, v in val.items()}
        except (ValueError, SyntaxError):
            pass
        return {"input": input_str}
    return {"input": input_str}


class PoPCallbackHandler(BaseCallbackHandler):
    """在 LLM 结束与工具结束事件上签发证书。

    流式（增量）证书：``stream_check=True``（默认）时，``on_llm_new_token``
    累积响应前缀；每当合规判定**发生变化**（例如某秘密模式在流中途补全），
    就签发一张**部分**证书（``streaming.partial = true``），使监控方能
    提前告警/早停。``on_llm_end`` 签发的证书仍是权威的那一张。
    """

    def __init__(self, monitor: AgentMonitor, vkey_hash: str = "unproven",
                 proof_sha256: Optional[str] = None, on_cert=None,
                 stream_check: bool = True, stream_every: int = 1,
                 on_stream_cert=None, stop_on_violation: bool = False,
                 on_early_stop=None, proof_mode: Optional[str] = None,
                 gateway: Optional[ToolGateway] = None):
        super().__init__()
        self.monitor = monitor
        # 工具网关（P1-5）：工具回执由它签发（``on_tool_end`` 在工具**执行后**
        # 触发，此刻结果已经拿到，所以能签出含结果摘要的真回执）。
        self.gateway = gateway if gateway is not None else ToolGateway()
        self.vkey_hash = vkey_hash
        self.proof_sha256 = proof_sha256
        # 诚实标注（P0-4）：这张 handler 签出的证书，证据属于哪一档证明模式。
        # 默认 None → build_payload 按「没附工件」记 unproven。
        self.proof_mode = proof_mode
        self.on_cert = on_cert
        self.certificates: List[Dict[str, Any]] = []
        self._tool_starts: Dict[str, Dict[str, Any]] = {}
        # 流式状态
        self.stream_check = stream_check
        self.stream_every = max(1, stream_every)
        self.on_stream_cert = on_stream_cert
        self.stop_on_violation = stop_on_violation
        self.on_early_stop = on_early_stop
        self.stream_certificates: List[Dict[str, Any]] = []
        self.stream_chains: Dict[str, List[str]] = {}   # run_id -> [载荷摘要]
        self._sbuf: Dict[str, str] = {}                 # run_id -> 累积的流式前缀
        self._scount: Dict[str, int] = {}               # run_id -> token 计数
        self._sverdict: Dict[str, bool] = {}            # run_id -> 上次判定
        self._sstopped: Dict[str, bool] = {}            # run_id -> 是否已早停

    # -- 辅助方法 --
    def _emit(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """登记并回调一张证书。"""
        self.certificates.append(envelope)
        if self.on_cert is not None:
            self.on_cert(envelope)
        return envelope

    def stream_chain(self, run_id: str) -> List[str]:
        """返回该 run 的流式证书链的载荷摘要列表。"""
        return list(self.stream_chains.get(run_id, []))

    def _stream_cert(self, run_id: str, text: str, partial: bool, extra_stream: Dict[str, Any]):
        """签发一张流式证书，链接到上一张（形成哈希链）。"""
        chain = self.stream_chains.setdefault(run_id, [])
        index = len(chain)
        prev = chain[-1] if chain else "genesis"
        stream = {"partial": partial, "tokens": self._scount.get(run_id, 0),
                  "chain": {"index": index, "prev": prev}}
        stream.update(extra_stream)
        env = self.monitor.on_generate(text, vkey_hash=self.vkey_hash,
                                       proof_sha256=self.proof_sha256,
                                       proof_mode=self.proof_mode,
                                       extra={"streaming": stream})
        chain.append(_cert_digest(env))
        return env

    # -- LLM（生成路径） --
    def on_llm_new_token(self, token: str, **kwargs: Any) -> None:
        """累积流式前缀；判定变化时签发链式部分证书，
        并在（可选的）首次违规时签早停证书。"""
        run_id = str(kwargs.get("run_id") or "")
        if self._sstopped.get(run_id):
            return  # 已早停：忽略后续 token
        self._sbuf[run_id] = self._sbuf.get(run_id, "") + (token or "")
        self._scount[run_id] = self._scount.get(run_id, 0) + 1
        if not self.stream_check or self._scount[run_id] % self.stream_every != 0:
            return
        outcome = self.monitor.generate_outcome(self._sbuf[run_id])
        verdict = bool(outcome["passed"])
        prev = self._sverdict.get(run_id)
        if prev is None or prev != verdict:
            # 判定首次出现或发生翻转 → 签发部分证书
            env = self._stream_cert(run_id, self._sbuf[run_id], partial=True, extra_stream={})
            self.stream_certificates.append(env)
            if self.on_stream_cert is not None:
                self.on_stream_cert(env)
            self._sverdict[run_id] = verdict
            if verdict is False and self.stop_on_violation:
                # 首次违规：再签一张「停止」证书并标记早停
                idx = len(self.stream_chains[run_id]) - 1
                stop_env = self._stream_cert(
                    run_id, self._sbuf[run_id], partial=False,
                    extra_stream={"stop": {"reason": "violation",
                                           "at_index": idx,
                                           "chain_head": self.stream_chains[run_id][idx]}})
                self.stream_certificates.append(stop_env)
                if self.on_early_stop is not None:
                    self.on_early_stop(stop_env)
                self._sstopped[run_id] = True

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """LLM 完成：签发权威证书（优先用流式缓冲，回退到结构提取）。"""
        run_id = str(kwargs.get("run_id") or "")
        # 优先用流式缓冲（所见 token 精确）；否则从 response 结构提取
        text = self._sbuf.get(run_id) or _extract_text(response)
        # 清理该 run 的流式状态
        self._sbuf.pop(run_id, None)
        self._scount.pop(run_id, None)
        self._sverdict.pop(run_id, None)
        self._sstopped.pop(run_id, None)
        if text:
            self._emit(self.monitor.on_generate(text, vkey_hash=self.vkey_hash,
                                                proof_sha256=self.proof_sha256,
                                                proof_mode=self.proof_mode))

    # -- 工具（工具调用路径） --
    def on_tool_start(self, serialized: Any, input_str: Any, **kwargs: Any) -> None:
        """工具开始：记录工具名与参数，供 on_tool_end 使用。"""
        run_id = str(kwargs.get("run_id") or "")
        self._tool_starts[run_id] = {"name": _tool_name(serialized, kwargs),
                                     "args": _parse_args(input_str)}

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        """工具结束：网关签发回执，再凭回执签发工具调用证书（P1-5）。"""
        run_id = str(kwargs.get("run_id") or "")
        rec = self._tool_starts.pop(run_id, None) or {"name": _tool_name(None, kwargs), "args": {}}
        receipt = self.gateway.issue(rec["name"], rec["args"],
                                     result=extract_result_text(output))
        self._emit(self.monitor.on_tool_call(receipt, vkey_hash=self.vkey_hash,
                                             proof_mode=self.proof_mode,
                                             chain=self.gateway.receipts))


def verify_certificates(handler: "PoPCallbackHandler", keyring: Any = None) -> bool:
    """截至目前签发的所有证书都能验证通过。

    ``keyring`` 可以是 ``Signer`` / 公钥 / ``{keyid: 验签器}`` / 裸 ``bytes``
    （旧式 HMAC，仅测试）。**缺省用 handler 自己的签名器**——那是「自验签」，
    对 demo/测试够用；第三方验证必须传入**公钥**，见 ``policydsl.keys``。
    """
    kr = keyring if keyring is not None else handler.monitor.signer
    return all(_cert.verify_envelope(env, kr)[0] for env in handler.certificates)


def _cert_digest(env: Dict[str, Any]) -> str:
    """证书载荷的稳定摘要（流式链的链接值）。"""
    return _cert.cert_digest(_cert.envelope_payload(env))


def verify_chain(certs: List[Dict[str, Any]]) -> bool:
    """验证流式证书链（序号连续 + prev 链接）。

    每张证书须携带 ``streaming.chain = {index, prev}``，其中 index 是其位置，
    prev 是上一张证书的摘要（首张为 ``"genesis"``）。可检测重排、插入与篡改。
    """
    prev = "genesis"
    for i, env in enumerate(certs):
        payload = _cert.envelope_payload(env)
        chain = (payload.get("streaming") or {}).get("chain")
        if not chain or chain.get("index") != i or chain.get("prev") != prev:
            return False
        prev = _cert.cert_digest(payload)
    return True
