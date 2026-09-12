"""Proof-of-Policy 的 LangGraph 集成。

支持两种接线方式（都驱动同一个 ``AgentMonitor``）：

1. **回调**（不改图）：LangGraph 会路由 LangChain 回调，因此：

       handler = attach(monitor)                       # 得到 PoPCallbackHandler
       graph.invoke(state, config={"callbacks": [handler]})
       # handler.certificates 现在每个 LLM/工具事件一张证书

2. **节点包装**（显式、框架原生）：包装一个生成或工具节点，使其输出被判定，
   证书被写入状态：

       generate = guard_node(monitor, my_generate_node, kind="generate", key="output")
       tool     = guard_node(monitor, my_tool_node, kind="tool")

LangGraph 本身是可选的；``require_langgraph()`` 在需要却缺失时抛出明确错误，
下面的辅助函数作用于普通可调用对象，因此可在无 LangGraph 时单测。
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from .agent import AgentMonitor
from .langchain_adapter import (  # noqa: F401
    PoPCallbackHandler, _extract_text, langgraph_available,
)
from .trace import ToolGateway, extract_result_text


def _content_text(obj: Any) -> str:
    """从类消息输出里取文本（``.content`` 字符串或 content parts）。"""
    content = getattr(obj, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict):
                parts.append(str(p.get("text", "")))
            else:
                parts.append(str(p))
        return "".join(parts)
    return ""


def require_langgraph() -> Any:
    """导入 langgraph，失败则给出可操作的错误信息。"""
    try:
        import langgraph  # noqa: F401

        return langgraph
    except ImportError as exc:  # pragma: no cover - 取决于环境
        raise RuntimeError(
            "LangGraph is not installed. Install with `pip install langgraph langchain` "
            "(see requirements-frameworks.txt); the AgentMonitor hooks and the "
            "guard_node/attach helpers need no adapter rewrite."
        ) from exc


def attach(monitor: AgentMonitor, graph: Any = None, **handler_kwargs: Any) -> PoPCallbackHandler:
    """返回一个回调 handler，用于 ``graph.invoke(..., config={"callbacks":[h]})``。

    ``graph`` 参数仅为可读性而接受，并不修改它（编译后的 LangGraph 图不可变）；
    调用方把 handler 放进 invoke 配置即可。
    """
    return PoPCallbackHandler(monitor, **handler_kwargs)


def guard_node(monitor: AgentMonitor, node: Callable[..., Any], kind: str = "generate",
               key: str = "output", certs_key: str = "certificates",
               vkey_hash: str = "unproven", proof_sha256: Optional[str] = None,
               proof_mode: Optional[str] = None,
               tool_name_key: str = "name", tool_args_key: str = "args",
               gateway: Optional[ToolGateway] = None) -> Callable[..., Dict[str, Any]]:
    """包装一个 LangGraph 节点，使其结果被判定并签发证书。

    kind="generate"：读取 ``result[key]`` 作为响应文本。
    kind="tool"：    读取 ``result[tool_name_key]`` / ``result[tool_args_key]``；
                     节点**已经返回**（工具已经跑完），因此网关在此刻签发
                     含结果摘要的回执（P1-5）。
    返回的字典 = 原节点结果 + ``certs_key``（证书列表）。
    """
    gw = gateway if gateway is not None else ToolGateway()

    def wrapped(state: Any, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        result = node(state, *args, **kwargs)
        if not isinstance(result, dict):
            result = {key: result}
        certs: List[Dict[str, Any]] = list(result.get(certs_key, []))
        if kind == "generate":
            raw = result.get(key, "")
            text = raw if isinstance(raw, str) else str(raw)
            # 与工具路径同源：生成证书也绑整条回执链并附网关的会话末端承诺——
            # 否则它在 verify_cert.py 的 trace_seal 卡上无从排除链尾被删（P1-5b）。
            certs.append(monitor.on_generate(text, vkey_hash=vkey_hash,
                                             proof_sha256=proof_sha256,
                                             proof_mode=proof_mode,
                                             receipts=gw.receipts,
                                             seal=gw.seal()))
        elif kind == "tool":
            name = str(result.get(tool_name_key, "tool"))
            targs = result.get(tool_args_key, {}) or {}
            receipt = gw.issue(name, targs,
                               result=extract_result_text(result.get(key, "")))
            certs.append(monitor.on_tool_call(receipt, vkey_hash=vkey_hash,
                                              proof_mode=proof_mode,
                                              chain=gw.receipts,
                                              seal=gw.seal()))
        else:
            raise ValueError("kind must be 'generate' or 'tool'")
        out = dict(result)
        out[certs_key] = certs
        return out

    return wrapped


class LangGraphGuard:
    """便捷包装器：把一个 monitor 绑定到节点工厂。"""

    def __init__(self, monitor: AgentMonitor, **handler_kwargs: Any):
        self.monitor = monitor
        self._handler_kwargs = handler_kwargs

    def callbacks(self) -> PoPCallbackHandler:
        return attach(self.monitor, **self._handler_kwargs)

    def generate_node(self, node: Callable[..., Any], **kw: Any) -> Callable[..., Dict[str, Any]]:
        return guard_node(self.monitor, node, kind="generate", **kw)

    def tool_node(self, node: Callable[..., Any], **kw: Any) -> Callable[..., Dict[str, Any]]:
        return guard_node(self.monitor, node, kind="tool", **kw)


class LangGraphEventCertifier:
    """通过消费 ``astream_events`` 为整次 LangGraph 运行签发证书。

    为每次聊天模型完成（生成路径）与每次结束的工具调用（工具路径）签发证书；
    可选地把 token 分片喂给 ``PoPCallbackHandler``，从而同时产出流式（增量）
    证书。记录所见事件名用于可观测性。
    """

    def __init__(self, monitor: AgentMonitor, tool_monitor: Optional[AgentMonitor] = None,
                 vkey_hash: str = "unproven",
                 stream_handler: Optional[PoPCallbackHandler] = None,
                 proof_mode: Optional[str] = None,
                 gateway: Optional[ToolGateway] = None):
        self.monitor = monitor
        self.tool_monitor = tool_monitor or monitor
        self.vkey_hash = vkey_hash
        # 工具网关（P1-5）：``on_tool_end`` 在工具执行后触发，正好能签出含
        # 结果摘要的回执。未显式给出时沿用流式 handler 的网关（同一会话同一条链）。
        self.gateway = (gateway if gateway is not None
                        else getattr(stream_handler, "gateway", None) or ToolGateway())
        # 未显式给出时，沿用流式 handler 的标注（两者本就是同一份证据）
        self.proof_mode = (proof_mode if proof_mode is not None
                           else getattr(stream_handler, "proof_mode", None))
        self.stream_handler = stream_handler
        self.certificates: List[Dict[str, Any]] = []
        self.events: List[str] = []

    async def run(self, graph: Any, inputs: Any, config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """异步运行图并消费事件流，返回证书列表。"""
        cfg = dict(config or {})
        try:
            agen = graph.astream_events(inputs, config=cfg)
        except TypeError:  # 旧/新签名需要 version 参数
            agen = graph.astream_events(inputs, config=cfg, version="v2")
        async for event in agen:
            self._handle(event)
        return self.certificates

    def run_sync(self, graph: Any, inputs: Any, config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """同步便捷封装（内部 asyncio.run）。"""
        import asyncio

        return asyncio.run(self.run(graph, inputs, config))

    def _handle(self, event: Dict[str, Any]) -> None:
        """处理单个事件：按事件类型路由到生成路径 / 工具路径。"""
        name = event.get("event", "")
        self.events.append(name)
        data = event.get("data") or {}
        run_id = str(event.get("run_id") or "")
        if name in ("on_chat_model_stream", "on_llm_stream"):
            # 流式分片：喂给流式 handler（若配置）以产出增量证书
            chunk = data.get("chunk")
            text = getattr(chunk, "content", None)
            if self.stream_handler is not None and isinstance(text, str) and text:
                self.stream_handler.on_llm_new_token(text, run_id=run_id)
        elif name in ("on_chat_model_end", "on_llm_end"):
            # 模型完成：签发生成证书
            text = _extract_text(data.get("output")) or _content_text(data.get("output"))
            if text:
                # 同 ``guard_node``：生成证书也绑链 + 附会话末端承诺（P1-5b）。
                self.certificates.append(self.monitor.on_generate(
                    text, vkey_hash=self.vkey_hash, proof_mode=self.proof_mode,
                    receipts=self.gateway.receipts, seal=self.gateway.seal()))
        elif name == "on_tool_end":
            # 工具结束：签发工具证书
            tool = str(event.get("name") or "tool")
            args = data.get("input") or {}
            if not isinstance(args, dict):
                args = {"input": args}
            receipt = self.gateway.issue(tool, args,
                                         result=extract_result_text(data.get("output")))
            self.certificates.append(
                self.tool_monitor.on_tool_call(receipt, vkey_hash=self.vkey_hash,
                                               proof_mode=self.proof_mode,
                                               chain=self.gateway.receipts,
                                               seal=self.gateway.seal()))
