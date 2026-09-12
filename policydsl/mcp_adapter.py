"""Proof-of-Policy 的 MCP（Model Context Protocol）守护。

包装一个真实 MCP 客户端会话，使每次工具调用在**执行前**就被策略判定并签发证书：

    guard = MCPGuard(monitor, block_on_violation=True)
    result, cert = await guard.call_tool(session, "search_kb", {"query": "x"})

- 参数经由 ``AgentMonitor.on_tool_call`` 检查（tool_arg_guard / budget_bound），
  每次调用产出一张证书；
- 当 ``block_on_violation=True`` 时，违规调用会在到达服务器**之前**被拒绝
  （飞行前守护），并抛出 ``MCPBlocked``；
- 先用 ``await guard.discover_tools(session)`` 问服务器要工具清单（``tools/list``），
  未声明的工具会在执行前被拦下（``MCPUnknownTool``）—— 写死的工具名在服务器改名
  之后不会报错，只会静默地跑成另一次调用；
- 该类对任何暴露 ``async call_tool(name, args)``（及可选的 ``async list_tools()``）
  的对象都适用（真实的 ``mcp.ClientSession`` 或测试里的 fake）。
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .agent import AgentMonitor
from .trace import ToolGateway, ToolReceipt


class MCPBlocked(Exception):
    """当工具调用/结果违反策略且启用拦截时抛出。"""

    def __init__(self, tool: str, violations: List[Dict[str, Any]], phase: str = "args"):
        super().__init__(f"tool '{tool}' blocked by policy at {phase}: {violations}")
        self.tool = tool
        self.violations = violations
        self.phase = phase


class MCPUnknownTool(MCPBlocked):
    """调用了服务器**没有声明**的工具 —— 在执行之前就被拦下。

    与策略违规分列，是因为它拦的是另一件事：不是「这次调用不合规」，而是
    「这次调用根本不存在」。真 agent 面对的是会变的服务器，写死的工具名
    在服务器改名之后不会报错，只会静默地跑成另一次调用。

    继承 ``MCPBlocked`` 是为了不改变调用方的 ``except`` 语义 —— ``phase``
    字段（``"unknown-tool"``）足以把两者分开。
    """

    def __init__(self, tool: str, known: "Sequence[str]"):
        self.known = sorted(known)
        super().__init__(tool, [], phase="unknown-tool")
        self.args = (
            f"tool '{tool}' is not advertised by the server "
            f"(known: {', '.join(self.known) or '(none)'})",)


#: 从 MCP CallToolResult / content 列表 / 普通值里尽力提取文本。
#: 实体在 :mod:`policydsl.trace`（LangChain/LangGraph 适配器也要用它给回执
#: 算结果摘要），这里保留同名再导出，免得既有调用点改路径。
from .trace import extract_result_text  # noqa: E402,F401


class MCPGuard:
    """为 MCP 工具调用（参数）及（可选的）其结果签发证书。

    ``result_monitor``（一个内容策略 ``AgentMonitor``）判定工具的*返回文本*，
    并签发 ``tool-result`` 证书；当 ``block_on_result_violation=True`` 时，
    违规结果在调用后被拒绝（抛 ``MCPBlocked``，``phase="result"``）。
    """

    def __init__(self, monitor: AgentMonitor, vkey_hash: str = "unproven",
                 block_on_violation: bool = False, on_cert=None,
                 result_monitor: Optional[AgentMonitor] = None,
                 block_on_result_violation: bool = False, on_result_cert=None,
                 proof_mode: Optional[str] = None,
                 gateway: Optional[ToolGateway] = None):
        self.monitor = monitor
        self.vkey_hash = vkey_hash
        # 诚实标注（P0-4）：本 guard 签出的证书属于哪一档证明模式；
        # None → build_payload 按「未附工件」记 unproven。
        self.proof_mode = proof_mode
        self.block_on_violation = block_on_violation
        self.on_cert = on_cert
        self.certificates: List[Dict[str, Any]] = []
        self.result_monitor = result_monitor
        self.block_on_result_violation = block_on_result_violation
        self.on_result_cert = on_result_cert
        self.result_certificates: List[Dict[str, Any]] = []
        # 工具网关（P1-5）：回执由它签发。缺省用进程内临时 Ed25519 钥；
        # 要跨进程/跨方验证回执链，请显式传入持有真实钥的网关。
        self.gateway = gateway if gateway is not None else ToolGateway()
        #: 服务器声明的工具名单（``discover_tools`` 之后才有）。None = 还没问过
        #: ⇒ 不做存在性检查；一旦问过，调用未声明的工具就在执行前被拦下。
        #: 不设缺省空集：那会把「没发现」读成「一个工具都没有」而全部拦掉。
        self.tool_names: Optional[List[str]] = None

    @property
    def receipts(self) -> List[ToolReceipt]:
        """本 guard 到目前为止签发的回执链（交给生成路径一并出证）。"""
        return self.gateway.receipts

    async def discover_tools(self, session: Any) -> List[str]:
        """从服务器动态取工具清单（MCP 的 ``tools/list``）。

        清单**不是判定输入**（判定用的是策略包，与工具叫什么无关），它是
        「这次调用打不打得中」的前提。写死工具名的演示在服务器改名之后不会
        报错，只会静默地跑成另一次调用 —— 那正是这个项目最反对的失败模式。

        对任何暴露 ``async list_tools()`` 的对象都适用（与 ``call_tool`` 同样的
        鸭子类型约定）；返回排好序的名字，并存进 :attr:`tool_names` 供
        :meth:`call_tool` 做执行前检查。
        """
        listed = await session.list_tools()
        names = sorted(str(getattr(t, "name", t)) for t in getattr(listed, "tools", listed))
        self.tool_names = names
        return names

    def check(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """**飞行前**筛一遍参数，返回证书信封（不真正调用工具）。

        P1-5 的诚实边界：此刻工具**还没执行**，结果摘要无从谈起，所以这里用的
        是一条**预览回执**（``ToolGateway.preview``）—— 工具名与参数与真正要
        执行的那次逐字节相同，只有 ``result_digest`` 尚待确定。它的
        ``trace_root`` 因此是**临时的**：``call_tool`` 会在执行后用真回执
        （含结果摘要）重新出证，那张才是随证明走的那一张。

        单独调用本方法（不进 ``call_tool``）的含义就是「只筛不出证」，
        信封里的 ``trace_root`` 请按预览值理解。
        """
        env = self._screen(name, arguments)
        self.certificates.append(env)
        if self.on_cert is not None:
            self.on_cert(env)
        return env

    def _screen(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """飞行前筛查（**不进** ``self.certificates``）：判定用的预览回执。

        预览回执**接在现有链尾**（``seq = len(chain)``、``prev = 链尾摘要``），
        于是判定时给的是一条结构自洽的链 ``[*chain, preview]`` —— 否则第二次
        起的每次筛查都会被自己的 seq 判成 ``trace_unbound``。因为预览还没入链，
        这张证书里的 ``trace_root`` 是**「链 + 这次待执行调用」**的摘要，
        与真出证时的链尾（``call_tool`` 第 4 步）不是同一个值。

        也因此它**天然没有 seal**（P1-5b）：网关只对**真实发生过**的链签会话
        末端承诺，而这次调用还没执行 —— 给它配一条 seal 等于让网关为一次尚未
        发生的调用背书。所以筛查证书是**预检告知**而不是证据：验证方**给了
        --gateway-key** 时（=它知道这段会话有网关），``verify_cert.py`` 会对它报
        ``trace_seal`` FAIL（连带 ``trace_binding`` 也对不上真链），这是**正确**的
        结论，不是缺陷。要可核验的轨迹证据，请看 ``call_tool`` 第 4 步出的那张。
        """
        preview = self.gateway.preview(name, arguments or {})
        return self.monitor.on_tool_call(preview, vkey_hash=self.vkey_hash,
                                         proof_mode=self.proof_mode,
                                         chain=[*self.gateway.receipts, preview])

    def judge_result(self, name: str, result: Any) -> Optional[Dict[str, Any]]:
        """判定工具返回文本（仅在配置了 result_monitor 时）。"""
        if self.result_monitor is None:
            return None
        text = extract_result_text(result)
        env = self.result_monitor.on_generate(
            text, vkey_hash=self.vkey_hash, proof_mode=self.proof_mode,
            receipts=self.gateway.receipts, seal=self.gateway.seal(),
            extra={"tool": {"name": name, "phase": "result"}})
        self.result_certificates.append(env)
        if self.on_result_cert is not None:
            self.on_result_cert(env)
        return env

    @staticmethod
    def _violations(env: Dict[str, Any]) -> List[Dict[str, Any]]:
        """从证书信封里取出违规列表。"""
        from .cert import envelope_payload

        return envelope_payload(env)["outcome"]["violations"]

    async def call_tool(self, session: Any, name: str,
                        arguments: Optional[Dict[str, Any]] = None) -> Tuple[Any, Dict[str, Any]]:
        """签参数证书 → 真正调用工具 → 签结果证书。

        返回 ``(result, args_cert)``；结果证书（若有）在
        ``self.result_certificates`` 里。
        """
        args = arguments or {}
        # 0) 飞行前：这个工具服务器到底有没有？（问过才查；见 discover_tools）
        #    顺序在策略筛查**之前**：一个不存在的工具，判它参数合不合规没有意义。
        if self.tool_names is not None and name not in self.tool_names:
            raise MCPUnknownTool(name, self.tool_names)
        # 1) 飞行前：违规就地拦住 —— 此时**回执还没签发、工具还没执行**，
        #    所以网关的链里不会留下一次「被拒绝的调用」（链只记录真的发生过的事）。
        #    但尝试本身要留痕：把这张筛查证书存进 certificates 再抛，
        #    否则被拦下的调用会连「曾经试图调用」都查不到。
        env = self._screen(name, args)
        if self.block_on_violation:
            violations = self._violations(env)
            if violations:
                self.certificates.append(env)
                if self.on_cert is not None:
                    self.on_cert(env)
                raise MCPBlocked(name, violations, phase="args")
        # 2) 执行
        result = await session.call_tool(name, args)
        # 3) 执行后：网关签发真回执（含结果摘要）并接链
        receipt = self.gateway.issue(name, args,
                                     result=extract_result_text(result))
        # 4) 用真回执出证 —— 这张（而不是上面那张预览）才是随证明走的那一张。
        #    判全链：既有结构校验，也让 trace_root 落在真实链尾上。
        env = self.monitor.on_tool_call(receipt, vkey_hash=self.vkey_hash,
                                        proof_mode=self.proof_mode,
                                        chain=self.gateway.receipts,
                                        seal=self.gateway.seal())
        self.certificates.append(env)
        if self.on_cert is not None:
            self.on_cert(env)
        renv = self.judge_result(name, result)
        if renv is not None and self.block_on_result_violation:
            violations = self._violations(renv)
            if violations:
                raise MCPBlocked(name, violations, phase="result")
        return result, env

    def call_tool_sync(self, session: Any, name: str,
                       arguments: Optional[Dict[str, Any]] = None) -> Tuple[Any, Dict[str, Any]]:
        """同步便捷封装（无需运行中的事件循环）。"""
        return asyncio.run(self.call_tool(session, name, arguments))
