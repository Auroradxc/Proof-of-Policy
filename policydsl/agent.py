"""Proof-of-Policy 的「框架无关」agent 插桩钩子。

``AgentMonitor`` 包装一个策略，并为以下两处签发合规证书：
  - **生成路径**（``on_generate``）：响应由电路内规则类型（keyword/length/pattern）
    判定，并构建一张证书；
  - **工具调用路径**（``on_tool_call``）：工具调用由 Python 参考层判定
    （tool_arg_guard / budget_bound）—— 尚未能在电路内证明，故这些证书标记
    ``zk: false``。

真实框架（LangGraph / MCP）接入这两个钩子；见
``policydsl.langgraph_adapter``。``mock_agent()`` 产出确定性的会话，
供 demo/测试使用，无需任何 LLM 依赖。
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import cert, commit
from .compile import compile_policy
from .evaluate import check
from .model import Policy, PolicyError, ToolCall, Transcript

DEFAULT_KEY = cert.DEMO_KEY


class AgentMonitor:
    """策略监控器：把「判定 → 证书」的流程封装成两个钩子。"""

    def __init__(self, policy: Policy, mode: str = "public", key: bytes = DEFAULT_KEY,
                 keyid: str = cert.DEFAULT_KEYID):
        if mode not in ("public", "private"):
            raise ValueError("mode must be 'public' or 'private'")
        self.policy = policy
        self.mode = mode
        self.key = key
        self.keyid = keyid
        self.spec = compile_policy(policy)  # 编译一次，供后续所有判定复用

    # -- 生成路径（电路内规则类型） --
    def generate_outcome(self, response: str, mask: Optional[List[int]] = None,
                         redacted: Optional[str] = None,
                         spans: Optional[List[Tuple[int, int]]] = None) -> Dict[str, Any]:
        """计算「承诺的判定结果」（镜像 SP1 的公开值）。

        公开模式暴露明文证据；私有模式只暴露证据承诺 + 脱敏信息。
        """
        if self.mode == "public":
            vs = commit.canonical_violations(self.spec, response)
            return {"passed": len(vs) == 0,
                    "violations": [{"rule": v["rule"], "kind": v["kind"],
                                    "evidence": v["evidence"]} for v in vs]}
        return commit.private_output(self.spec, response, mask, redacted, spans)

    def on_generate(self, response: str, ts: Optional[str] = None,
                    vkey_hash: str = "unproven", proof_sha256: Optional[str] = None,
                    mask: Optional[List[int]] = None, redacted: Optional[str] = None,
                    spans: Optional[List[Tuple[int, int]]] = None,
                    extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """生成路径钩子：判定响应并签发证书。

        vkey_hash 默认 "unproven" 表示「未附加真实证明」；附加了 SP1 证明时会
        传入真实 vkey 哈希与证明哈希。
        """
        outcome = self.generate_outcome(response, mask, redacted, spans)
        payload = cert.build_payload(self.policy.id, self.policy.version, self.spec,
                                     self.mode, outcome, vkey_hash, proof_sha256, ts,
                                     extra=extra)
        return cert.sign_payload(payload, self.key, self.keyid)

    # -- 工具调用路径（Python 参考层规则类型） --
    def tool_call_outcome(self, name: str, args: Dict[str, Any],
                          response: Optional[str] = None) -> Dict[str, Any]:
        """判定一次工具调用。``tool_arg_guard``/``budget_bound`` 现为电路内
        规则类型，故结果标记 ``zk: True``；是否真的附加了 *证明* 由证书的
        ``binding.vkey_hash`` 单独体现（未生成证明时为 ``unproven``）。"""
        tx = Transcript(response=response, tool_calls=[ToolCall(name, args)])
        try:
            res = check(self.policy, tx)
        except PolicyError as exc:
            raise PolicyError(f"tool-call check needs a response for content rules: {exc}") from exc
        return {"passed": res.passed, "zk": True,
                "violations": [{"rule": v.rule.name, "kind": v.rule.kind,
                                "evidence_kind": v.evidence_kind, "evidence": v.evidence}
                               for v in res.violations]}

    def on_tool_call(self, name: str, args: Dict[str, Any], ts: Optional[str] = None,
                     response: Optional[str] = None, vkey_hash: str = "unproven") -> Dict[str, Any]:
        """工具调用路径钩子：判定并签发工具调用证书（mode 固定 "tool-call"）。"""
        outcome = self.tool_call_outcome(name, args, response)
        payload = cert.build_payload(self.policy.id, self.policy.version, self.spec,
                                     "tool-call", outcome, vkey_hash, None, ts)
        return cert.sign_payload(payload, self.key, self.keyid)


def mock_agent() -> Iterator[Tuple[str, Any]]:
    """一个确定性的、免 LLM 的「agent 会话」：先一次工具调用，再一次生成。

    用于 demo/测试，保证结果可复现（无随机性）。
    """
    yield ("tool_call", ("search_kb", {"query": "refund policy", "token": "sk-abcdefghijklmnopqrstuvwxyz"}))
    yield ("generate", "Here is the refund policy summary. Contact support for details.")
