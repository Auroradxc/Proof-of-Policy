"""Proof-of-Policy 的「框架无关」agent 插桩钩子。

``AgentMonitor`` 包装一个策略，并为以下两处签发合规证书：
  - **生成路径**（``on_generate``）：响应由电路内规则类型（keyword/length/pattern）
    判定，并构建一张证书；
  - **工具调用路径**（``on_tool_call``）：工具调用由 Python 参考层判定
    （tool_arg_guard / budget_bound）。这些**规则**已全部入电路，故结果标记
    ``zk: True``；「这张证书是否附了真实证明」是另一件事，由
    ``binding.vkey_hash``（``"unproven"`` 表示未附）单独体现。

**P1-5 轨迹绑定**：工具调用的凭证不再是 agent 自报的 ``{name, args}``，而是
:class:`policydsl.trace.ToolGateway` 签发的 :class:`~policydsl.trace.ToolReceipt`。
``on_tool_call`` 因此改成收一条**已签名的回执**（由网关在调用执行后签发）；
生成路径则把整条回执链（``receipts``）一并交给判定，使
``tool_arg_guard``/``budget_bound`` 判的是回执、且链尾摘要进证书
（``outcome.trace_root``）。

签名（P0-3）：``AgentMonitor`` 持有一个 :class:`cert.Signer`，默认是**进程内
临时 Ed25519 密钥**（不落盘）。要跨进程/跨方验证，请显式传入由
``policydsl.keys.load_or_create()`` 得到的签名器，并把公钥交给验证方；
否则请把 ``monitor.signer.public_hex`` 随证书一起交出去。

真实框架（LangGraph / MCP）接入这两个钩子；见
``policydsl.langgraph_adapter``。``mock_agent()`` 产出确定性的会话，
供 demo/测试使用，无需任何 LLM 依赖。
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import cert, commit, keys, trace
from .compile import compile_policy
from .evaluate import check
from .model import Policy, PolicyError, Transcript


class AgentMonitor:
    """策略监控器：把「判定 → 证书」的流程封装成两个钩子。"""

    def __init__(self, policy: Policy, mode: str = "public",
                 signer: Optional["cert.Signer"] = None,
                 key: Optional[bytes] = None, keyid: Optional[str] = None):
        """``signer`` 优先；只给 ``key`` 时按**测试用** HMAC 签名器处理
        （keyid 前缀 ``test-hmac-sha256``，仅测试）；都不给则用进程内临时
        Ed25519 密钥。**旧式 ``DEMO_KEY`` 路径已移除** —— 它不提供不可否认性。
        """
        if mode not in ("public", "private"):
            raise ValueError("mode must be 'public' or 'private'")
        if signer is None:
            signer = (cert.HmacSigner(key, keyid) if key is not None
                      else keys.ephemeral_signer())
        self.policy = policy
        self.mode = mode
        self.signer = signer
        self.spec = compile_policy(policy)  # 编译一次，供后续所有判定复用

    # -- 生成路径（电路内规则类型） --
    def generate_outcome(self, response: str, mask: Optional[List[int]] = None,
                         redacted: Optional[str] = None,
                         spans: Optional[List[Tuple[int, int]]] = None,
                         receipts: Optional[List[Any]] = None,
                         nonce: bytes = b"") -> Dict[str, Any]:
        """计算「承诺的判定结果」（镜像 SP1 的公开值）。

        公开模式暴露明文证据；私有模式只暴露证据承诺 + 脱敏信息。
        ``receipts`` 是本次会话的工具回执链（P1-5）：工具类规则判它，其链尾
        摘要进 ``trace_root``。``nonce`` 是挑战值（P0-2），两者都参与承诺。

        **这里没有 seal**：本方法返回的是**证明公开值的镜像**，电路里产不出
        P1-5b 的会话末端承诺。seal 由 :meth:`on_generate` / :meth:`on_tool_call`
        从调用方传进 ``build_payload``，落在证书载荷的**顶层**
        （``payload["trace_seal"]``），与 ``challenge`` 块同级。见
        ``policydsl/trace.py`` 的「截尾与 ToolSeal」一节。
        """
        rs = [commit.as_receipt(r) for r in (receipts or [])]
        if self.mode == "public":
            vs = commit.canonical_violations(self.spec, response, rs)
            return {"trace_root": trace.trace_root(rs),
                    "passed": len(vs) == 0,
                    "violations": [{"rule": v["rule"], "kind": v["kind"],
                                    "evidence": v["evidence"]} for v in vs]}
        return commit.private_output(self.spec, response, mask, redacted, spans,
                                     receipts=rs, nonce=nonce)

    def on_generate(self, response: str, ts: Optional[str] = None,
                    vkey_hash: str = "unproven", proof_sha256: Optional[str] = None,
                    mask: Optional[List[int]] = None, redacted: Optional[str] = None,
                    spans: Optional[List[Tuple[int, int]]] = None,
                    extra: Optional[Dict[str, Any]] = None,
                    proof_mode: Optional[str] = None,
                    receipts: Optional[List[Any]] = None,
                    nonce: bytes = b"",
                    seal: "Optional[trace.ToolSeal]" = None) -> Dict[str, Any]:
        """生成路径钩子：判定响应并签发证书。

        vkey_hash 默认 "unproven" 表示「未附加真实证明」；附加了 SP1 证明时会
        传入真实 vkey 哈希、证明哈希与 ``proof_mode``（诚实标注隐藏程度）。

        ``receipts``/``nonce``（P1-5/P0-2）：本会话的工具回执链与挑战值，
        一并进 outcome（``trace_root`` / ``response_binding``）。
        ``seal``（P1-5b）：网关的会话末端承诺（``gateway.seal()``），落在载荷
        **顶层** ``trace_seal``。**不传它的证书会在 ``verify_cert.py`` 的
        ``trace_seal`` 卡上被判 FAIL**（验证方给了网关公钥时）——没有它就无法
        排除「链尾那条违规回执被整条删掉」，所以这里不给缺省值兜底。
        """
        outcome = self.generate_outcome(response, mask, redacted, spans,
                                        receipts=receipts, nonce=nonce)
        payload = cert.build_payload(self.policy.id, self.policy.version, self.spec,
                                     self.mode, outcome, vkey_hash, proof_sha256, ts,
                                     extra=extra, proof_mode=proof_mode,
                                     trace_seal=trace.seal_to_json(seal))
        return cert.sign_payload(payload, self.signer)

    # -- 工具调用路径（Python 参考层规则类型） --
    def tool_call_outcome(self, receipt: "trace.ToolReceipt",
                          response: Optional[str] = None,
                          chain: Optional[List[Any]] = None) -> Dict[str, Any]:
        """判定一次工具调用（P1-5：判的是**网关签发的回执**，不是自报的调用）。

        ``tool_arg_guard``/``budget_bound`` 现为电路内规则类型，故结果标记
        ``zk: True``；是否真的附加了 *证明* 由证书的 ``binding.vkey_hash``
        单独体现（未生成证明时为 ``unproven``）。

        ``chain`` 是这条回执所属的**完整链**（含它自己），缺省为 ``[receipt]``。
        必须传全链的理由有二：① 链结构校验要求从 ``seq=0`` 起逐条相连，只拿链
        中间的一条会（正确地）判 ``trace_unbound``；② 证书里的 ``trace_root``
        要等于**真实链尾**，否则验证方拿网关侧回执重算会对不上。

        **判定范围是整条链**（而不是只看这一条），即这张证书的 ``passed`` 含义是
        「会话进行到这次调用为止一直合规」：链上任何一条回执留下违规，后续每次
        工具调用证书都会继续判失败。这是刻意的保守取侧 —— 一张写 ``passed=True``
        的证书绝不该出现在一条脏轨迹上。因此「本次调用的参数是否干净」不能由
        这张证书单独回答；要问这个，请对这条回执单独建链（新网关）判一次。

        **seal 不在这里**（P1-5b）：本方法返回证明公开值的镜像，而 seal 是链下
        网关签的旁证 —— 它由 :meth:`on_tool_call` 放进载荷顶层 ``trace_seal``。
        要紧的是：**判的是整条链，所以承诺的也必须是整条链** —— 少了它，删掉
        链尾那条违规回执就无从发现。
        """
        ch = list(chain) if chain is not None else [receipt]
        tx = Transcript(response=response, receipts=ch)
        try:
            res = check(self.policy, tx)
        except PolicyError as exc:
            raise PolicyError(f"tool-call check needs a response for content rules: {exc}") from exc
        return {"passed": res.passed, "zk": True,
                "trace_root": trace.trace_root(ch),
                "violations": [{"rule": v.rule.name, "kind": v.rule.kind,
                                "evidence_kind": v.evidence_kind, "evidence": v.evidence}
                               for v in res.violations]}

    def on_tool_call(self, receipt: "trace.ToolReceipt", ts: Optional[str] = None,
                     response: Optional[str] = None, vkey_hash: str = "unproven",
                     proof_mode: Optional[str] = None,
                     chain: Optional[List[Any]] = None,
                     seal: "Optional[trace.ToolSeal]" = None) -> Dict[str, Any]:
        """工具调用路径钩子：判定并签发工具调用证书（mode 固定 "tool-call"）。

        ``receipt`` 由 :class:`policydsl.trace.ToolGateway` 在**本次调用执行后**
        签发。签名本层不再校验（它是网关的职责，验证方会独立验一遍）：这里
        重算的 ``trace_root`` 会写进证书，供验证方与网关侧回执比对。
        ``chain`` 见 :meth:`tool_call_outcome`（适配器应传 ``gateway.receipts``），
        ``seal``（P1-5b）是网关的会话末端承诺，落在载荷顶层 ``trace_seal``。
        """
        outcome = self.tool_call_outcome(receipt, response, chain=chain)
        payload = cert.build_payload(self.policy.id, self.policy.version, self.spec,
                                     "tool-call", outcome, vkey_hash, None, ts,
                                     proof_mode=proof_mode,
                                     trace_seal=trace.seal_to_json(seal))
        return cert.sign_payload(payload, self.signer)


def mock_agent() -> Iterator[Tuple[str, Any]]:
    """一个确定性的、免 LLM 的「agent 会话」：先一次工具调用，再一次生成。

    用于 demo/测试，保证结果可复现（无随机性）。
    """
    yield ("tool_call", ("search_kb", {"query": "refund policy", "token": "sk-abcdefghijklmnopqrstuvwxyz"}))
    yield ("generate", "Here is the refund policy summary. Contact support for details.")
