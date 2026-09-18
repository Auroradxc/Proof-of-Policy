"""Proof-of-Policy 的「框架无关」agent 插桩钩子。

``AgentMonitor`` 包装一个策略，并为以下两处签发合规证书：
  - **生成路径**（``on_generate``）：响应由电路内规则类型（keyword/length/pattern）
    判定，并构建一张证书；
  - **工具调用路径**（``on_tool_call``）：工具调用由 Python 参考层判定
    （tool_arg_guard / budget_bound）。这些**规则**已全部入电路，故结果标记
    ``zk: True``；「这张证书是否附了真实证明」是另一件事，由
    ``binding.vkey_hash``（``"unproven"`` 表示未附）单独体现。

**P1-5 轨迹绑定**：工具调用的凭证不再是 agent 自报的 ``{name, args}``，而是
:class:`policydsl.evidence.ToolGateway` 签发的 :class:`~policydsl.evidence.ToolReceipt`。
``on_tool_call`` 因此改成收一条**已签名的回执**（由网关在调用执行后签发）；
生成路径则把整条回执链（``receipts``）一并交给判定，使
``tool_arg_guard``/``budget_bound`` 判的是回执、且链尾摘要进证书
（``outcome.trace_root``）。

签名（P0-3）：``AgentMonitor`` 持有一个 :class:`cert.Signer`，默认是**进程内
临时 Ed25519 密钥**（不落盘）。要跨进程/跨方验证，请显式传入由
``policydsl.evidence.load_or_create()`` 得到的签名器，并把公钥交给验证方；
否则请把 ``monitor.signer.public_hex`` 随证书一起交出去。

真实框架（LangGraph / MCP）接入这两个钩子；见
``policydsl.adapters.langgraph_adapter``。``mock_agent()`` 产出确定性的会话，
供 demo/测试使用，无需任何 LLM 依赖。
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterator, List, Optional, Tuple

from policydsl.evidence import cert, keys, trace
from policydsl.privacy import commit
from policydsl.core.compile import compile_policy
from policydsl.core.evaluate import check
from policydsl.core.model import Policy, PolicyError, Transcript


def failure_fingerprint(error: BaseException) -> Dict[str, Any]:
    """失败的**可公开指纹**：异常类型名 + 消息的 SHA-256。

    异常消息里常有 prompt 片段、URL、偶尔还有密钥（HTTP 客户端的报错尤其容易
    带上请求头），所以这里**只放指纹、不放原文** —— 与证书其余部分「只放承诺、
    不放明文」同一口径（见 ``docs/security-model.md`` §2）。要核对具体是哪次
    失败，让持有原文的一方自己算哈希来比。

    ``error_block()``（适配器层）与 fail-closed 工具的 ``judgment`` 块共用它：
    两处脱敏口径若各写一份，日后必然各走各的。
    """
    return {
        "type": type(error).__name__,
        "message_sha256": hashlib.sha256(str(error).encode("utf-8")).hexdigest(),
    }


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
        #: 工具路径上**判定或签发失败**的异常（fail-closed 的进程内留痕）。
        #: 每次失败都**同时**出一张 fail-closed 证书（见 :meth:`unjudged_tool_cert`），
        #: 这里留的是原件 —— 证书里只有类型名与消息哈希，够核对、不够调试。
        self.judgment_failures: List[BaseException] = []

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
        ``policydsl/evidence/trace.py`` 的「截尾与 ToolSeal」一节。
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
                     seal: "Optional[trace.ToolSeal]" = None,
                     extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """工具调用路径钩子：判定并签发工具调用证书（mode 固定 "tool-call"）。

        ``receipt`` 由 :class:`policydsl.evidence.ToolGateway` 在**本次调用执行后**
        签发。签名本层不再校验（它是网关的职责，验证方会独立验一遍）：这里
        重算的 ``trace_root`` 会写进证书，供验证方与网关侧回执比对。
        ``chain`` 见 :meth:`tool_call_outcome`（适配器应传 ``gateway.receipts``），
        ``seal``（P1-5b）是网关的会话末端承诺，落在载荷顶层 ``trace_seal``。
        ``extra`` 是载荷**顶层**的旁证（与 :meth:`on_generate` 同款），目前用于
        工具失败时的 ``error`` 块 —— 与 ``seal``/``challenge`` 一样，它**不进**
        ``outcome``，因为 ``outcome`` 是证明公开值的镜像，而电路里没有这些字段。

        **fail-closed（判定做不了 ⇒ 出证，且判为不通过）**：判定、构造、签名
        任一环抛异常时，为**同一条回执**出一张 fail-closed 证书（见
        :meth:`unjudged_tool_cert`），而不是把异常抛给调用方。理由有两条：

        ① **回执必须有人认领**。回执由网关在调用**执行后**签发，它记的是
           「agent 干了什么」；判定失败时若直接抛出去，回执就留在链上没有证书
           —— 产物上「这次调用没判定」与「这次调用是干净的」同形，正是 P0-4
           要消灭的那类歧义；
        ② **重抛把正确性交给了调用方**。全仓有六个 ``issue() → on_tool_call()``
           的调用点（四个适配器），重抛要求每一处都记得 ``_emit(exc.certificate)``
           才不会把证书丢掉，漏一个就退回孤儿回执。失败不再需要靠异常来「不被
           吞」：它已经是产物上一条签过名、第三方可核验的事实。

        留痕有三处，各有各的用处：证书里是 ``judgment`` 块（类型名 + 消息哈希）、
        :attr:`judgment_failures` 里是异常原件（进程内调试）、调用方的
        ``errors`` 由适配器负责（框架侧可见）。
        """
        try:
            return self._judged_tool_cert(receipt, ts, response, vkey_hash,
                                          proof_mode, chain, seal, extra)
        except Exception as exc:  # noqa: BLE001 —— 判定/构造/签名，任一环
            self.judgment_failures.append(exc)
            try:
                return self.unjudged_tool_cert(receipt, exc, ts=ts,
                                               vkey_hash=vkey_hash,
                                               proof_mode=proof_mode,
                                               chain=chain, seal=seal,
                                               extra=extra)
            except Exception as exc2:  # noqa: BLE001
                # 连兜底那张也签不出来。已知的唯一成因是**签名器本身坏了** ——
                # 没有签名器就没有证书，无解。既然给不出证据，就**不能**假装
                # 无事发生：留痕后继续抛，让调用方（适配器）把它记进 errors。
                self.judgment_failures.append(exc2)
                raise

    def _judged_tool_cert(self, receipt: "trace.ToolReceipt",
                          ts: Optional[str], response: Optional[str],
                          vkey_hash: str, proof_mode: Optional[str],
                          chain: Optional[List[Any]],
                          seal: "Optional[trace.ToolSeal]",
                          extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """正常路径：判定 + 构造 + 签名（:meth:`on_tool_call` 的失败保护在它外面）。"""
        outcome = self.tool_call_outcome(receipt, response, chain=chain)
        payload = cert.build_payload(self.policy.id, self.policy.version, self.spec,
                                     "tool-call", outcome, vkey_hash, None, ts,
                                     proof_mode=proof_mode, extra=extra,
                                     trace_seal=trace.seal_to_json(seal))
        return cert.sign_payload(payload, self.signer)

    def unjudged_tool_cert(self, receipt: "trace.ToolReceipt",
                           error: BaseException, ts: Optional[str] = None,
                           vkey_hash: str = "unproven",
                           proof_mode: Optional[str] = None,
                           chain: Optional[List[Any]] = None,
                           seal: "Optional[trace.ToolSeal]" = None,
                           extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """**判定做不了**时为这条回执出的 fail-closed 证书。

        它回答的是「这条回执怎么样了」，**不是**「它合规」：

        - ``outcome.passed = False`` —— 判不了就不该出现 ``passed=True``。这是
          :meth:`tool_call_outcome` 自己钉的口径（「一张写 ``passed=True`` 的证书
          绝不该出现在一条脏轨迹上」），判不了只会更该如此；
        - ``outcome.violations = []`` —— **如实**：没有判定出任何违规，而不是
          「没有违规」。这两件事靠顶层 ``judgment`` 块分开：
          ``{"performed": false, "type": …, "message_sha256": …}``。它是旁证，
          与 ``error`` / ``trace_seal`` 同款地放在**顶层**（``outcome`` 是证明
          公开值的镜像，电路里没有这个字段）；调用方原本的 ``extra``（例如工具
          自身失败时的 ``error`` 块）**原样保留**，不覆盖 —— 那是另一件事，
          丢掉它等于把工具故障从产物上抹掉；
        - ``mode`` 仍是 ``"tool-call"``：这确实是工具路径上出的证书。

        **为什么不把回执从链上撤掉**（最容易被想到的那个「修法」）：工具**已经
        执行了** —— ``on_tool_end`` 时副作用已经发生。抹掉回执等于**伪造轨迹**，
        而且方向反了：谁能制造一次判定失败，谁就能让自己的工具调用从证据链上
        消失而副作用照留，比孤儿回执更严重。回执链记的是「agent 干了什么」，
        不是「什么被判过」。
        """
        ch = list(chain) if chain is not None else [receipt]
        fp = failure_fingerprint(error)
        note = dict(extra or {})
        note["judgment"] = {"performed": False, "type": fp["type"],
                            "message_sha256": fp["message_sha256"]}
        outcome = {"passed": False, "trace_root": trace.trace_root(ch),
                   "violations": []}
        payload = cert.build_payload(self.policy.id, self.policy.version, self.spec,
                                     "tool-call", outcome, vkey_hash, None, ts,
                                     proof_mode=proof_mode, extra=note,
                                     trace_seal=trace.seal_to_json(seal))
        return cert.sign_payload(payload, self.signer)


def mock_agent() -> Iterator[Tuple[str, Any]]:
    """一个确定性的、免 LLM 的「agent 会话」：先一次工具调用，再一次生成。

    用于 demo/测试，保证结果可复现（无随机性）。
    """
    yield ("tool_call", ("search_kb", {"query": "refund policy", "token": "sk-abcdefghijklmnopqrstuvwxyz"}))
    yield ("generate", "Here is the refund policy summary. Contact support for details.")
