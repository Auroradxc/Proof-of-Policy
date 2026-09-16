"""Proof-of-Policy 的**框架无关**参考适配器（:class:`GenericGuard`）。

## 一个适配器其实由两半组成

三个框架适配器（``langchain_adapter`` / ``langgraph_adapter`` / ``mcp_adapter``）
看上去是三份代码，实际做的都是同一件事的两半：

===========  ==========================================================  ================
            做什么                                                       属于
===========  ==========================================================  ================
**① 提取**   「本框架的事件」→（宽松解析）→ 文本 / (工具名, 参数, 结果)   **框架特定**
**② 出证**   那些东西 →（两个钩子 + 一把网关）→ 证书                     **契约，框架无关**
===========  ==========================================================  ================

本模块把 **②** 单独写出来，且**不含任何框架依赖**（只用到标准库与本仓库模块）
—— 于是它同时是三样东西：

- **一份可运行的契约说明**：「一个适配器最少必须做对哪几件事」在这里是代码，
  不是 `docs/modules/06-frameworks.md` §8 那种三条建议；
- **接新框架时的可复制骨架**：你要写的是 **①**，**②** 照抄本模块；
- **一条不必装任何框架就能跑的路径**：因此可以离线单测、可以在 CI 里跑。

## 接一个新框架，照这个时序做

::

    guard = GenericGuard(policy, policy_pack)     # 一个会话一把 guard

    # 每次「模型完成」                            ← 接你框架的 llm/生成事件
    guard.generate(text)

    # 每次「工具调用**结束**」                     ← 接你框架的工具事件
    guard.tool_call("search_kb", {"query": "x"}, result="...")

    # 会话结束（最后一次工具调用**之后**）
    write_session(guard, out_dir)                 # → session.json + ledger.jsonl

之后第三方可以只凭 ``out_dir`` 里的公开产物独立验：

::

    python3 scripts/verify_session.py <out_dir>/session.json
    python3 scripts/verify_cert.py <out_dir>/cert.json --gateway-key <out_dir>/gateway.pub.hex

## 三件必须做对的事（做错的后果各不相同）

这三条被放在 **② 里**，所以接新框架时**不用重做** —— 但也意味着**别在 ① 里
自作主张绕过它们**：

1. **一个会话只用一把网关。** 两条链各指一条 ``trace_root``，会话就被劈成两条，
   ``session`` 的三条义务当场不成立。``demo_e2e.py`` 早期正是「两处各自
   ``ToolGateway()``」，见 ``docs/modules/06-frameworks.md`` §4 的同一处血账。
2. **``seal`` 取「现在」那一刻的，不要缓存。** seal 说的是「到此为止」；会话
   中途再 ``issue`` 会让先前那条 seal 的 ``count`` 对不上 —— 这正是它要拦的东西，
   所以缓存的 seal 会**把截尾检测悄悄关掉**。本模块在每个签名点现取。
3. **网关的钥与出证方的钥是两把。** 网关是「工具轨迹的见证人」，出证方是
   「这张证书的签发人」；合成一把，P1-5「轨迹不再是 agent 自报」就没了 ——
   那正是这条设计存在的全部理由。两把公钥都进 ``session["signers"]``，
   验证方照样只凭公开产物独立验。

## 它**不是**第四个框架适配器

也不是框架适配器的基类。三个适配器 = **①** + 本模块的 **②**，它们各自持有
``AgentMonitor`` 与 ``ToolGateway`` 的历史早于本模块；本模块是把那份公共时序
**取出来写在明面上**。因此这里**不该**长出任何 ``import langchain`` /
``import mcp`` —— 一有框架依赖，上面「可离线跑」这条就作废了。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import anchor as _anchor
from . import cert as _cert
from . import keys as _keys
from . import trace as _trace
from .agent import AgentMonitor
from .model import Policy

__all__ = ["GenericGuard", "write_session"]

# 会话条目里 kind 的取值：与 ``demo_e2e.py`` / ``verify_session.py`` 同一套口径
KIND_GENERATE = "llm"
KIND_TOOL = "tool"


class GenericGuard:
    """把「两个钩子 + 一把网关」的时序写死的框架无关适配器。

    ``policy`` 与 ``policy_pack``（策略包**路径**）都要给：前者用来判定，
    后者写进 ``session.json`` 的每一条目（``verify_session.py`` 靠它找策略包
    复算 ``policy_hash``）。``Policy`` 对象本身不带路径，所以这一项没法自动推。

    ``signer`` 是**出证方**的签名器（缺省进程内临时 Ed25519）；
    ``gateway`` 是**网关**（缺省新开一把、并自带独立密钥）。给 ``gateway``
    是为了**跨 guard 共享同一把网关** —— 一个 agent 会话里若有多个策略包
    （例如 MCP 工具策略 + 内容策略各一个 monitor），它们必须共用一条回执链。
    """

    def __init__(self, policy: Policy, policy_pack: str, mode: str = "public",
                 signer: Optional["_cert.Signer"] = None,
                 gateway: Optional[_trace.ToolGateway] = None,
                 vkey_hash: str = _cert.VKEY_HASH_UNPROVEN,
                 proof_mode: Optional[str] = None):
        if mode not in ("public", "private"):
            raise ValueError("mode must be 'public' or 'private'")
        self.monitor = AgentMonitor(policy, mode, signer=signer)
        # 网关**默认独立密钥**（第 3 条）：不能顺手用它俩同一个 signer
        self.gateway = (gateway if gateway is not None
                        else _trace.ToolGateway(signer=_keys.ephemeral_signer()))
        self.policy_pack = policy_pack
        self.vkey_hash = vkey_hash
        self.proof_mode = proof_mode
        # 与 ``kinds`` 按下标对齐；拆成两个 list 而不是 list[tuple]，
        # 是因为 ``certificates`` 要能直接序列化进 session.json
        self.certificates: List[Dict[str, Any]] = []
        self.kinds: List[str] = []

    # ---- 生成路径 ----------------------------------------------------

    def generate(self, text: str, ts: Optional[str] = None,
                 mask: Optional[List[int]] = None,
                 redacted: Optional[str] = None,
                 spans: Optional[Sequence[Any]] = None,
                 nonce: bytes = b"",
                 extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """一次「模型完成」→ 一张生成路径证书。

        ``receipts`` 与 ``seal`` 都取**此刻**的网关状态（第 1、2 条）：
        这样证书承诺的是「进行到这次生成为止的整条工具轨迹」，
        而不是某个被缓存下来的旧链尾。

        ``mask``/``redacted``/``spans``/``nonce`` 只有在 ``mode="private"``
        下才有意义，直接透传给 :meth:`AgentMonitor.on_generate`。
        """
        env = self.monitor.on_generate(
            text, ts=ts, vkey_hash=self.vkey_hash, proof_mode=self.proof_mode,
            mask=mask, redacted=redacted, spans=list(spans) if spans else None,
            nonce=nonce, receipts=self.gateway.receipts,
            seal=self.gateway.seal(), extra=extra)
        return self._emit(KIND_GENERATE, env)

    # ---- 工具路径 ----------------------------------------------------

    def tool_call(self, name: str, args: Optional[Dict[str, Any]] = None,
                  result: Optional[str] = None, ts: Optional[str] = None,
                  response: Optional[str] = None,
                  extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """一次「工具调用结束」→ 一条回执 + 一张工具路径证书。

        **必须在调用执行后调**：回执的 ``result_digest`` 是执行结果的摘要，
        调用前根本没有结果可签（那条路是 :meth:`ToolGateway.preview`，
        它造的是**不进链**的预览回执，供飞行前筛查用）。

        ``response`` 只有**内容类规则**（``tool_result_guard``）才需要 ——
        它要审的是结果原文。纯参数/预算类策略可以不传；但策略里有内容规则
        而不传，这里会如实抛 ``PolicyError``（而不是悄悄按「无结果」判过）。
        """
        receipt = self.gateway.issue(name, args, result=result, ts=ts)
        env = self.monitor.on_tool_call(
            receipt, ts=ts, response=response, vkey_hash=self.vkey_hash,
            proof_mode=self.proof_mode, chain=self.gateway.receipts,
            seal=self.gateway.seal(), extra=extra)
        return self._emit(KIND_TOOL, env)

    def _emit(self, kind: str, env: Dict[str, Any]) -> Dict[str, Any]:
        self.certificates.append(env)
        self.kinds.append(kind)
        return env

    # ---- 会话末端 ----------------------------------------------------

    def seal(self) -> "_trace.ToolSeal":
        """会话末端的承诺（**最后一次工具调用之后**再取）。"""
        return self.gateway.seal()

    @property
    def trace_root(self) -> str:
        return self.gateway.trace_root

    def signers(self) -> List[Dict[str, str]]:
        """本会话要交给验证方的**两把**公钥（出证方 + 网关，第 3 条）。

        写进 ``session.json`` 的 ``signers`` 后，``verify_session.py`` 只凭
        这一个字段就能构造出验签所需的全部 keyring —— 私钥全程没有离开过出证方。
        """
        out: List[Dict[str, str]] = []
        cert_pub = getattr(self.monitor.signer, "public_key", None)
        if cert_pub is not None:
            out.append(_keys.public_record(cert_pub))
        gw_pub = self.gateway.public_key
        if gw_pub is not None:
            out.append(_keys.public_record(gw_pub))
        return out

    def session(self, session_id: str = "session",
                ledger_name: str = "ledger.jsonl") -> Dict[str, Any]:
        """把本会话汇总成 ``session.json`` 的内容（**纯函数，不碰磁盘**）。

        形状与 ``demo_e2e.py`` 产出的一致，因此 ``verify_session.py`` 直接可读。
        ``proof`` 块（真证明的边车）本模块不产出 —— 那是 ``zk_path`` 那条路的
        事；这里的证书 ``binding.vkey_hash`` 如实为 ``unproven``。
        """
        entries = [{"kind": k, "policy_pack": self.policy_pack, "envelope": env}
                   for k, env in zip(self.kinds, self.certificates)]
        counts: Dict[str, int] = {}
        for k in self.kinds:
            counts[k] = counts.get(k, 0) + 1
        return {
            "session_id": session_id,
            "ledger": ledger_name,
            "packs": sorted({e["policy_pack"] for e in entries}),
            "signers": self.signers(),
            "certificates": entries,
            "summary": {"certificates": len(entries), "kinds": counts},
            # 网关侧的旁证：链尾摘要 + 会话末端承诺。**seal 在这里再取一次**
            # 是不行的（第 2 条已签进各证书），这里序列化的是**同一把** seal ——
            # 最后一次 ``issue`` 之后没再动过链，所以两者一致。
            "trace": {
                "trace_root": self.gateway.trace_root,
                "gateway_keyid": self.gateway.signer.keyid,
                "seal": self.gateway.seal().to_dict(),
            },
        }


def write_session(guard: GenericGuard, out_dir: Path,
                  session_id: Optional[str] = None,
                  ledger_name: str = "ledger.jsonl") -> Path:
    """把一次会话落盘成**第三方可独立核对**的一组公开产物：

    ============================  ==================================================
    ``session.json``              会话汇总（``verify_session.py --session`` 读它）
    ``ledger.jsonl``              每张证书的 ``cert_digest`` 锚定（哈希链）
    ``key.json``                  两把**公钥**（出证方 + 网关）
    ``gateway.pub.hex``           网关公钥（``verify_cert.py --gateway-key`` 要它）
    ``receipts.json``             网关签发的回执链（``--receipts``，第三方据此
                                  重算 ``trace_root`` —— **不给它，``trace_binding``
                                  那张卡就没法核，只能报 FAIL**）
    ``cert-<n>-<kind>.json``      逐张证书（``verify_cert.py --cert`` 要它）
    ============================  ==================================================

    写的**全是公钥与产物，没有一个私钥**。要上真链，走 ``proof_service.py`` /
    ``anchor_e2e.sh`` 那条路 —— 本函数只做文件账本，够第三方离线核对。

    核对配方（``<dir>`` 即 ``out_dir``）：:

        python3 scripts/verify_session.py --session <dir>/session.json
        python3 scripts/verify_cert.py --cert <dir>/cert-1-tool.json \\
            --pack <policy_pack> --ledger <dir>/ledger.jsonl \\
            --keyring <dir>/key.json --receipts <dir>/receipts.json \\
            --gateway-key <dir>/gateway.pub.hex
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger = out_dir / ledger_name
    backend = _anchor.backend_from_env(ledger)
    # 用 zip 而不是 ``certificates.index(env)``：index 对 dict 比的是 ``==``，
    # 两张**内容相同**的证书会双双取到第一个下标 —— 锚定记录里的 kind 就会错，
    # 而且它是 O(n²)。
    for kind, env in zip(guard.kinds, guard.certificates):
        payload = _cert.envelope_payload(env)
        backend.anchor(_cert.cert_digest(payload),
                       {"kind": kind, "policy": payload["policy"]["id"]})

    session = guard.session(session_id=session_id or out_dir.name,
                            ledger_name=ledger_name)
    ok_chain, reason = _anchor.verify_ledger(ledger)
    session["summary"]["ledger_ok"] = ok_chain
    session["summary"]["ledger_reason"] = reason

    path = out_dir / "session.json"
    path.write_text(json.dumps(session, indent=2, ensure_ascii=False),
                    encoding="utf-8")

    # 第三方核 trace_binding 要自己重算链尾 —— 回执链得给出去（**只有公钥与
    # 摘要**：回执里存的是 result_digest，结果原文不在其中）
    (out_dir / "receipts.json").write_text(
        json.dumps(_trace.receipts_to_json(guard.gateway.receipts),
                   indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "key.json").write_text(
        json.dumps(guard.signers(), indent=2, ensure_ascii=False),
        encoding="utf-8")
    for i, (kind, env) in enumerate(zip(guard.kinds, guard.certificates)):
        (out_dir / f"cert-{i}-{kind}.json").write_text(
            json.dumps(env, indent=2, ensure_ascii=False), encoding="utf-8")

    gw_pub = guard.gateway.public_key
    try:
        (out_dir / "gateway.pub.hex").write_text(
            _keys.public_hex(gw_pub) + "\n", encoding="utf-8")
    except (TypeError, AttributeError):
        # 非 Ed25519 签名器（例如测试用的 HMAC）没有可分发的公钥 ——
        # 那就**不写**这个文件，而不是写一个假的出去
        pass
    return path
