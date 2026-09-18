#!/usr/bin/env python3
"""用两个简易 LangChain agent 做一次**真实接入测试**。

跑法::

    python3 scripts/demo/langchain_agents_demo.py                 # 离线桩（默认）
    python3 scripts/demo/langchain_agents_demo.py --stub          # 本地协议桩 + 真客户端
    python3 scripts/demo/langchain_agents_demo.py --model openai:gpt-4o-mini
    python3 scripts/demo/langchain_agents_demo.py --scenario A     # 只跑合规那条

## 三个场景

============  ============================================  ==========================
场景          内容路径（生成）                               工具路径
============  ============================================  ==========================
``A`` 合规    正常短答                                         ``search_kb(query=...)``
``B`` 违规    回显一行含 ``sk-`` 的密钥                        带上 ``api_key`` 参数
``C`` 错误    模型直接抛 503                                   —
============  ============================================  ==========================

A 应当**全绿**；B 应当**被判违规**（内容 + 工具各一条）；C 应当签出**带 ``error`` 块**
的失败证书（P0-4）—— 三条都由脚本自己断言，退出码即结论。

## 接线：一个 handler，两个 monitor

``PoPCallbackHandler(monitor=…, tool_monitor=…)`` —— 生成路径与工具路径各判各的，
**共用一把网关**（契约第 3 条：不共用 ⇒ 两条链各指一条 ``trace_root``，会话被
劈成两条）。

``tool_monitor`` 这个口子是本次接入测试**撞出来之后才补进适配器的**
（dev-plan §5.1.2 第 7 条）。在此之前它只有 ``monitor`` 一个参数，而
``on_tool_end`` 硬编码拿它判工具调用 —— 把内容策略的 monitor 接上工具事件的
后果是**静默**的：

  ``AgentMonitor.on_tool_call`` 抛 ``PolicyError``（内容规则要 transcript 的
  response），而 **LangChain 缺省吞掉回调异常**，只留一条
  ``Error in PoPCallbackHandler.on_tool_end callback`` 的 warning
  ⇒ 这次工具调用**既没有证书、也没有任何调用方可见的报错**，在产物上与
  「这次调用是干净的」完全同形。

修之前本脚本用两个「按事件过滤」的子类绕过去：每个只认自己那条路径的事件。
代价是：一次工具调用被两个 ``on_tool_end`` 各签一条回执 ⇒ 链上多一条没有证书的
**孤儿回执**，回执条数与证书数对不上（第三方核验的 ``trace_binding`` 读得出这个
缺口）。现在一个 handler 就够了，孤儿回执随之消失。这段历史留在注释里，因为
「接错了不会报错，只会没有产物」是接入真实 agent 时最该记住的一条。

## 已知边界（如实记）

* ``--stub`` 起的是**本地协议桩**（``tests/openai_sse_stub.py``）+ **真的**
  ``langchain_openai`` 客户端：走真 HTTP、真 SSE 流，但**不需要网络与真 key**。
  它证的是「自备端点那种配置形状能一路走到证书」，**不证** provider 自己的语义。
  真正的 provider 只能靠 ``--model`` + 真 key。
* 真模型下**违规那条是否真违规是数据相关的**：模型照不照做由它自己决定。
  脚本因此把内容路径的断言降成「如实记录」（见 ``main()`` 里的 ``deterministic``）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _bootstrap import REPO, bootstrap  # noqa: E402

bootstrap()

from policydsl.adapters.agent import AgentMonitor  # noqa: E402
from policydsl.adapters.langchain_adapter import (  # noqa: E402
    PoPCallbackHandler, error_block)
from policydsl.evidence import anchor, cert, keys, trace  # noqa: E402
from policydsl.runtime.service import load_policy  # noqa: E402

CONTENT_PACK = "policy_packs/agent_content_v1.json"
TOOL_PACK = "policy_packs/agent_tool_v1.json"

#: 含 ``sk-`` 后接 ≥16 位字母数字 ⇒ 命中 ``agent_content_v1`` 的 ``no_secret``
LEAK_REPLY = "Sure, here it is: sk-abcdefghijklmnopqrstuvwxyz"
CLEAN_REPLY = "Returns are accepted within 30 days of delivery."


# ------------------------------------------------------------------ 模型 ---

def _fake(reply: str):
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage
    return GenericFakeChatModel(messages=iter([AIMessage(content=reply)]))


def _boom():
    """一个必然失败的模型 —— 用来走 P0-4 的错误路径。

    真的抛在 ``_generate`` 里，而不是直接调 ``on_llm_error``：只有让异常穿过
    LangChain 自己的路由，验的才是「框架会不会把错误回调送到我们手上」。
    """
    from langchain_core.language_models.chat_models import BaseChatModel

    class _Boom(BaseChatModel):
        @property
        def _llm_type(self) -> str: return "boom"

        def _generate(self, messages, stop=None, run_manager=None, **kw):
            raise RuntimeError("simulated provider outage (HTTP 503)")

    return _Boom()


#: 本地协议桩必须活到整个 run 结束（它是 HTTP 服务器，被 GC 掉端口就没了）
_STUB = None


def _start_stub(spec: str):
    """起本地 OpenAI 协议桩，并**按「自备端点」的配置方式**设好环境变量。

    这是**配置测试**：``--model openai:deepseek-chat`` 在 DeepSeek 上要配的
    就是 ``OPENAI_API_KEY`` + ``OPENAI_BASE_URL`` 这两个变量，这里把
    ``OPENAI_BASE_URL`` 指向本地桩、key 给一个占位值，于是**同一段配置代码**
    走的是真的 ``langchain_openai`` 客户端 + 真 HTTP + 真 SSE 流。
    唯一没被证到的是 provider 自己的语义 —— 那必须用真 key。

    （桩是仓库自己的协议夹具，``tests/test_real_llm.py`` 同款用法；
    ``scripts/demo/demo_e2e.py`` 也直接引用 ``tests/mcp_echo_server.py``。）
    """
    global _STUB
    sys.path.insert(0, str(REPO / "tests"))
    import openai_sse_stub as stub
    _STUB = stub.StubServer(["stub reply from the local protocol stub"])
    _STUB.start()
    os.environ["OPENAI_API_KEY"] = "stub-key-not-a-credential"
    os.environ["OPENAI_BASE_URL"] = _STUB.base_url
    from policydsl.adapters import llm as _llm
    return _llm.build_chat_model(spec), _llm.describe(spec), spec


def build_model(arg: str | None, use_stub: bool = False):
    """``--model`` 缺省即离线桩；给了就走真客户端（缺 key 会当场说清是哪个变量）。

    ``--stub`` 把真客户端指向本地协议桩 —— 不碰网络、不需要真 key。
    """
    if not arg:
        return None, "fake (offline)", ""
    if use_stub:
        return _start_stub(arg)
    from policydsl.adapters import llm as _llm
    model = _llm.build_chat_model(arg)          # 缺依赖/缺 key 在这里抛，措辞由 llm.py 给
    return model, _llm.describe(arg), arg


# ------------------------------------------------------------ 工具（真调用） ---

def make_tools():
    from langchain_core.tools import tool

    @tool
    def search_kb(query: str, api_key: str = "") -> str:
        """Search the internal knowledge base for policy documents."""
        return "refund policy: returns accepted within 30 days of delivery."

    return search_kb


# ----------------------------------------------------------------- 会话骨架 ---

class Session:
    """一个 agent 会话：**一个** handler、两个 monitor、一把网关。

    **一把网关**是刻意的（契约第 3 条）：内容证书与工具证书必须签在同一条轨迹上。
    两个 monitor 交给 ``tool_monitor=`` 分流（见模块 docstring），所以这里只需要
    一个 handler —— 修之前要挂两个按事件过滤的子类，还会在链上留下孤儿回执。
    """

    def __init__(self, model=None):
        self.signer = keys.ephemeral_signer()
        self.gateway = trace.ToolGateway()
        self.content = AgentMonitor(load_policy(REPO / CONTENT_PACK), signer=self.signer)
        self.tools = AgentMonitor(load_policy(REPO / TOOL_PACK), signer=self.signer)
        self.handler = PoPCallbackHandler(self.content, tool_monitor=self.tools,
                                          gateway=self.gateway)
        self.model = model
        self.callbacks = [self.handler]

    # -- 生成路径 ---------------------------------------------------------
    def generate(self, prompt: str, reply: str) -> str:
        model = self.model if self.model is not None else _fake(reply)
        chunks = []
        try:
            for c in model.stream(prompt, config={"callbacks": self.callbacks}):
                chunks.append(c.content or "")
        except Exception as exc:                  # 场景 C：模型失败
            return f"<error: {type(exc).__name__}>"
        return "".join(chunks)

    # -- 工具路径 ---------------------------------------------------------
    def call_tool(self, tool, args: dict) -> str:
        try:
            return str(tool.invoke(args, config={"callbacks": self.callbacks}))
        except Exception as exc:
            return f"<error: {type(exc).__name__}>"

    # -- 汇总 -------------------------------------------------------------
    @property
    def certificates(self):
        """全部证书，按签发顺序（生成在前、工具在后，与 agent 的真实时序一致）。"""
        return list(self.handler.certificates)

    def split(self):
        """按证书自称的 ``mode`` 分成（生成, 工具）两组。

        按 ``mode`` 分而不是按签发次序切：次序是**约定**，``mode`` 是证书自己
        写下的字段 —— 拿约定去切，改动一旦让次序变了，产物会静默错位。
        """
        gen, tool = [], []
        for env in self.certificates:
            payload = cert.envelope_payload(env)
            (tool if payload.get("mode") == "tool-call" else gen).append(env)
        return gen, tool

    def verdicts(self):
        out = []
        for env in self.certificates:
            p = cert.envelope_payload(env)
            out.append({
                "mode": p.get("mode"),
                "policy": (p.get("policy") or {}).get("id"),
                "passed": (p.get("outcome") or {}).get("passed"),
                "violations": [v.get("rule") for v in
                               ((p.get("outcome") or {}).get("violations") or [])],
                "error": bool(p.get("error")),
                "error_phase": ((p.get("error") or {}).get("phase")),
                "seal_count": ((p.get("trace_seal") or {}).get("count")),
            })
        return out


def write_bundle(s: Session, out_dir: Path, name: str) -> Path:
    """落盘成**第三方可独立核对**的一组公开产物（仅公钥与产物，无任何私钥）。

    形状与 ``generic_adapter.write_session`` 一致，两个现成核验脚本直接可读。
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger = out_dir / "ledger.jsonl"
    backend = anchor.backend_from_env(ledger)
    for env in s.certificates:
        p = cert.envelope_payload(env)
        backend.anchor(cert.cert_digest(p),
                       {"kind": p.get("mode"), "policy": (p.get("policy") or {}).get("id")})

    signers = []
    for pub in (getattr(s.signer, "public_key", None), s.gateway.public_key):
        if pub is not None:
            signers.append(keys.public_record(pub))

    gen, tool = s.split()
    ok_chain, reason = anchor.verify_ledger(ledger)
    entries = []
    for env in s.certificates:
        is_tool = cert.envelope_payload(env).get("mode") == "tool-call"
        entries.append({"kind": "tool" if is_tool else "llm",
                        "policy_pack": TOOL_PACK if is_tool else CONTENT_PACK,
                        "envelope": env})
    session = {
        "session_id": name,
        "ledger": ledger.name,
        "packs": sorted({CONTENT_PACK, TOOL_PACK}),
        "signers": signers,
        "certificates": entries,
        "summary": {"certificates": len(s.certificates),
                    "kinds": {"llm": len(gen), "tool": len(tool)},
                    "ledger_ok": ok_chain, "ledger_reason": reason},
        "trace": {"trace_root": s.gateway.trace_root,
                  "gateway_keyid": s.gateway.signer.keyid,
                  "seal": s.gateway.seal().to_dict()},
    }
    (out_dir / "session.json").write_text(
        json.dumps(session, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "receipts.json").write_text(
        json.dumps(trace.receipts_to_json(s.gateway.receipts), indent=2,
                   ensure_ascii=False), encoding="utf-8")
    (out_dir / "key.json").write_text(
        json.dumps(signers, indent=2, ensure_ascii=False), encoding="utf-8")
    for i, env in enumerate(s.certificates):
        (out_dir / f"cert-{i}.json").write_text(
            json.dumps(env, indent=2, ensure_ascii=False), encoding="utf-8")
    if s.gateway.public_key is not None:
        (out_dir / "gateway.pub.hex").write_text(
            keys.public_hex(s.gateway.public_key) + "\n", encoding="utf-8")
    return out_dir / "session.json"


# ------------------------------------------------------------------- 场景 ---

def scenario_A(model, label) -> tuple[Session, list[str]]:
    """合规：干净的生成 + 干净的工具调用 ⇒ 两张证书都该 passed=True。"""
    s = Session(model)
    tool = make_tools()
    s.generate("What does our refund policy say?", CLEAN_REPLY)
    s.call_tool(tool, {"query": "refund policy"})
    return s, ["A · 合规"]


def scenario_B(model, label) -> tuple[Session, list[str]]:
    """违规：回显密钥 + 工具带 api_key ⇒ 两张证书都该 passed=False。"""
    s = Session(model)
    tool = make_tools()
    s.generate("Repeat this line verbatim: " + LEAK_REPLY, LEAK_REPLY)
    s.call_tool(tool, {"query": "refund", "api_key": "sk-live-should-not-be-here"})
    return s, ["B · 违规"]


def scenario_C(model, label) -> tuple[Session, list[str]]:
    """错误路径（P0-4）：模型抛 503 ⇒ 该签出一张带 error 块的失败证书。"""
    s = Session(model)
    s.generate("anything", "")          # model 是 _boom() 时 reply 用不上
    return s, ["C · 错误"]


SCENARIOS = {"A": scenario_A, "B": scenario_B, "C": scenario_C}


# ------------------------------------------------------------------- 主流程 ---

def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--model", default=None,
                   help="provider:model，如 openai:gpt-4o-mini；缺省离线桩")
    p.add_argument("--stub", action="store_true",
                   help="把真客户端指向本地协议桩（真 HTTP/真 SSE，但不需要网络与 key）"
                        "—— 用来复现「自备端点」那种配置形状，如 DeepSeek")
    p.add_argument("--out", default="scripts/examples/out/langchain_agents",
                   help="产物目录（相对仓库根）")
    p.add_argument("--scenario", default="all", choices=["A", "B", "C", "all"])
    return p.parse_args(argv)


def main() -> int:
    args = parse_args()
    out_root = Path(args.out)
    if not out_root.is_absolute():
        out_root = REPO / out_root

    if args.stub and not args.model:
        args.model = "openai:stub-model"     # --stub 自带一个规格，省得再写一遍
    model, label, spec = build_model(args.model, use_stub=args.stub)
    print(f"repo     : {REPO}")
    print(f"llm model: {label}" + (f"  ({spec})" if spec else ""))
    if args.stub:
        print(f"stub     : 本地协议桩 {os.environ['OPENAI_BASE_URL']}"
              f"（真客户端 + 真 HTTP，key 是占位值；证的是配置形状，不是 provider 语义）")
    print(f"content  : {CONTENT_PACK}")
    print(f"tool     : {TOOL_PACK}")
    print()

    names = ["A", "B", "C"] if args.scenario == "all" else [args.scenario]
    failures: list[str] = []
    advisories: list[str] = []
    #: 离线桩的回复是我们写死的 ⇒ 内容路径的结论确定；真模型下不确定。
    deterministic = model is None

    for name in names:
        # 场景 C 用必然失败的模型；A/B 用 --model 指定的（或各自的离线桩）
        m = _boom() if name == "C" else model
        sess, tags = SCENARIOS[name](m, label)
        out = out_root / name
        write_bundle(sess, out, name)
        v = sess.verdicts()

        print(f"=== 场景 {tags[0]} ===")
        print(f"  {label if name != 'C' else 'boom (always fails)'}")
        for i, row in enumerate(v):
            flag = "PASS" if row["passed"] else "VIOLATION"
            extra = f"  违规规则={row['violations']}" if row["violations"] else ""
            if row["error"]:
                flag, extra = "ERROR-CERT", f"  error.phase={row['error_phase']}"
            print(f"  cert-{i}  mode={row['mode']:<9} policy={row['policy']:<16} "
                  f"seal.count={row['seal_count']}  → {flag}{extra}")
        if not v:
            print("  !!! 没有任何证书 —— 这正是要抓的 fail-open")
        print(f"  产物: {out.relative_to(REPO) if out.is_relative_to(REPO) else out}"
              f"  网关回执 {len(sess.gateway.receipts)} 条 / trace_root {sess.gateway.trace_root[:16]}…")
        print()

        # ---- 断言：把「应当」写死在脚本里，退出码即结论 ----
        #
        # **真模型下，内容路径的结论是数据相关的，不能写成硬断言。** 模型照不照做
        # 由它自己决定：它可能拒绝回显密钥、也可能答非所问地吐一段正常文字。
        # 那就不是「接入失败」，而是「这一跑没走到那条规则」。`demo_e2e.py` 记过
        # 同一笔账：把「模型一定会违规」写死成断言，是在赌 provider 的服从性。
        #
        # 所以分两档：
        #   * **工具路径** —— 参数是我们自己传的，**永远确定**，任何模型下都硬断言；
        #   * **内容路径** —— 离线桩确定（回复是我们写死的），真模型下只如实报告。
        # 场景 C 与模型无关，始终硬断言。
        strict = deterministic

        if name == "A":
            if not all(r["passed"] for r in v):
                (failures if strict else advisories).append(
                    "A 的生成证书应当 pass（真模型下模型可能吐了违规内容）")
            if len(sess.gateway.receipts) != 1:
                failures.append(f"应当只有 1 条回执，实为 {len(sess.gateway.receipts)}"
                                f"（>1 说明同一条链上回执被重复签发）")
        if name == "B":
            got = {r for row in v for r in row["violations"]}
            # 工具路径：确定性，任何时候都硬断言
            if "no_secret_args" not in got:
                failures.append(f"B 的工具证书应命中 no_secret_args，实为 {got}")
            # 内容路径：真模型下只报告
            if "no_secret" not in got:
                (failures if strict else advisories).append(
                    "B 的生成证书应命中 no_secret —— 真模型下说明它**拒绝照做**了，"
                    "不是接入失败（想稳定复现请用离线桩）")
            if len(sess.gateway.receipts) != 1:
                failures.append(f"应当只有 1 条回执，实为 {len(sess.gateway.receipts)}")
        if name == "C":
            if not v or not any(r["error"] for r in v):
                failures.append("C 应当签出一张带 error 块的证书（P0-4）")

    # 一把网关横跨两条路径：trace_root 必须**只有一条**
    print("核验配方（第三方只凭公开产物）：")
    for name in names:
        d = (out_root / name).relative_to(REPO) if (out_root / name).is_relative_to(REPO) else out_root / name
        print(f"  python3 scripts/verify/verify_session.py --session {d}/session.json")
    print()

    if advisories:
        print("NOTE（真模型下不作数，只如实记录）:")
        for a in advisories:
            print(f"  - {a}")
        print()

    if failures:
        print("FAIL:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
