#!/usr/bin/env python3
"""Proof-of-Policy 端到端 demo（一条命令跑通）。

真实 agent 会话 → 证书 → 锚定账本 →（可选）真实 SP1 证明。

它演练的是：
  1. LLM 生成路径（LangChain 流式），带**流式证书**（形成哈希链）与**早停**
     （首个违规即停）；
  2. 工具路径，针对**真实 MCP 服务器**（stdio）：参数被认证（含飞行前拦截），
     工具的**结果**也被认证（结果侧）；
  3. zk 层：为一条响应生成真实 SP1 证明（除非 --no-prove），通过 vkey 哈希 +
     证明哈希绑定进证书；
  4. 每张证书都锚定进一个仅追加、防篡改的账本；给了 `--rpc/--contract` 时
     **同时登记到 Anchor 合约**（链上存在性 + 时间戳，链上成功后回写本地 meta）。

之后用 `python3 scripts/verify_session.py ...` 独立验证这一切。

用法：
  SP1_PROVER=cpu python3 scripts/demo_e2e.py [--out-dir DIR] [--no-prove]
  # 链上锚定（另开终端跑 `anvil`，先部署合约：python3 scripts/deploy_anchor.py）
  SP1_PROVER=cpu python3 scripts/demo_e2e.py --no-prove \
      --rpc http://127.0.0.1:8545 --contract 0x5FbDB2315678afecb367f032d93F642f64180aa3
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

from policydsl import anchor, cert  # noqa: E402
from policydsl.agent import AgentMonitor  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.langchain_adapter import PoPCallbackHandler  # noqa: E402
from policydsl.mcp_adapter import MCPBlocked, MCPGuard  # noqa: E402
from policydsl.serialize import spec_to_rust_constraints  # noqa: E402
import issue_cert as ic  # noqa: E402  （复用 load_policy/run_pop/POP_SCRIPT）

# 内容策略包 / 工具策略包 / MCP 服务器脚本
CONTENT_PACK = "policy_packs/agent_content_v1.json"
TOOL_PACK = "policy_packs/agent_tool_v1.json"
SERVER = REPO / "tests" / "mcp_echo_server.py"
CLEAN_REPLY = "A safe reply about the refund policy."
BAD_REPLY = "Leak sk-abcdefghijklmnopqrstuvwxyz now"


def llm_stream_path(monitor: AgentMonitor, handler: PoPCallbackHandler) -> None:
    """两次流式运行：一次干净、一次违规（触发早停 + 链式证书）。"""
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    # 干净响应：不违规，正常流式完成
    clean = GenericFakeChatModel(messages=iter([AIMessage(content=CLEAN_REPLY)]))
    for _ in clean.stream("hi", config={"callbacks": [handler]}):
        pass
    # 违规响应：流式中途泄露 secret_key，触发早停
    bad = GenericFakeChatModel(messages=iter([AIMessage(content=BAD_REPLY)]))
    for _ in bad.stream("hi", config={"callbacks": [handler]}):
        pass


async def mcp_path(tools: AgentMonitor, content: AgentMonitor, vkey: str) -> list:
    """通过守护调用真实 MCP 服务器（参数 + 结果认证）。"""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    guard = MCPGuard(tools, vkey_hash=vkey, block_on_violation=True,
                     result_monitor=content, block_on_result_violation=False)
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])
    blocked = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await guard.call_tool(session, "search_kb", {"query": "refund"})   # 干净
            await guard.call_tool(session, "dump_config", {})                  # 秘密结果
            try:
                # 带 secret token 的调用 → 飞行前拦截
                await guard.call_tool(session, "search_kb", {"query": "x", "token": "s"})
            except MCPBlocked as exc:
                blocked.append(exc.phase)
    guard._blocked = blocked  # type: ignore[attr-defined]
    return guard


def zk_path(out_dir: Path, response: str, vkey: str, no_prove: bool,
            proof_mode: str = "core"):
    """为一条响应生成真实 SP1 证明（或宿主校验），并签发绑定它的证书。"""
    policy = ic.load_policy(REPO / CONTENT_PACK)
    spec = compile_policy(policy)
    zk_dir = out_dir / "zk"
    zk_dir.mkdir(parents=True, exist_ok=True)
    vectors = zk_dir / "vectors.json"
    vectors.write_text(json.dumps({"vectors": [{
        "name": policy.id, "response": response,
        "constraints": spec_to_rust_constraints(spec)}]}, indent=2))
    results = zk_dir / "results.json"
    proof = zk_dir / "proof.bin"
    if no_prove:
        # 仅宿主校验，不生成证明
        ic.run_pop(["--check", "--vectors", str(vectors), "--out", str(results)])
        vkey_hash, proof_sha, proof_rel, pv_sha = "unproven", None, None, None
    else:
        # 真实证明 + 元信息（vkey_hash）+ 证明哈希绑定
        cmd = ["--vectors", str(vectors), "--out", str(results), "--proof-out", str(proof)]
        if proof_mode != "core":
            cmd += ["--proof-mode", proof_mode]
        ic.run_pop(cmd)
        meta = json.loads(Path(f"{proof}.meta.json").read_text())
        vkey_hash = meta["vkey_hash"]
        proof_sha = ic.sha256_file(proof)
        proof_rel = str(proof.relative_to(out_dir))
        pv_file = Path(f"{proof}.pv")
        pv_sha = ic.sha256_file(pv_file) if pv_file.exists() else None
    got = json.loads(results.read_text())[0]
    outcome = {k: v for k, v in got.items() if k not in ("name", "mode")}
    payload = cert.build_payload(policy.id, policy.version, spec, "public", outcome,
                                 vkey_hash, proof_sha, public_values_sha256=pv_sha)
    return cert.sign_payload(payload, cert.DEMO_KEY), policy.id, proof_rel, outcome["passed"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", type=Path, default=REPO / "scripts" / "examples" / "out" / "e2e")
    ap.add_argument("--no-prove", action="store_true", help="skip the real SP1 proof")
    ap.add_argument("--proof-mode", choices=["core", "compressed", "groth16", "plonk"],
                    default="core", help="core (default) or compressed for verifier-only audit")
    ap.add_argument("--rpc", default=None, help="EVM RPC：把每张证书摘要同时登记上链")
    ap.add_argument("--contract", default=None, help="已部署的 Anchor 合约地址")
    ap.add_argument("--private-key", default=None, help="上链提交私钥（默认 Anvil #0）")
    args = ap.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger = out_dir / "ledger.jsonl"
    vkey = "demo"
    session_entries = []

    # ---- 1) LLM 流式路径（哈希链 + 早停） ----
    content = AgentMonitor(ic.load_policy(REPO / CONTENT_PACK))
    handler = PoPCallbackHandler(content, vkey_hash=vkey, stop_on_violation=True)
    llm_stream_path(content, handler)
    for env in handler.stream_certificates:
        session_entries.append({"kind": "stream", "policy_pack": CONTENT_PACK, "envelope": env})
    for env in handler.certificates:
        session_entries.append({"kind": "llm", "policy_pack": CONTENT_PACK, "envelope": env})

    # ---- 2) MCP 工具路径（参数 + 结果） ----
    tools = AgentMonitor(ic.load_policy(REPO / TOOL_PACK))
    guard = asyncio.run(mcp_path(tools, content, vkey))
    for env in guard.certificates:
        session_entries.append({"kind": "tool-args", "policy_pack": TOOL_PACK, "envelope": env})
    for env in guard.result_certificates:
        session_entries.append({"kind": "tool-result", "policy_pack": CONTENT_PACK, "envelope": env})

    # ---- 3) zk 路径（真实 SP1 证明） ----
    zk_env, zk_policy, proof_rel, zk_passed = zk_path(out_dir, CLEAN_REPLY, vkey,
                                                      args.no_prove, args.proof_mode)
    entry = {"kind": "zk", "policy_pack": CONTENT_PACK, "envelope": zk_env}
    if proof_rel:
        entry["proof"] = proof_rel
    session_entries.append(entry)

    # ---- 4) 把每张证书锚定进账本（可选：同时上链） ----
    backend = anchor.backend_from_env(ledger, rpc_url=args.rpc, contract=args.contract,
                                      private_key=args.private_key)
    on_chain = {"status": "anchored", "n": 0}
    for e in session_entries:
        payload = cert.envelope_payload(e["envelope"])
        rec = backend.anchor(cert.cert_digest(payload),
                             {"kind": e["kind"], "policy": payload["policy"]["id"]})
        if rec.get("backend") == "rpc":
            on_chain["n"] += rec["status"] in ("anchored", "already_anchored")
            on_chain["status"] = rec["status"]
            on_chain["contract"] = rec["contract"]
            on_chain["tx_hash"] = rec.get("tx_hash")
    ok_chain, reason = anchor.verify_ledger(ledger)

    # 汇总会话，写入 session.json
    session = {
        "session_id": out_dir.name,
        "ledger": ledger.name,
        "packs": sorted({e["policy_pack"] for e in session_entries}),
        "certificates": session_entries,
        "summary": {
            "certificates": len(session_entries),
            "stream_certs": sum(1 for e in session_entries if e["kind"] == "stream"),
            "blocked_tool_calls": getattr(guard, "_blocked", []),
            "zk_passed": zk_passed,
            "ledger_ok": ok_chain,
            "on_chain": on_chain["n"],
        },
    }
    if on_chain["n"]:
        # 第三方验证只需公开坐标：把 RPC + 合约地址写进 session
        session["chain"] = {"rpc_url": backend.rpc_url, "contract": on_chain["contract"],
                            "chain_id": backend.client.chain_id(),
                            "anchored": on_chain["n"], "last_tx": on_chain.get("tx_hash")}
    (out_dir / "session.json").write_text(json.dumps(session, indent=2))

    print(f"session     : {out_dir / 'session.json'}")
    print(f"certificates: {session['summary']['certificates']} "
          f"(stream={session['summary']['stream_certs']})")
    print(f"blocked tool calls: {session['summary']['blocked_tool_calls']}")
    print(f"zk proof    : {proof_rel or '(skipped: --no-prove)'}  passed={zk_passed}")
    print(f"ledger      : {ledger} chain={reason}")
    if on_chain["n"]:
        print(f"on-chain    : {on_chain['n']}/{len(session_entries)} anchored on "
              f"{on_chain['contract']} (tx={str(on_chain.get('tx_hash'))[:18]}…)")
    else:
        print("on-chain    : skipped (no --rpc/--contract; pass them to anchor on a real chain)")
    print("\nverify with: python3 scripts/verify_session.py --session " + str(out_dir / "session.json"))
    return 0 if ok_chain else 1


if __name__ == "__main__":
    sys.exit(main())
