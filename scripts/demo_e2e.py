#!/usr/bin/env python3
"""Proof-of-Policy end-to-end demo (one command).

Real agent session -> certificates -> anchor ledger -> (optional) real SP1 proof.

What it exercises:
  1. LLM generation path (LangChain stream) with **streaming certificates** forming
     a hash chain and **early stop** on the first violation;
  2. tool path against a **real MCP server** (stdio): arguments certified (with
     pre-flight blocking), and the tool's **result** certified too (result side);
  3. the zk layer: a real SP1 proof for one response (unless --no-prove), bound
     into a certificate via vkey hash + proof hash;
  4. every certificate is anchored into an append-only tamper-evident ledger.

Then verify it all independently with:  python3 scripts/verify_session.py ...

Usage:
  SP1_PROVER=cpu python3 scripts/demo_e2e.py [--out-dir DIR] [--no-prove]
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
import issue_cert as ic  # noqa: E402  (reuses load_policy/run_pop/POP_SCRIPT)

CONTENT_PACK = "policy_packs/agent_content_v1.json"
TOOL_PACK = "policy_packs/agent_tool_v1.json"
SERVER = REPO / "tests" / "mcp_echo_server.py"
CLEAN_REPLY = "A safe reply about the refund policy."
BAD_REPLY = "Leak sk-abcdefghijklmnopqrstuvwxyz now"


def llm_stream_path(monitor: AgentMonitor, handler: PoPCallbackHandler) -> None:
    """Two streamed runs: one clean, one violating (early stop + chain)."""
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage

    clean = GenericFakeChatModel(messages=iter([AIMessage(content=CLEAN_REPLY)]))
    for _ in clean.stream("hi", config={"callbacks": [handler]}):
        pass
    bad = GenericFakeChatModel(messages=iter([AIMessage(content=BAD_REPLY)]))
    for _ in bad.stream("hi", config={"callbacks": [handler]}):
        pass


async def mcp_path(tools: AgentMonitor, content: AgentMonitor, vkey: str) -> list:
    """Call the real MCP server through the guard (args + result certification)."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    guard = MCPGuard(tools, vkey_hash=vkey, block_on_violation=True,
                     result_monitor=content, block_on_result_violation=False)
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)])
    blocked = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await guard.call_tool(session, "search_kb", {"query": "refund"})   # clean
            await guard.call_tool(session, "dump_config", {})                  # secret result
            try:
                await guard.call_tool(session, "search_kb", {"query": "x", "token": "s"})
            except MCPBlocked as exc:
                blocked.append(exc.phase)
    guard._blocked = blocked  # type: ignore[attr-defined]
    return guard


def zk_path(out_dir: Path, response: str, vkey: str, no_prove: bool,
            proof_mode: str = "core"):
    """Produce a real SP1 proof (or host check) and a certificate bound to it."""
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
        ic.run_pop(["--check", "--vectors", str(vectors), "--out", str(results)])
        vkey_hash, proof_sha, proof_rel, pv_sha = "unproven", None, None, None
    else:
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
    args = ap.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger = out_dir / "ledger.jsonl"
    vkey = "demo"
    session_entries = []

    # ---- 1) LLM streaming path (chain + early stop) ----
    content = AgentMonitor(ic.load_policy(REPO / CONTENT_PACK))
    handler = PoPCallbackHandler(content, vkey_hash=vkey, stop_on_violation=True)
    llm_stream_path(content, handler)
    for env in handler.stream_certificates:
        session_entries.append({"kind": "stream", "policy_pack": CONTENT_PACK, "envelope": env})
    for env in handler.certificates:
        session_entries.append({"kind": "llm", "policy_pack": CONTENT_PACK, "envelope": env})

    # ---- 2) MCP tool path (args + result) ----
    tools = AgentMonitor(ic.load_policy(REPO / TOOL_PACK))
    guard = asyncio.run(mcp_path(tools, content, vkey))
    for env in guard.certificates:
        session_entries.append({"kind": "tool-args", "policy_pack": TOOL_PACK, "envelope": env})
    for env in guard.result_certificates:
        session_entries.append({"kind": "tool-result", "policy_pack": CONTENT_PACK, "envelope": env})

    # ---- 3) zk path (real SP1 proof) ----
    zk_env, zk_policy, proof_rel, zk_passed = zk_path(out_dir, CLEAN_REPLY, vkey,
                                                      args.no_prove, args.proof_mode)
    entry = {"kind": "zk", "policy_pack": CONTENT_PACK, "envelope": zk_env}
    if proof_rel:
        entry["proof"] = proof_rel
    session_entries.append(entry)

    # ---- 4) anchor every certificate ----
    for e in session_entries:
        digest = cert.cert_digest(cert.envelope_payload(e["envelope"]))
        anchor.append_anchor(ledger, digest,
                             {"kind": e["kind"], "policy": cert.envelope_payload(e["envelope"])["policy"]["id"]})
    ok_chain, reason = anchor.verify_ledger(ledger)

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
        },
    }
    (out_dir / "session.json").write_text(json.dumps(session, indent=2))

    print(f"session     : {out_dir / 'session.json'}")
    print(f"certificates: {session['summary']['certificates']} "
          f"(stream={session['summary']['stream_certs']})")
    print(f"blocked tool calls: {session['summary']['blocked_tool_calls']}")
    print(f"zk proof    : {proof_rel or '(skipped: --no-prove)'}  passed={zk_passed}")
    print(f"ledger      : {ledger} chain={reason}")
    print("\nverify with: python3 scripts/verify_session.py --session " + str(out_dir / "session.json"))
    return 0 if ok_chain else 1


if __name__ == "__main__":
    sys.exit(main())
