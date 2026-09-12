#!/usr/bin/env python3
"""Proof-of-Policy 端到端 demo（一条命令跑通）。

真实 agent 会话 → 证书 → 锚定账本 →（可选）真实 SP1 证明。

它演练的是：
  1. LLM 生成路径（LangChain 流式），带**流式证书**（形成哈希链）与**早停**
     （首个违规即停）；
  2. 工具路径，针对**真实 MCP 服务器**（stdio）：参数被认证（含飞行前拦截），
     工具的**结果**也被认证（结果侧）；
  3. zk 层：为一条响应生成真实 SP1 证明（除非 --no-prove），通过 vkey 哈希 +
     `binding.proof_mode` 如实标注证据档位（core/compressed 的 STARK 并非零知识）+
     证明哈希绑定进证书；并走一次**真实的挑战流程**（P0-2）：客户端先出题
     （一次性 nonce），证明方把 (nonce, T) 一起承诺进公开值，最后用**送达的
     响应 T′** 与 nonce 离线核对 —— 演示里还会故意送错一条 T′ 来看它被拒；
  4. **公私模式对比**：同一条响应、同一条策略，公开模式与私有模式各出一张证书
     （都进同一个会话，verify_session 一并验），并把「验证方在这两张证书里分别
     看得见什么」**现读**出来并排打印 —— 公开模式的违规证据是明文（关键词规则
     会把命中的那个词本身写进证书），私有模式只有承诺 + 可选择性开示的证据。
     ⚠️ 这两张证书**默认只做宿主校验**（标 `unproven`）：本 demo 这条策略的
     **私有模式证明在本机证不了**（见 `mode_contrast` 的 docstring）。
     `--no-contrast` 整步跳过；`--contrast-prove`（≥16 GB）才给它们出真证明；
  5. 每张证书都锚定进一个仅追加、防篡改的账本；给了 `--rpc/--contract` 时
     **同时登记到 Anchor 合约**（链上存在性 + 时间戳，链上成功后回写本地 meta）。

每张证书都用 **Ed25519** 签名（P0-3）：demo 缺省生成一把**临时**密钥（不落盘），
把**公钥**写进 `session.json` 的 `signers` 字段。于是第三方只凭公开的 session.json
就能独立验签 —— 而 demo 自己手里那把私钥，验证方拿不到、也就伪造不了。

之后用 `python3 scripts/verify_session.py ...` 独立验证这一切。

用法：
  SP1_PROVER=cpu python3 scripts/demo_e2e.py [--out-dir DIR] [--no-prove] [--nonce auto|<hex>|none] [--key <私钥.pem>]
  # 链上锚定（另开终端跑 `anvil`，先部署合约：python3 scripts/deploy_anchor.py）
  SP1_PROVER=cpu python3 scripts/demo_e2e.py --no-prove \
      --rpc http://127.0.0.1:8545 --contract 0x5FbDB2315678afecb367f032d93F642f64180aa3
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

from policydsl import anchor, cert, challenge, commit, keys  # noqa: E402
from policydsl.agent import AgentMonitor  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.langchain_adapter import PoPCallbackHandler  # noqa: E402
from policydsl.mcp_adapter import MCPBlocked, MCPGuard  # noqa: E402
from policydsl.serialize import spec_canonical_text  # noqa: E402
import issue_cert as ic  # noqa: E402  （复用 load_policy/run_pop/POP_SCRIPT）

# 内容策略包 / 工具策略包 / MCP 服务器脚本
CONTENT_PACK = "policy_packs/agent_content_v1.json"
TOOL_PACK = "policy_packs/agent_tool_v1.json"
SERVER = REPO / "tests" / "mcp_echo_server.py"
CLEAN_REPLY = "A safe reply about the refund policy."
BAD_REPLY = "Leak sk-abcdefghijklmnopqrstuvwxyz now"
# 公私模式对比专用的响应：同一句话**同时踩中** keyword 与 pattern 两条规则。
# 踩 keyword 是要紧的 —— 它的公开证据是**命中的那个词本身**，于是「公开模式
# 会把响应内容泄进证书、私有模式只给承诺」这件事才看得出来（见 print_mode_contrast）。
CONTRAST_REPLY = "I will exploit the vulnerability and leak sk-abcdefghijklmnopqrstuvwxyz"


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
            nonce: bytes = b"", proof_mode: str = "core",
            signer: "cert.Signer" = None, tag: str = "", mode: str = "public"):
    """为一条响应生成真实 SP1 证明（或宿主校验），并签发绑定它的证书。

    ``nonce`` 是客户端事先出的挑战值（P0-2）：它随响应一起进电路，产出
    ``response_binding``，证书的 ``challenge`` 块把它公开出来。
    ``signer`` 是出证方的 Ed25519 签名器（缺省临时生成一把）。
    ``tag`` 区分同一次会话里的多份证明（各自一个子目录，避免互相覆盖）。
    ``mode`` 是 ``public`` / ``private``：私有模式要多带掩码、脱敏文本与见证区间
    （与 ``issue_cert.py --mode private`` 同一套构造），电路据此走
    ``evaluate_private``，公开值里只有承诺。
    """
    policy = ic.load_policy(REPO / CONTENT_PACK)
    spec = compile_policy(policy)
    zk_dir = out_dir / f"zk{tag}"
    zk_dir.mkdir(parents=True, exist_ok=True)
    vectors = zk_dir / "vectors.json"
    vector = {
        "name": policy.id, "response": response,
        "spec_canonical": spec_canonical_text(spec),
        "nonce": list(nonce)}
    if mode == "private":
        # 私有模式的见证：掩码 / 脱敏文本 / 见证区间（与 issue_cert.py --mode private
        # 同一套构造）。掩码来自策略里的 pattern_block —— 内容包只有「密钥」那一条，
        # 所以掩码覆盖的正是响应里那段密钥（mask_count 会如实反映长度）。
        patterns = [p for c in spec["constraints"] if c["kind"] == "pattern_block"
                    for p in c["patterns"]]
        mask = commit.mask_from_patterns(patterns, response) if patterns else []
        spans = commit.spec_spans(spec, response) if patterns else []
        vector.update({"private": True, "mask": mask,
                       "redacted": commit.redact(response, mask), "spans": spans})
    vectors.write_text(json.dumps({"vectors": [vector]}, indent=2))
    results = zk_dir / "results.json"
    proof = zk_dir / "proof.bin"
    if no_prove:
        # 仅宿主校验，不生成证明
        ic.run_pop(["--check", "--vectors", str(vectors), "--out", str(results)])
        vkey_hash, proof_sha, proof_rel, pv_sha = "unproven", None, None, None
        # 诚实标注（P0-4）：没有工件 ⇒ 只能记 unproven
        proof_mode = cert.PROOF_MODE_UNPROVEN
    else:
        # 真实证明 + 元信息（vkey_hash）+ 证明哈希绑定
        cmd = ["--vectors", str(vectors), "--out", str(results), "--proof-out", str(proof)]
        if proof_mode != "core":
            cmd += ["--proof-mode", proof_mode]
        ic.run_pop(cmd)
        meta = json.loads(Path(f"{proof}.meta.json").read_text())
        vkey_hash = meta["vkey_hash"]
        # 模式取 pop-script 写下的边车元信息 —— 证书如实转述**实际产出的**那一档
        proof_mode = meta.get("proof_mode") or proof_mode
        proof_sha = ic.sha256_file(proof)
        proof_rel = str(proof.relative_to(out_dir))
        pv_file = Path(f"{proof}.pv")
        pv_sha = ic.sha256_file(pv_file) if pv_file.exists() else None
    got = json.loads(results.read_text())[0]
    outcome = {k: v for k, v in got.items() if k not in ("name", "mode")}
    payload = cert.build_payload(policy.id, policy.version, spec, mode, outcome,
                                 vkey_hash, proof_sha, public_values_sha256=pv_sha,
                                 challenge=challenge.challenge_block(
                                     nonce, outcome["response_binding"]),
                                 proof_mode=proof_mode)
    env = cert.sign_payload(payload, signer or keys.ephemeral_signer())
    return env, policy.id, proof_rel, outcome["passed"], proof_mode


def challenge_experiment(env: dict, delivered: str) -> bool:
    """挑战流程的收尾核对（P0-2）：用**送达的 T′** 离线验绑定。

    三件事一起演示，缺一不可：
      - 正确的 T′ 通过（绑定确实能用）；
      - 换一条 T′ 失败（**这就是中间人换货被抓住的地方**）；
      - 同一个 nonce 配另一条响应也算出的绑定不同 ⇒ 换 nonce 同样失败。
    """
    payload = cert.envelope_payload(env)
    ch = payload.get("challenge") or {}
    nonce_hex, binding = ch.get("nonce"), ch.get("response_binding")
    ok_delivered = challenge.check_challenge(payload, delivered)
    ok_tampered = not challenge.check_challenge(payload, delivered + " (被替换)")
    ok_nonce = False
    if isinstance(nonce_hex, str) and isinstance(binding, str):
        nonce = challenge.parse_nonce(nonce_hex)
        other = bytes(len(nonce))  # 另一个挑战值（全零），必然与随机 nonce 不同
        ok_nonce = (other != nonce
                    and challenge.verify_binding(nonce, delivered, binding)
                    and not challenge.verify_binding(other, delivered, binding))
    ok = ok_delivered and ok_tampered and ok_nonce
    print(f"[{'PASS' if ok else 'FAIL'}] challenge delivered_T'_ok={ok_delivered} "
          f"tampered_T'_rejected={ok_tampered} wrong_nonce_rejected={ok_nonce}")
    return ok


def print_mode_contrast(pub_env: dict, priv_env: dict, spec: dict, response: str) -> bool:
    """同一条 T、同一条策略、两种模式 —— 把验证方**实际看得见的东西**并排打出来。

    表里每一格都是从两份证书的 ``outcome`` **现读**的，不是手写的说明文字：
    策略一改、规则一换，这张表跟着变（否则它就变成又一处会漂移的文档）。
    """
    p = cert.envelope_payload(pub_env)
    v = cert.envelope_payload(priv_env)
    po, vo = p["outcome"], v["outcome"]

    def evidence(o):
        """公开模式给明文 evidence；私有模式只给 evidence_commitment。"""
        return [(x["rule"], x.get("evidence") or x.get("evidence_commitment") or "?")
                for x in o.get("violations", [])]

    same = (po["passed"] == vo["passed"] and p["policy_hash"] == v["policy_hash"])
    rd = vo.get("redaction") or {}
    rows = [
        ("结论 passed", str(po["passed"]), str(vo["passed"])),
        ("策略指纹 policy_hash", p["policy_hash"][:16] + "…", v["policy_hash"][:16] + "…"),
        ("命中了哪几条规则", " ".join(r for r, _ in evidence(po)) or "—",
         " ".join(r for r, _ in evidence(vo)) or "—"),
        ("每条规则的证据", ", ".join(f"{r}「{e}」" for r, e in evidence(po)) or "—",
         ", ".join(f"{r} {e[:16]}…" for r, e in evidence(vo)) or "—"),
        ("响应本身的承诺", "—（该模式不承诺 T）",
         (vo.get("response_commitment") or "—")[:16] + "…"),
        ("脱敏见证", "—",
         f"mask_count={rd.get('mask_count')} mask_covered={rd.get('mask_covered')}"),
    ]
    # 中英混排下 str.ljust 按**字符**补齐会错位，这里按**显示宽度**补（CJK 记 2 列）。
    # 口径与 demo_all.sh 的 pad() 保持一致：只有 East_Asian_Width ∈ {W,F} 记 2 列。
    # 别改成 `ord(c) > 0x2000` —— 那会把 `—`(U+2014) / `…`(U+2026) 这些
    # *Ambiguous* 字符也算成 2 列，于是**含这两个字符的行会整体左移一格**，
    # 正是这两个脚本口径不一致时会犯的错。
    def width(s: str) -> int:
        return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in s)

    def fit(s: str, n: int) -> str:
        return s + " " * max(0, n - width(s))

    w1 = max(width(r[0]) for r in rows)
    w2 = max(width("公开模式"), *(width(r[1]) for r in rows))
    print(f"[{'PASS' if same else 'FAIL'}] 对比前提 同一 T · 同一策略："
          f"policy_hash 相同={p['policy_hash'] == v['policy_hash']} "
          f"passed 相同={po['passed'] == vo['passed']}（={po['passed']}）")
    print(f"     {fit('验证方能看到', w1)}   {fit('公开模式', w2)} 私有模式")
    for label, a, b in rows:
        print(f"     {fit(label, w1)}   {fit(a, w2)} {b}")

    # 私有模式真正的出口：证据可以**选择性开示**。开示件必须与证书里的承诺对得上，
    # 篡改一件必须被拒 —— 否则「承诺」就只是装饰，不构成可核对的披露。
    bundle = commit.evidence_bundle(spec, response)
    ok_open = commit.verify_bundle(bundle)
    proof_comms = {x["evidence_commitment"] for x in vo.get("violations", [])}
    bundled = {e["evidence_commitment"] for e in bundle}
    tampered = [dict(e) for e in bundle]
    if tampered:
        tampered[0]["evidence"] = "tampered"
    ok_reject = not commit.verify_bundle(tampered)
    ok_disclose = ok_open and proof_comms == bundled and ok_reject
    print(f"[{'PASS' if ok_disclose else 'FAIL'}] 选择性开示 开示件自洽={ok_open} "
          f"与证明里的承诺逐条相符={proof_comms == bundled} 篡改被拒={ok_reject}"
          f"（公开模式没有这一步 —— 证据本来就是明文）")
    return same and ok_disclose


def mode_contrast(out_dir: Path, response: str, vkey: str, prove: bool,
                  signer, proof_mode: str):
    """同一个挑战值喂给两种模式，各出一张证书 —— 这才是控制变量的对比。

    ``prove`` 缺省 **False**（`--contrast-prove` 才打开），原因不是省时间而是**证不了**：
    拿本 demo 的 `agent_content_v1`（3 条规则、含 `pattern_block`）出证，
    **公开模式**能过，**私有模式**在本机（11.9 GB）实测被内核 OOM-kill
    （`anon-rss` 10.391 GiB，而本机的可用天花板约 10.385 GiB —— 见 README
    「公私模式对比」一节）。私有模式的真证明由支路② `private_demo.py` 承担，
    那条策略更小、实测峰值 10.383 GiB 能过。所以这里默认只做**宿主校验**，
    两张证书如实标注 `proof_mode: unproven`。
    """
    spec = compile_policy(ic.load_policy(REPO / CONTENT_PACK))
    nonce = challenge.new_nonce()
    no_prove = not prove
    pub = zk_path(out_dir, response, vkey, no_prove, nonce, proof_mode, signer,
                  tag="_public", mode="public")
    priv = zk_path(out_dir, response, vkey, no_prove, nonce, proof_mode, signer,
                   tag="_private", mode="private")
    ok = print_mode_contrast(pub[0], priv[0], spec, response)
    return pub, priv, ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", type=Path, default=REPO / "scripts" / "examples" / "out" / "e2e")
    ap.add_argument("--no-prove", action="store_true", help="skip the real SP1 proof")
    ap.add_argument("--no-contrast", action="store_true", help="跳过公私模式对比")
    ap.add_argument("--contrast-prove", action="store_true",
                    help="给对比的两张证书也出真证明。**默认关闭**：本机 11.9 GB 上"
                         "这条策略的私有模式证明需要 ~10.39 GiB，会被内核 OOM-kill"
                         "（见 README「公私模式对比」）。≥16 GB 的机器可以打开")
    ap.add_argument("--proof-mode", choices=["core", "compressed", "groth16", "plonk"],
                    default="core", help="core (default) or compressed for verifier-only audit")
    ap.add_argument("--nonce", default="auto",
                    help="挑战值：auto（默认，现场生成）| none（不绑定）| <hex>")
    ap.add_argument("--rpc", default=None, help="EVM RPC：把每张证书摘要同时登记上链")
    ap.add_argument("--contract", default=None, help="已部署的 Anchor 合约地址")
    ap.add_argument("--private-key", default=None, help="上链提交私钥（默认 Anvil #0）")
    ap.add_argument("--key", type=Path, default=None,
                    help="Ed25519 私钥文件。缺省生成**临时**密钥对（不落盘），"
                         "公钥以 keyid + hex 打印并写进 session.json")
    args = ap.parse_args()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    ledger = out_dir / "ledger.jsonl"
    # 宿主三类证书（stream/llm/tool）的 `binding.vkey_hash`。
    #
    # 这里**不是**一个「暂时还没接上真值」的占位符 —— 这三类证书根本没有证明，
    # 也就没有验证密钥可指，`unproven` 就是它们的**正确**取值（与 `cert.py`
    # 的 VKEY_HASH_UNPROVEN、`agent.py` 的缺省、`issue_cert.py:200`、
    # `zk_path --no-prove` 四处口径一致）。
    #
    # 此前的魔法值 `"demo"` 不只是不好看：`vkey_hash` 的语义是「哪块电路判定了
    # 它」，`"demo"` 让这个字段看起来像有内容，而验证方只比对「证书 vs 证明」，
    # 从不问这个值本身是否可能是真的 —— 于是它**全绿通过**。反过来说，给这三类
    # 证书塞一个**真** vkey 哈希（比如从 pop-program 的工件里取）会更坏：
    # `"demo"` 一眼是占位符，真哈希会让人读成「由 pop-program 判定过」，
    # 而实际判定是宿主 Python 做的 —— 那是过度声明，正是 P0-4 要消灭的东西。
    #
    # 真 vkey 只属于 zk 路径，而那条路径已经是真的：`zk_path` 出证后用
    # `proof.meta.json` 里的 `vkey_hash` **覆盖**这个值（见 zk_path 的 no_prove 分支）。
    vkey = cert.VKEY_HASH_UNPROVEN
    session_entries = []

    # ---- 0) 出证方签名密钥（P0-3）：Ed25519。验证方只需公钥 ----
    # 缺省用**进程内临时**密钥：demo 不往仓库里留私钥文件；公钥随 session.json
    # 交给验证方，所以事后仍能独立验签（见 verify_session.py）。
    signer = keys.signer_from_env(args.key) if args.key else keys.ephemeral_signer()

    # ---- 1) LLM 流式路径（哈希链 + 早停） ----
    content = AgentMonitor(ic.load_policy(REPO / CONTENT_PACK), signer=signer)
    handler = PoPCallbackHandler(content, vkey_hash=vkey, stop_on_violation=True)
    llm_stream_path(content, handler)
    for env in handler.stream_certificates:
        session_entries.append({"kind": "stream", "policy_pack": CONTENT_PACK, "envelope": env})
    for env in handler.certificates:
        session_entries.append({"kind": "llm", "policy_pack": CONTENT_PACK, "envelope": env})

    # ---- 2) MCP 工具路径（参数 + 结果） ----
    tools = AgentMonitor(ic.load_policy(REPO / TOOL_PACK), signer=signer)
    guard = asyncio.run(mcp_path(tools, content, vkey))
    for env in guard.certificates:
        session_entries.append({"kind": "tool-args", "policy_pack": TOOL_PACK, "envelope": env})
    for env in guard.result_certificates:
        session_entries.append({"kind": "tool-result", "policy_pack": CONTENT_PACK, "envelope": env})

    # ---- 3) zk 路径（真实 SP1 证明 + 真实挑战流程） ----
    # 挑战由**客户端**（这里是扮演该角色的 demo）先出，证明方只能照做 ——
    # 这正是 P0-2 想表达的信任方向：出题权在验证方手里。
    nonce = ic.resolve_nonce(args.nonce)
    zk_env, zk_policy, proof_rel, zk_passed, zk_mode = zk_path(out_dir, CLEAN_REPLY, vkey,
                                                               args.no_prove, nonce,
                                                               args.proof_mode, signer)
    entry = {"kind": "zk", "policy_pack": CONTENT_PACK, "envelope": zk_env}
    if proof_rel:
        entry["proof"] = proof_rel
    session_entries.append(entry)
    ok_challenge = challenge_experiment(zk_env, CLEAN_REPLY)

    # ---- 3b) 公私模式对比（同一个 T、同一条策略，两张证书）----
    # 这一段的产物**也进会话**（kind 同为 "zk"），所以 verify_session.py 会连着
    # 把两张证书一起验 —— 对比演示不额外开一条验证旁路。
    contrast = None
    if not args.no_contrast:
        (cpub, cpriv, ok_contrast) = mode_contrast(
            out_dir, CONTRAST_REPLY, vkey, args.contrast_prove, signer, args.proof_mode)
        # zk_path 返回 (env, policy_id, proof_rel, passed, proof_mode) 五元组 ——
        # 这里按位取（解包成 4 个会当场 ValueError，别退回去）。
        contrast = {"ok": ok_contrast, "proved": args.contrast_prove,
                    "public": {"proof": cpub[2], "passed": cpub[3], "proof_mode": cpub[4]},
                    "private": {"proof": cpriv[2], "passed": cpriv[3], "proof_mode": cpriv[4]}}
        # 条目本身不必标 public/private —— 证书载荷里的 "mode" 字段已经写明了。
        for _tag, c in (("public", cpub), ("private", cpriv)):
            e = {"kind": "zk", "policy_pack": CONTENT_PACK, "envelope": c[0]}
            if c[2]:
                e["proof"] = c[2]
            session_entries.append(e)

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
        # 出证方公钥（P0-3）：第三方**只需要这一条**就能独立验签全部证书。
        # 私钥从头到尾没有离开出证方。
        "signers": [keys.public_record(signer.public_key)],
        "certificates": session_entries,
        "summary": {
            "certificates": len(session_entries),
            "stream_certs": sum(1 for e in session_entries if e["kind"] == "stream"),
            "blocked_tool_calls": getattr(guard, "_blocked", []),
            # 工具轨迹（P1-5）：网关签发的回执链。链尾摘要 + 网关公钥都是**公开**
            # 坐标 —— 验证方拿网关侧收到的回执重算最后一条的 SHA256，即可独立核对
            # 「这份证明绑的是哪条链」，无需相信出证方的转述。
            "tool_trace": {
                "receipts": len(guard.receipts),
                "trace_root": guard.gateway.trace_root,
                "gateway_keyid": guard.gateway.signer.keyid,
                "gateway_public_hex": getattr(guard.gateway.signer, "public_hex", None),
                # P1-5b：网关对**会话末端**的签名承诺。验证方拿它核对链长与链尾，
                # 从而能发现「链尾那条违规回执被整条删掉」。
                "seal": guard.gateway.seal().to_dict(),
            },
            "zk_passed": zk_passed,
            # 诚实标注（P0-4）：这张 zk 证书到底附了哪一档证据
            "zk_proof_mode": zk_mode,
            # 公私模式对比（3b）：两张证书都在 certificates 里，这里只记结论
            "mode_contrast": contrast,
            "challenge_bound": ok_challenge,
            "ledger_ok": ok_chain,
            "on_chain": on_chain["n"],
        },
    }
    # 挑战坐标（nonce + 绑定）是**公开**的：谁持有一条候选响应 T′，都能凭它离线
    # 核对「这条 T′ 是不是被证明的那条」。刻意不把 T 本身写进会话包 —— 演示里它
    # 是公开的，但真实场景下那正是要被保护的内容。
    zk_ch = cert.envelope_payload(zk_env).get("challenge")
    if zk_ch:
        session["challenge"] = zk_ch
    if on_chain["n"]:
        # 第三方验证只需公开坐标：把 RPC + 合约地址写进 session
        session["chain"] = {"rpc_url": backend.rpc_url, "contract": on_chain["contract"],
                            "chain_id": backend.client.chain_id(),
                            "anchored": on_chain["n"], "last_tx": on_chain.get("tx_hash")}
    (out_dir / "session.json").write_text(json.dumps(session, indent=2))

    print(f"session     : {out_dir / 'session.json'}")
    print(f"signer      : {signer.keyid}")
    print(f"              public_hex={signer.public_hex}")
    print(f"certificates: {session['summary']['certificates']} "
          f"(stream={session['summary']['stream_certs']})")
    print(f"blocked tool calls: {session['summary']['blocked_tool_calls']}")
    tt = session["summary"]["tool_trace"]
    print(f"tool trace  : {tt['receipts']} receipt(s), "
          f"trace_root={tt['trace_root'][:16]}… (gateway {tt['gateway_keyid']})")
    print(f"zk proof    : {proof_rel or '(skipped: --no-prove)'}  passed={zk_passed}")
    print(f"proof_mode  : {zk_mode} (hiding: {cert.proof_hiding(zk_mode)})")
    if zk_ch:
        print(f"challenge   : nonce={zk_ch['nonce'][:16]}… "
              f"response_bound={ok_challenge}")
    if contrast is not None:
        # 如实说清这两张证书附的是哪一档证据：默认**只有宿主校验**，
        # 别让「对比演示通过」被读成「两种模式都出证了」。
        print(f"mode contrast: 公开/私有各一张证书已入会话 "
              f"(passed={contrast['public']['passed']}) —— 上面那张表是现读的")
        print(f"             证据档位: {'core（--contrast-prove）' if contrast['proved'] else 'unproven（宿主校验；本机 12 GB 证不了这条策略的私有模式，见 README）'}")
    print(f"ledger      : {ledger} chain={reason}")
    if on_chain["n"]:
        print(f"on-chain    : {on_chain['n']}/{len(session_entries)} anchored on "
              f"{on_chain['contract']} (tx={str(on_chain.get('tx_hash'))[:18]}…)")
    else:
        print("on-chain    : skipped (no --rpc/--contract; pass them to anchor on a real chain)")
    print("\nverify with: python3 scripts/verify_session.py --session " + str(out_dir / "session.json"))
    ok = ok_chain and ok_challenge and (contrast is None or contrast["ok"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
