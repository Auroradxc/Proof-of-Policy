#!/usr/bin/env python3
"""独立验证一个 Proof-of-Policy 端到端会话包（session bundle）。

仅凭公开工件（session.json + ledger + 可选 proof），检查：
  0. 出证方公钥：取自 session.json 的 ``signers``（或 --keyring / 同目录 key.json）。
     P0-3 起是 Ed25519 —— 验证方只持公钥，**无法伪造**证书；
  1. 锚定账本链完整（防篡改的记录留存）；
  2. 每张证书：DSSE 签名有效 + policy_hash 三方比对（证书声明 / 证书 outcome 内嵌 /
     由策略包现场重编译）+ 证书摘要存在于账本中；带 challenge 块的证书再做一次
     证书内部的响应绑定自洽比对（challenge 块 vs outcome 内嵌，P0-2）；
  3. 流式证书形成有效的哈希链（按 run）；
  4. zk 证书的 SP1 证明做密码学验证，其承诺的 outcome / vkey 哈希 / 证明哈希与证书一致，
     并补上策略绑定与响应绑定各自缺失的那条腿（证明公开值承诺的 policy_hash 与
     response_binding）；证书自称的 `binding.proof_mode` 还须与工件自报的模式一致
     （core/compressed 并非零知识，这一档必须如实标注，P0-4）；
  5. （可选）链上锚定核对：每个证书摘要都能在 Anchor 合约上读回，且链上记录与本地
     账本 meta 里的 tx/区块/时间戳一致（**需要 RPC**，见下）。

用法：
  python3 scripts/verify_session.py --session scripts/examples/out/e2e/session.json
  # 链上核对：--rpc/--contract 显式给出，或用 session 里记录的 chain 字段
  python3 scripts/verify_session.py --session ... --rpc http://127.0.0.1:8545 \
      --contract 0x5FbDB2315678afecb367f032d93F642f64180aa3
  python3 scripts/verify_session.py --session ... --no-chain   # 强制只做链下核对
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import anchor, cert, keys, verifier  # noqa: E402
from policydsl.compile import compile_policy  # noqa: E402
from policydsl.langchain_adapter import verify_chain  # noqa: E402
from policydsl.model import Policy, Rule  # noqa: E402
# 快路径判定（二进制 + 边车 + 非 core 模式）在 policydsl.verifier；此处再导出以兼容旧导入
from policydsl.verifier import prefer_verifier_only  # noqa: E402,F401

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"


def load_policy(path: Path) -> Policy:
    """从 JSON 文件加载策略包。"""
    d = json.loads(path.read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r.get("name", f"r{i}"), params=r.get("params", {}))
             for i, r in enumerate(d["rules"])]
    return Policy(d["id"], d.get("version", "0.1.0"), rules=rules)


def sha256_file(path: Path) -> str:
    """对文件字节求 SHA-256。"""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", type=Path, required=True)
    ap.add_argument("--rpc", default=None, help="EVM RPC 端点（链上锚定核对）")
    ap.add_argument("--contract", default=None, help="已部署的 Anchor 合约地址")
    ap.add_argument("--no-chain", action="store_true", help="即使 session 记录了 chain 也跳过链上核对")
    ap.add_argument("--private-key", default=None, help=argparse.SUPPRESS)  # 只读核对用不到，保留兼容
    ap.add_argument("--keyring", default=None,
                    help="出证方公钥（key.json / *.pub.hex / hex 文本）。缺省读 "
                         "session.json 里的 signers 字段，再回退到同目录 key.json")
    args = ap.parse_args()

    base = args.session.parent
    session = json.loads(args.session.read_text(encoding="utf-8"))
    ledger = base / session.get("ledger", "ledger.jsonl")
    entries = session["certificates"]
    results = []

    # 0) 出证方公钥（P0-3）：只拿公钥就能验签，拿不到就没法开始
    try:
        keyring = keys.merge_keyrings(args.keyring,
                                      session.get("signers"),
                                      base / "key.json")
    except (OSError, ValueError, TypeError) as exc:
        print(f"  [FAIL] keyring         无法获得出证方公钥：{exc}\n"
              f"         请用 --keyring 指定")
        print("\nRESULT: FAIL")
        return 1
    if not keyring:
        print("  [FAIL] keyring         session 未记录 signers，且同目录没有 key.json；"
              "请用 --keyring 给出公钥")
        print("\nRESULT: FAIL")
        return 1

    # 0) 账本链
    ok_chain, reason = anchor.verify_ledger(ledger)
    results.append(("ledger_chain", ok_chain, reason))

    # policy hash 缓存（同一策略包只编译一次）
    spec_cache = {}
    def spec_for(pack: str):
        if pack not in spec_cache:
            spec_cache[pack] = compile_policy(load_policy(REPO / pack))
        return spec_cache[pack]

    # 1) 逐证书检查：签名 / policy_hash / 锚定
    sig_ok = pol_ok = anch_ok = True
    pol_bad: list[str] = []
    bind_ok = True
    bind_bad: list[str] = []
    bound_n = 0
    mode_ok = True
    mode_bad: list[str] = []
    mode_marked = mode_skipped = 0
    kinds = {}
    for e in entries:
        env = e["envelope"]
        ok, payload = cert.verify_envelope(env, keyring)
        sig_ok &= ok
        if not ok or payload is None:
            pol_ok = anch_ok = bind_ok = False
            continue
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
        # policy_hash 三方比对（链下部分）：证书载荷、证书 outcome 内嵌值、
        # 由策略包现场重编译的 sha256。带证明的证书还会在下面第 3 步补上
        # 「证明公开值承诺的 policy_hash」这一路。
        ok_pol, pol_detail = verifier.check_policy_binding([
            ("cert", payload.get("policy_hash")),
            ("cert.outcome", (payload.get("outcome") or {}).get("policy_hash")),
            ("recompiled", spec_for(e["policy_pack"])["sha256"]),
        ])
        pol_ok &= ok_pol
        if not ok_pol:
            pol_bad.append(pol_detail)
        # 响应绑定（P0-2）：证书内部两处声称（challenge 块 vs outcome 内嵌）必须一致。
        # 没有 challenge 块的证书（流式/工具路径）不参与 —— 那是「本来就没绑定」，
        # 不是「绑定通过」。真正的密码学那一腿在第 4 步用证明公开值补上。
        if payload.get("challenge"):
            bound_n += 1
            ok_bind, bind_detail = verifier.check_response_binding([
                ("cert.challenge", payload["challenge"].get("response_binding")),
                ("cert.outcome", (payload.get("outcome") or {}).get("response_binding")),
            ])
            bind_ok &= ok_bind
            if not ok_bind:
                bind_bad.append(bind_detail)
        # 证明模式标注（P0-4）：证书要么标 unproven、要么附了证明，二者必居其一。
        # 标了某档模式却拿不出工件 = 过度声明；有了工件却标 unproven = 低报。
        declared_mode = (payload.get("binding") or {}).get("proof_mode")
        if declared_mode is None:
            mode_skipped += 1   # P0-4 之前签发的证书没有这个字段
        else:
            mode_marked += 1
            has_proof = payload["binding"].get("proof_sha256") is not None
            ok_mode = ((declared_mode != cert.PROOF_MODE_UNPROVEN) == has_proof)
            mode_ok &= ok_mode
            if not ok_mode:
                mode_bad.append(
                    f"{e['kind']}: proof_mode={declared_mode} 但 proof_sha256="
                    f"{'有' if has_proof else 'null'}")
        anch_ok &= anchor.find_anchor(ledger, cert.cert_digest(payload)) is not None
    results.append(("certificates_signature", sig_ok,
                    f"{len(entries)} certs, {len(keyring)} key(s) in ring"))
    pol_detail = f"{len(spec_cache)} pack(s), 3 sources" if pol_ok else "; ".join(pol_bad[:2])
    results.append(("certificates_policy_hash", pol_ok, pol_detail))
    results.append(("certificates_response_binding", bind_ok,
                    f"{bound_n} challenge-bound cert(s), self-consistent"
                    if bind_ok else "; ".join(bind_bad[:2])))
    results.append(("certificates_proof_mode", mode_ok,
                    f"{mode_marked} cert(s) labeled, {mode_skipped} predate the field"
                    if mode_ok else "; ".join(mode_bad[:2])))
    results.append(("certificates_anchored", anch_ok, "digest present in ledger"))

    # 2) 流式链：在 chain.index == 0 处拆成多个 run
    groups, current = [], []
    for e in entries:
        if e["kind"] != "stream":
            continue
        payload = cert.envelope_payload(e["envelope"])
        chain = (payload.get("streaming") or {}).get("chain") or {}
        if chain.get("index") == 0 and current:
            groups.append(current); current = []
        current.append(e["envelope"])
    if current:
        groups.append(current)
    chain_ok = all(verify_chain(g) for g in groups) if groups else True
    results.append(("stream_chains", chain_ok, f"{len(groups)} run(s)"))

    # 3) zk 证明 —— 存在边车时优先走 verifier-only 二进制
    POP_VERIFY = REPO / "circuits" / "target" / "release" / "pop-verify"
    zk_entries = [e for e in entries if e["kind"] == "zk"]
    zk_ok = True
    # 逐条记录每种结局的**条数**再汇总 —— 早先这里是一个被覆盖的 `detail` 标量，
    # 于是「1 张真证明 + 2 张宿主校验」的会话会只印最后一张的 "unproven"，
    # 把已经验过的证明说没了。混合会话现在是常态（公私对比的两张证书就是 unproven）。
    tally: dict[str, int] = {}
    for e in zk_entries:
        payload = cert.envelope_payload(e["envelope"])
        proof_rel = e.get("proof")
        if not proof_rel:
            # 未证明（host-check only）：要求证书也没有声称有证明
            zk_ok &= payload["binding"]["proof_sha256"] is None
            tally["unproven (host-check only)"] = tally.get("unproven (host-check only)", 0) + 1
            continue
        proof = base / proof_rel
        sidecar = verifier.sidecar_path(proof)
        if prefer_verifier_only(proof, POP_VERIFY):
            # 免证明器快路径
            out = base / "verify_only.json"
            subprocess.run([str(POP_VERIFY), "--meta", str(sidecar), "--out", str(out)],
                           check=True, cwd=str(REPO))
            v = json.loads(out.read_text())
            b = payload["binding"]
            zk_ok &= bool(v.get("verified"))
            zk_ok &= v.get("public_values_sha256") == b.get("public_values_sha256")
            zk_ok &= v.get("vkey_hash") == b.get("vkey_hash")
            zk_ok &= sha256_file(proof) == payload["binding"]["proof_sha256"]
            # 公开值解出来的 outcome 必须与证书载荷逐字段一致（含 policy_hash）
            zk_ok &= verifier.outcome_without_meta(v) == payload["outcome"]
            kind = f"pop-verify ({v.get('proof_mode')}, no prover)"
        else:
            # Core 证明：用 pop-script --verify 重新验证
            out = base / "verify_out.json"
            subprocess.run([str(POP_SCRIPT), "--verify", "--proof", str(proof), "--out", str(out)],
                           env=dict(os.environ, SP1_PROVER="cpu"), check=True, cwd=str(REPO))
            v = json.loads(out.read_text())
            zk_ok &= bool(v.get("verified"))
            zk_ok &= verifier.outcome_without_meta(v) == payload["outcome"]
            zk_ok &= v.get("vkey_hash") == payload["binding"]["vkey_hash"]
            zk_ok &= sha256_file(proof) == payload["binding"]["proof_sha256"]
            kind = "SP1 proof verified (pop-script)"
        # 这一条自己成功了，之后绑定的失败注解单独记 —— 成功种类按条计数。
        notes: list[str] = []
        tally[kind] = tally.get(kind, 0) + 1
        # 证明模式标注（P0-4）：证书自称的这一档，要与工件**自报**的模式一致
        # （边车 / meta / 验证器输出，多来源必须指向同一档）。
        declared = (payload.get("binding") or {}).get("proof_mode")
        observed = verifier.artifact_proof_modes(proof, v)
        if declared is not None and observed:
            modes = sorted(set(observed.values()))
            if modes != [declared]:
                zk_ok = False
                notes.append("proof_mode MISMATCH: cert={} vs {}"
                             .format(declared,
                                     " == ".join(f"{m}[{s}]" for s, m in observed.items())))
        # 第三方比对的最后一腿：证明公开值承诺的 policy_hash，必须与证书声明的
        # 一致，也必须与「该证书所用的策略包现场重编译」所得一致。
        ok_bind, bind_detail = verifier.check_policy_binding([
            ("cert", payload.get("policy_hash")),
            ("recompiled", spec_for(e["policy_pack"])["sha256"]),
            ("proof", verifier.committed_policy_hash(v)),
        ])
        zk_ok &= ok_bind
        if not ok_bind:
            notes.append(bind_detail)
        # 响应绑定同理：证明公开值承诺的 response_binding 必须与证书里那两处
        # 声称一致。这三路都指向「被证明的 T」，缺了它，证书所说的「某条响应
        # 通过了」就没法拴到任何一条具体响应上。
        ok_rbind, rbind_detail = verifier.check_response_binding([
            ("cert.challenge", (payload.get("challenge") or {}).get("response_binding")),
            ("cert.outcome", (payload.get("outcome") or {}).get("response_binding")),
            ("proof", verifier.committed_response_binding(v)),
        ])
        zk_ok &= ok_rbind
        if not ok_rbind:
            notes.append(rbind_detail)
        if notes:
            key = "问题: " + " | ".join(notes)
            tally[key] = tally.get(key, 0) + 1
    # 汇总成「每种结局各几条」，形如 `SP1 proof verified (pop-script)×1 + unproven×2`。
    detail = " + ".join(f"{k}×{n}" if n > 1 else k for k, n in tally.items()) or "n/a"
    results.append(("zk_proof", zk_ok, detail))

    # 4) 链上锚定核对（可选）：每个证书摘要都能从 Anchor 合约读回，且链上时间戳
    #    与本地账本 meta 记录的区块一致（用了 --rpc 或 session 里记录了 chain）
    chain_cfg = session.get("chain") or {}
    rpc = args.rpc or chain_cfg.get("rpc_url")
    contract = args.contract or chain_cfg.get("contract")
    if args.no_chain:
        results.append(("chain_anchored", True, "skipped (--no-chain)"))
    elif not (rpc and contract):
        results.append(("chain_anchored", True, "not anchored on chain (file ledger only)"))
    else:
        try:
            cli = anchor.CastRpc(rpc)
            on_chain, mismatch, checked = 0, [], 0
            for e in entries:
                digest = cert.cert_digest(cert.envelope_payload(e["envelope"]))
                rec = anchor.verify_digest_on_chain(digest, rpc, contract, client=cli)
                if rec is None:
                    continue
                on_chain += 1
                # 强核对：本地账本 meta 里记的区块时间戳 == 链上登记时间戳
                local = anchor.find_anchor(ledger, digest) or {}
                oc = (local.get("meta") or {}).get("on_chain") or {}
                if oc:
                    checked += 1
                    if oc.get("chain_ts") != rec["chain_ts"]:
                        mismatch.append(f"{digest[:10]}… ts {oc.get('chain_ts')}≠{rec['chain_ts']}")
                    elif oc.get("block") is not None:
                        bts = cli.timestamp_of_block(int(oc["block"]))
                        if bts != rec["chain_ts"]:
                            mismatch.append(f"{digest[:10]}… block {oc['block']} ts {bts}≠{rec['chain_ts']}")
            ok = on_chain == len(entries) and not mismatch
            det = (f"{on_chain}/{len(entries)} digests on chain {contract[:10]}… "
                   f"({checked} cross-checked)")
            if mismatch:
                det += " MISMATCH: " + "; ".join(mismatch[:3])
            results.append(("chain_anchored", ok, det))
        except anchor.AnchorError as exc:
            results.append(("chain_anchored", False, f"rpc error: {exc}"))

    ok_all = all(r[1] for r in results)
    print(f"session: {args.session}")
    print(f"certificates by kind: {kinds}")
    for name, ok, det in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:24s} {det}")
    print("\nRESULT: " + ("PASS" if ok_all else "FAIL"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
