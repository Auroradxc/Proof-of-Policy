#!/usr/bin/env python3
"""阶段五：独立验证一张 Proof-of-Policy 合规证书。

第三方仅持有公开工件，检查：
  1. DSSE 信封签名（完整性/真实性）—— 用**出证方公钥**（P0-3：Ed25519，非对称，
     验证方无法伪造；缺省读证书同目录的 key.json，或用 --keyring 显式给出）；
  2. （带 --proof 时）SP1 证明做密码学验证，其承诺的 outcome + vkey 哈希与证书一致；
     并核对证书自称的 `binding.proof_mode` 与工件自报的模式（边车/元信息）一致
     —— core/compressed 的 STARK 并非零知识，这一档必须如实标注（P0-4）；
  3. 策略绑定**三方比对**：证书声明的 policy_hash == 由策略包现场重编译的 sha256
     == 证明公开值承诺的 policy_hash（三者必须同时成立，见 policydsl.verifier）；
  3b. 响应绑定（P0-2）：证书 challenge 块声明的 response_binding == outcome 内嵌的
     == 证明公开值承诺的 == 由**送达的响应 T′** 与 nonce 现场重算的。带 --response
     时这一路才齐全 —— 那也正是「持 T′ 的一方」要做的核对；
  4. 证书摘要存在于锚定账本中、且账本链完整（记录留存/防篡改）；
  5. （带 --rpc/--contract 时）证书摘要能在 Anchor 合约上读回（链上存在性 + 时间戳）。

步骤 2 必须排在步骤 3/3b 之前：比对里的「证明公开值」要先验出来才谈得上比对。

**不带 --proof 时的边界**：步骤 3/3b 仍会跑，但参与比对的来源只剩证书自己的两处
声称（载荷顶层 vs outcome 内嵌）。那两处都是签发者写的，所以它挡得住「证书自相
矛盾」，挡不住「签发者整体造假」—— 真正的密码学保证来自步骤 2 的证明。

用法：
  python3 scripts/verify_cert.py --cert scripts/examples/out/cert_public/cert.json \
      --pack policy_packs/eu_ai_act_v1.json \
      --ledger scripts/examples/out/ledger.jsonl \
      [--proof scripts/examples/out/cert_public/proof.bin] \
      [--response scripts/examples/eu_agent_reply.txt] [--nonce <hex>] \
      [--keyring scripts/examples/out/cert_public/key.json] \
      [--rpc http://127.0.0.1:8545 --contract 0x...]
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

from policydsl import anchor, cert, challenge, commit, keys, verifier
from policydsl.compile import compile_policy
from policydsl.model import Policy, Rule

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
    ap.add_argument("--cert", type=Path, required=True)
    ap.add_argument("--pack", type=Path, required=True)
    ap.add_argument("--ledger", type=Path, required=True)
    ap.add_argument("--proof", type=Path, default=None)
    ap.add_argument("--response", type=Path, default=None,
                    help="送达的响应 T′：给了才能把「被证明的 T」与「收到的 T′」对上")
    ap.add_argument("--nonce", default=None,
                    help="覆盖证书里的挑战值（十六进制）；用于验证重放/换 nonce 会被拒")
    ap.add_argument("--rpc", default=None, help="EVM RPC 端点（链上锚定核对）")
    ap.add_argument("--contract", default=None, help="已部署的 Anchor 合约地址")
    ap.add_argument("--keyring", default=None,
                    help="出证方公钥：key.json / *.pub.hex / *.pub.pem / hex 文本。"
                         "缺省读证书同目录的 key.json")
    args = ap.parse_args()

    env = json.loads(args.cert.read_text(encoding="utf-8"))
    results = []

    # 1) 签名校验（P0-3）：非对称 —— 验证方只拿公钥，无法伪造签名。
    try:
        keyring = keys.load_keyring(args.keyring) if args.keyring else keys.load_keyring(
            args.cert.parent / "key.json")
    except (OSError, ValueError, TypeError) as exc:
        print(f"  [FAIL] keyring        无法获得出证方公钥：{exc}\n"
              f"         请用 --keyring 指定（见 scripts/gen_key.py --pubkey）")
        print("\nRESULT: FAIL")
        return 1
    if not keyring:
        print("  [FAIL] keyring        公钥 ring 为空，无法验签")
        print("\nRESULT: FAIL")
        return 1
    ok_sig, payload = cert.verify_envelope(env, keyring)
    scheme = cert.envelope_scheme(env)
    results.append(("signature", ok_sig,
                    f"{scheme or 'no-signature'} envelope verified [{cert.envelope_keyid(env) or '-'}]"
                    if ok_sig else "bad signature (or unknown/revoked scheme)"))
    if not ok_sig or payload is None:
        print_fail(results)
        return 1

    # 2) 证明校验（可选，密码学）—— 优先走 verifier-only 二进制（免构造证明器）
    #
    #    放在策略绑定之前：绑定要做「三方比对」，其中一方是**证明公开值承诺的
    #    policy_hash**，必须先把证明验出来才谈得上比对。否则验证方只能核对
    #    「证书自称 == 重编译」，而漏掉「证明其实是对另一个策略做的」。
    POP_VERIFY = REPO / "circuits" / "target" / "release" / "pop-verify"
    sidecar = verifier.sidecar_path(args.proof) if args.proof else None
    proof_result = None  # 验证器输出的原始 JSON；policy_hash 三方比对要用
    if args.proof is not None and args.proof.exists() and verifier.prefer_verifier_only(args.proof, POP_VERIFY):
        # 存在边车 + pop-verify 已构建 → 走快路径（无需 ~10GB 证明器状态）
        out = args.proof.parent / "verify_only.json"
        subprocess.run([str(POP_VERIFY), "--meta", str(sidecar), "--out", str(out)],
                       check=True, cwd=str(REPO))
        v = proof_result = json.loads(out.read_text())
        b = payload["binding"]
        results.append(("verify_only", bool(v.get("verified")),
                        f"pop-verify ({v.get('proof_mode')}, no prover)"))
        results.append(("public_values", v.get("public_values_sha256") == b.get("public_values_sha256"),
                        "committed public values match"))
        results.append(("vkey_hash", v.get("vkey_hash") == b.get("vkey_hash"), "vkey matches"))
        # 快路径过去只比公开值的哈希，证书里的 outcome 完全没被核对过；
        # 现在 pop-verify 会把公开值解回 Outcome，这里逐字段比对。
        decoded = verifier.outcome_without_meta(v)
        results.append(("proof_outcome", decoded is not None and decoded == payload["outcome"],
                        "decoded public values == certificate outcome"))
    elif args.proof is not None and args.proof.exists():
        # 无边车 → 用 pop-script 重新验证（core 证明路径）
        out = args.proof.parent / "verify_out.json"
        subprocess.run([str(POP_SCRIPT), "--verify", "--proof", str(args.proof), "--out", str(out)],
                       env=dict(os.environ, SP1_PROVER="cpu"), check=True, cwd=str(REPO))
        v = proof_result = json.loads(out.read_text())
        ok_verified = bool(v.get("verified"))
        ok_outcome = verifier.outcome_without_meta(v) == payload["outcome"]
        ok_vkey = v.get("vkey_hash") == payload["binding"]["vkey_hash"]
        ok_sha = sha256_file(args.proof) == payload["binding"]["proof_sha256"]
        results.append(("proof_verify", ok_verified, "SP1 proof verified (pop-script)"))
        results.append(("proof_outcome", ok_outcome, "committed outcome == certificate"))
        results.append(("proof_vkey", ok_vkey, "vkey hash matches"))
        results.append(("proof_sha256", ok_sha, "proof artifact hash matches"))
    elif payload["binding"]["proof_sha256"] is None:
        # 证书未声称有证明（host-check only）→ 跳过
        results.append(("proof", True, "certificate is unproven (host-check only) — skipped"))
    else:
        results.append(("proof", False, "certificate claims a proof but --proof not given"))

    # 2b) 证明模式标注（P0-4）：证书自称的那一档，要与**工件自报的**一致。
    #
    #     core/compressed 的 STARK **不是零知识**证明（见 docs/sp1-zk-audit.md），
    #     所以「这张证书到底是哪一档证据」不能只由出证方一句话决定 —— 工件的
    #     边车与元信息都自报模式，三者必须指向同一档。没有工件的证书则只允许
    #     标 unproven：声称 core/compressed 却拿不出证明，是**过度声明**。
    declared_mode = (payload.get("binding") or {}).get("proof_mode")
    has_artifact = args.proof is not None and args.proof.exists()
    observed = verifier.artifact_proof_modes(args.proof, proof_result) if has_artifact else {}
    if declared_mode is None:
        # P0-4 之前签发的证书没有这个字段：如实跳过，而不是当成通过。
        results.append(("proof_mode", True, "certificate predates the field — skipped"))
    elif observed:
        modes = sorted(set(observed.values()))
        agree = len(modes) == 1 and modes[0] == declared_mode
        srcs = " == ".join(f"{m}[{s}]" for s, m in observed.items())
        results.append(("proof_mode", agree,
                        f"cert={declared_mode} (hiding: {cert.proof_hiding(declared_mode)}); {srcs}"
                        if agree else f"MISMATCH: cert={declared_mode} vs {srcs}"))
    elif has_artifact:
        results.append(("proof_mode", True,
                        f"cert={declared_mode} — 工件未自报模式，无法核对 (skipped)"))
    elif (payload.get("binding") or {}).get("proof_sha256") is None:
        # 没有证明工件：唯一诚实的标注就是 unproven。
        ok_unproven = declared_mode == cert.PROOF_MODE_UNPROVEN
        results.append(("proof_mode", ok_unproven,
                        f"{declared_mode} (hiding: {cert.proof_hiding(declared_mode)})"
                        + ("" if ok_unproven else
                           " — 未附证明的证书只能标注 unproven，不得声称某档证据")))
    else:
        results.append(("proof_mode", True,
                        f"cert={declared_mode} — no --proof given, 无法核对 (skipped)"))

    # 3) 策略绑定（三方比对）：
    #      a. 证书载荷声明的 policy_hash
    #      b. 证书 outcome 内嵌的 policy_hash（证书内部两处声称必须自洽）
    #      c. 由策略包**现场重编译**得到的 sha256
    #      d. 证明公开值承诺的 policy_hash（有证明时）
    #    任何两个相等都可能有盲区：只比 a==c 会漏掉「证明是对别的策略做的」，
    #    只比 a==d 会漏掉「证书声称的策略根本不是这个策略包」。必须一起比。
    spec = compile_policy(load_policy(args.pack))
    sources = [
        ("cert", payload.get("policy_hash")),
        ("cert.outcome", (payload.get("outcome") or {}).get("policy_hash")),
        ("recompiled", spec["sha256"]),
        ("proof", verifier.committed_policy_hash(proof_result) if proof_result else None),
    ]
    ok_pol, pol_detail = verifier.check_policy_binding(sources)
    results.append(("policy_hash", ok_pol, pol_detail))

    # 3b) 响应绑定（P0-2）：被证明的 T 是不是送达的 T′。
    #
    #     策略绑定保证「判定的规则就是声明的策略」，却完全不提「判定的是哪条
    #     响应」—— 公开模式还好（T 至少是证明的输入），私有模式下验证者连 T 的
    #     影子都看不到。这一卡补的就是那一段：把 T 拴到本次会话的 nonce 上。
    #
    #     证书里**没有** challenge 块（或证明的公开值里没有 response_binding）时
    #     如实跳过 —— 那是「这张证书本来就没绑定响应」，不是「绑定通过」。
    ch = payload.get("challenge") or {}
    proof_binding = verifier.committed_response_binding(proof_result) if proof_result else None
    if not ch and proof_binding is None:
        results.append(("response_binding", True,
                        "certificate is not challenge-bound — skipped (no challenge block)"))
    else:
        nonce_hex = args.nonce if args.nonce is not None else ch.get("nonce")
        recomputed, note = None, ""
        if args.response is not None:
            if nonce_hex is None:
                note = " (--response given 但证书没有 nonce，无法重算)"
            else:
                try:
                    recomputed = commit.response_binding(
                        challenge.parse_nonce(nonce_hex),
                        args.response.read_text(encoding="utf-8"))
                    note = " — 送达的 T′ 就是被证明的 T"
                except ValueError as exc:
                    note = f" (nonce 无法解析: {exc})"
        ok_bind, bind_detail = verifier.check_response_binding([
            ("cert.challenge", ch.get("response_binding")),
            ("cert.outcome", (payload.get("outcome") or {}).get("response_binding")),
            ("proof", proof_binding),
            ("response", recomputed),
        ])
        if not ok_bind and recomputed is not None:
            note = " — 送达的 T′ 与被证明的 T 对不上"
        results.append(("response_binding", ok_bind, bind_detail + note))

    # 4) 锚定账本：链完整 + 证书摘要确实在账本中
    ok_chain, reason = anchor.verify_ledger(args.ledger)
    digest = cert.cert_digest(payload)
    entry = anchor.find_anchor(args.ledger, digest)
    ok_anchor = ok_chain and entry is not None
    results.append(("anchor", ok_anchor, f"chain={reason} entry={'found' if entry else 'MISSING'}"))

    # 4b) 链上锚定（可选，只读核对）
    if args.rpc and args.contract:
        try:
            rec = anchor.verify_digest_on_chain(digest, args.rpc, args.contract)
            if rec is None:
                results.append(("anchor_on_chain", False, f"digest not found on {args.contract}"))
            else:
                oc = (entry.get("meta") or {}).get("on_chain") if entry else None
                consistent = oc is None or oc.get("chain_ts") == rec["chain_ts"]
                results.append(("anchor_on_chain", consistent,
                                f"ts={rec['chain_ts']} ({rec['chain_ts_iso']}) by={rec['anchored_by']}"
                                + ("" if consistent else f" ≠ ledger meta {oc.get('chain_ts')}")))
        except anchor.AnchorError as exc:
            results.append(("anchor_on_chain", False, f"rpc error: {exc}"))
    elif args.rpc or args.contract:
        results.append(("anchor_on_chain", False, "--rpc and --contract must be given together"))

    ok_all = all(r[1] for r in results)
    print(f"certificate: {args.cert}")
    print(f"policy={payload['policy']['id']}@{payload['policy']['version']} mode={payload['mode']} "
          f"passed={payload['outcome'].get('passed')} ts={payload['ts']}")
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:14s} {detail}")
    print("\nRESULT: " + ("PASS" if ok_all else "FAIL"))
    return 0 if ok_all else 1


def print_fail(results) -> None:
    """签名失败时打印已得结果并返回失败。"""
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:14s} {detail}")
    print("\nRESULT: FAIL")


if __name__ == "__main__":
    sys.exit(main())
