#!/usr/bin/env python3
"""阶段五：独立验证一张 Proof-of-Policy 合规证书。

第三方仅持有公开工件，检查：
  1. DSSE 信封签名（完整性/真实性）；
  2. （带 --proof 时）SP1 证明做密码学验证，其承诺的 outcome + vkey 哈希与证书一致；
  3. 策略绑定**三方比对**：证书声明的 policy_hash == 由策略包现场重编译的 sha256
     == 证明公开值承诺的 policy_hash（三者必须同时成立，见 policydsl.verifier）；
  4. 证书摘要存在于锚定账本中、且账本链完整（记录留存/防篡改）；
  5. （带 --rpc/--contract 时）证书摘要能在 Anchor 合约上读回（链上存在性 + 时间戳）。

步骤 2 必须排在步骤 3 之前：三方比对里的「证明公开值」要先验出来才谈得上比对。

用法：
  python3 scripts/verify_cert.py --cert scripts/examples/out/cert_public/cert.json \
      --pack policy_packs/eu_ai_act_v1.json \
      --ledger scripts/examples/out/ledger.jsonl \
      [--proof scripts/examples/out/cert_public/proof.bin] \
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

from policydsl import anchor, cert, verifier
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
    ap.add_argument("--rpc", default=None, help="EVM RPC 端点（链上锚定核对）")
    ap.add_argument("--contract", default=None, help="已部署的 Anchor 合约地址")
    args = ap.parse_args()

    env = json.loads(args.cert.read_text(encoding="utf-8"))
    results = []

    # 1) 签名校验
    ok_sig, payload = cert.verify_envelope(env, cert.DEMO_KEY)
    results.append(("signature", ok_sig, "HMAC-SHA256 envelope verified" if ok_sig else "bad signature"))
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
