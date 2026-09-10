#!/usr/bin/env python3
"""阶段五：独立验证一张 Proof-of-Policy 合规证书。

第三方仅持有公开工件，检查：
  1. DSSE 信封签名（完整性/真实性）；
  2. policy_hash == 现在重新编译的策略包的 sha256（策略绑定）；
  3. 证书摘要存在于锚定账本中、且账本链完整（记录留存/防篡改）；
  4. （带 --proof 时）SP1 证明做密码学验证，其承诺的 outcome + vkey 哈希与证书一致；
  5. （带 --rpc/--contract 时）证书摘要能在 Anchor 合约上读回（链上存在性 + 时间戳）。

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

    # 2) 策略绑定：证书里的 policy_hash 必须等于「现在」重编译得到的哈希
    spec = compile_policy(load_policy(args.pack))
    ok_pol = payload["policy_hash"] == spec["sha256"]
    results.append(("policy_hash", ok_pol,
                    f"{payload['policy_hash'][:16]}… vs {spec['sha256'][:16]}…"))

    # 3) 锚定账本：链完整 + 证书摘要确实在账本中
    ok_chain, reason = anchor.verify_ledger(args.ledger)
    digest = cert.cert_digest(payload)
    entry = anchor.find_anchor(args.ledger, digest)
    ok_anchor = ok_chain and entry is not None
    results.append(("anchor", ok_anchor, f"chain={reason} entry={'found' if entry else 'MISSING'}"))

    # 3b) 链上锚定（可选，只读核对）
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

    # 4) 证明校验（可选，密码学）—— 优先走 verifier-only 二进制（免构造证明器）
    POP_VERIFY = REPO / "circuits" / "target" / "release" / "pop-verify"
    sidecar = verifier.sidecar_path(args.proof) if args.proof else None
    if args.proof is not None and args.proof.exists() and verifier.prefer_verifier_only(args.proof, POP_VERIFY):
        # 存在边车 + pop-verify 已构建 → 走快路径（无需 ~10GB 证明器状态）
        out = args.proof.parent / "verify_only.json"
        subprocess.run([str(POP_VERIFY), "--meta", str(sidecar), "--out", str(out)],
                       check=True, cwd=str(REPO))
        v = json.loads(out.read_text())
        b = payload["binding"]
        results.append(("verify_only", bool(v.get("verified")),
                        f"pop-verify ({v.get('proof_mode')}, no prover)"))
        results.append(("public_values", v.get("public_values_sha256") == b.get("public_values_sha256"),
                        "committed public values match"))
        results.append(("vkey_hash", v.get("vkey_hash") == b.get("vkey_hash"), "vkey matches"))
    elif args.proof is not None and args.proof.exists():
        # 无边车 → 用 pop-script 重新验证（core 证明路径）
        out = args.proof.parent / "verify_out.json"
        subprocess.run([str(POP_SCRIPT), "--verify", "--proof", str(args.proof), "--out", str(out)],
                       env=dict(os.environ, SP1_PROVER="cpu"), check=True, cwd=str(REPO))
        v = json.loads(out.read_text())
        ok_verified = bool(v.get("verified"))
        outcome = v.get("outcome", {})
        outcome.pop("name", None)
        outcome.pop("mode", None)
        ok_outcome = outcome == payload["outcome"]
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
