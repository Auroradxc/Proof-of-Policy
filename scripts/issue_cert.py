#!/usr/bin/env python3
"""阶段五：为一条响应签发合规证书，然后锚定它。

流水线：
  策略包 + 响应 --(公开：SP1 证明 / 私有：承诺证明)--> 公开值
  公开值 + policy_hash + vkey_hash + ts --(DSSE 签名)--> cert.json
  证书摘要 --> 锚定账本（仅追加、防篡改）；给了 --rpc/--contract 时**同时**上链

用法：
  SP1_PROVER=cpu python3 scripts/issue_cert.py \
      --pack policy_packs/eu_ai_act_v1.json \
      --response scripts/examples/eu_agent_reply.txt \
      --out-dir scripts/examples/out/cert_public [--mode public|private] [--no-prove]

链上锚定（可选，需要一条 EVM 链 + 已部署的 contracts/Anchor.sol）：
  python3 scripts/issue_cert.py ... --rpc http://127.0.0.1:8545 --contract 0x...
  （也可用环境变量 POP_ANCHOR_RPC / POP_ANCHOR_CONTRACT；未配置则只写文件账本）
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

from policydsl import anchor, cert, commit
from policydsl.compile import compile_policy
from policydsl.model import Policy, Rule
from policydsl.serialize import spec_canonical_text

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"


def load_policy(path: Path) -> Policy:
    """从 JSON 文件加载策略包。"""
    d = json.loads(path.read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r.get("name", f"r{i}"), params=r.get("params", {}))
             for i, r in enumerate(d["rules"])]
    return Policy(d["id"], d.get("version", "0.1.0"), rules=rules)


def sha256_file(path: Path) -> str:
    """对文件字节求 SHA-256（用于证明工件哈希绑定）。"""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_pop(args: list[str]) -> None:
    """调用 pop-script 驱动（强制 SP1_PROVER=cpu）。"""
    subprocess.run([str(POP_SCRIPT), *args], env=dict(os.environ, SP1_PROVER="cpu"),
                   check=True, cwd=str(REPO))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", type=Path, required=True)
    ap.add_argument("--response", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--mode", choices=["public", "private"], default="public")
    ap.add_argument("--proof-mode", choices=["core", "compressed", "groth16", "plonk"],
                    default="core", help="core (fast, default) or compressed for verifier-only audit")
    ap.add_argument("--ledger", type=Path, default=REPO / "scripts" / "examples" / "out" / "ledger.jsonl")
    ap.add_argument("--no-prove", action="store_true", help="host-check only (no SP1 proof)")
    ap.add_argument("--rpc", default=None, help="EVM RPC：把证书摘要同时登记上链")
    ap.add_argument("--contract", default=None, help="已部署的 Anchor 合约地址")
    ap.add_argument("--private-key", default=None, help="上链提交私钥（默认 Anvil #0）")
    args = ap.parse_args()

    policy = load_policy(args.pack)
    response = args.response.read_text(encoding="utf-8")
    spec = compile_policy(policy)
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # 构造单个证明请求向量
    vector = {"name": policy.id, "response": response,
              "spec_canonical": spec_canonical_text(spec)}
    if args.mode == "private":
        # 私有模式：附带掩码、脱敏文本与见证区间（witness spans）
        patterns = [p for c in spec["constraints"] if c["kind"] == "pattern_block"
                    for p in c["patterns"]]
        mask = commit.mask_from_patterns(patterns, response) if patterns else []
        spans = commit.spec_spans(spec, response) if patterns else []
        vector.update({"private": True, "mask": mask,
                       "redacted": commit.redact(response, mask), "spans": spans})

    vectors = out_dir / "vectors.json"
    vectors.write_text(json.dumps({"vectors": [vector]}, indent=2))
    results = out_dir / "results.json"
    proof = out_dir / "proof.bin"

    if args.no_prove:
        # 仅宿主校验（不生成 SP1 证明）
        run_pop(["--check", "--vectors", str(vectors), "--out", str(results)])
        vkey_hash = "unproven"
        proof_sha = None
        pv_sha = None
    else:
        # 真实证明：产出 proof.bin + 元信息（含 vkey_hash）
        cmd = ["--vectors", str(vectors), "--out", str(results), "--proof-out", str(proof)]
        if args.proof_mode != "core":
            cmd += ["--proof-mode", args.proof_mode]
        run_pop(cmd)
        meta = json.loads(Path(f"{proof}.meta.json").read_text())
        vkey_hash = meta["vkey_hash"]
        proof_sha = sha256_file(proof)
        pv_file = Path(f"{proof}.pv")
        pv_sha = sha256_file(pv_file) if pv_file.exists() else None

    # 组装证书载荷（去掉 name/mode 元信息，得到纯 outcome）
    got = json.loads(results.read_text())[0]
    outcome = {k: v for k, v in got.items() if k not in ("name", "mode")}
    payload = cert.build_payload(policy.id, policy.version, spec, args.mode, outcome,
                                 vkey_hash, proof_sha, public_values_sha256=pv_sha)
    env = cert.sign_payload(payload, cert.DEMO_KEY)
    (out_dir / "cert.json").write_text(json.dumps(env, indent=2))
    (out_dir / "payload.json").write_text(json.dumps(payload, indent=2))

    # 锚定到账本（给了 --rpc/--contract 时同时上链，链上成功后回写本地 meta）
    digest = cert.cert_digest(payload)
    backend = anchor.backend_from_env(args.ledger, rpc_url=args.rpc, contract=args.contract,
                                      private_key=args.private_key)
    entry = backend.anchor(digest, {"policy": policy.id, "mode": args.mode,
                                    "proved": not args.no_prove})
    (out_dir / "anchor.json").write_text(json.dumps(entry, indent=2))

    print(f"policy_hash : {spec['sha256']}")
    print(f"vkey_hash   : {vkey_hash}")
    print(f"passed      : {outcome['passed']}")
    print(f"cert_digest : {digest}")
    if entry.get("backend") == "rpc":
        print(f"anchor      : backend=rpc status={entry['status']} tx={str(entry.get('tx_hash'))[:18]}… "
              f"contract={entry['contract']} chain_ts={entry.get('chain_ts')}")
        print(f"              local ledger seq={entry.get('ledger', {}).get('seq')} ({args.ledger})")
    else:
        print(f"anchor      : seq={entry['seq']} hash={entry['hash'][:16]}… ledger={args.ledger}")
    print(f"wrote       : {out_dir}/cert.json, payload.json, results.json" +
          ("" if args.no_prove else f", {proof.name}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
