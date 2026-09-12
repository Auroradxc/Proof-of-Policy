#!/usr/bin/env python3
"""阶段五：为一条响应签发合规证书，然后锚定它。

流水线：
  挑战 nonce（默认现场生成） + 策略包 + 响应
        --(公开：SP1 证明 / 私有：承诺证明)--> 公开值（含 response_binding）
  公开值 + policy_hash + vkey_hash + ts + challenge 块 --(DSSE 签名)--> cert.json
  证书摘要 --> 锚定账本（仅追加、防篡改）；给了 --rpc/--contract 时**同时**上链

关于 `--nonce`（P0-2）：证明只说明「某条 T 满足 π」，从不说 T 是哪一条。把
挑战值随响应一起承诺进公开值后，持 T′ 与 nonce 的人可以离线核对「被证明的 T」
就是「送达的 T′」。默认 `auto`（现场取一个 32 字节 CSPRNG 挑战值）；`none`
表示不绑定（仅用于对照/兼容，会如实写进证书的 ai_act 声明）。

用法：
  SP1_PROVER=cpu python3 scripts/issue_cert.py \
      --pack policy_packs/eu_ai_act_v1.json \
      --response scripts/examples/eu_agent_reply.txt \
      --out-dir scripts/examples/out/cert_public [--mode public|private] [--no-prove] \
      [--nonce auto|<hex>|none]

签名（P0-3）：用 Ed25519 私钥签名，**私钥不出出证方**。缺省在
`.pop-keys/signing.key` 生成/复用一把（已被 gitignore），可用 `--key` 或环境变量
`POP_SIGNING_KEY` 指定。公钥写到 `<out-dir>/key.json`，第三方验签只需要它。

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

from policydsl import anchor, cert, challenge, commit, keys
from policydsl import semantic as S
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


def resolve_nonce(text: str) -> bytes:
    """把 `--nonce` 的取值解析成挑战值字节。

    ``auto``（默认）= 现场生成；``none`` = 空（不绑定）；其余按十六进制解析。
    """
    t = (text or "auto").strip().lower()
    if t in ("auto", ""):
        return challenge.new_nonce()
    if t == "none":
        return b""
    return challenge.parse_nonce(text)


def sha256_file(path: Path) -> str:
    """对文件字节求 SHA-256（用于证明工件哈希绑定）。"""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_pop(args: list[str]) -> None:
    """调用 pop-script 驱动（强制 SP1_PROVER=cpu）。"""
    subprocess.run([str(POP_SCRIPT), *args], env=dict(os.environ, SP1_PROVER="cpu"),
                   check=True, cwd=str(REPO))


#: 语义规则的 ezkl 材料目录（与 ``scripts/ezkl_prove.py`` 共用同一份）。
SEMANTIC_ARTIFACTS = REPO / "semantic" / "artifacts"


def build_semantic_block(delegated: list, args) -> dict:
    """为被委托的约束生成证书里的 ``semantic`` 块（P2-9 §9.5）。

    ``delegated`` 是**电路公开值里**的那一串（不是策略里有什么）—— 出证方与电路
    对策略的理解必须一致，以电路为准；不一致时验证方的 ``semantic`` 卡会当场发现。

    为什么**所有**规则共用同一份 ezkl 证明：v1 只有**一个模型**，而证明的内容是
    「``encode(T)`` 经这张图算出的分数」。方向（``le``/``ge``）与阈值只是对**同一个
    分数**的不同比较，不需要第二份证明。多模型时要按模型分开出证，这一点如实
    记在 ``docs/design-semantic-rules.md``。

    ``--no-semantic`` 只负责跳过出证，**不负责让证书变得能过**：跳过后证书里没有
    ``semantic.companions``，而 ``outcome.delegated`` 非空，``verify_cert.py``
    会因此判 FAIL（fail closed）。这是刻意的 —— 一张「语义规则没人判」的证书
    不应当被当成完整证据。
    """
    if not delegated:
        return {}
    if args.no_semantic:
        print(f"⚠ 策略含 {len(delegated)} 条语义规则，但给了 --no-semantic：\n"
              f"  证书不会带陪伴证明，verify_cert.py 将据此判 FAIL（fail closed）")
        return {}

    print(f"策略含 {len(delegated)} 条语义规则 —— 生成 ezkl 陪伴证明（约 1–2 分钟）…")
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "ezkl_prove.py"), "prove",
         "--response", str(args.response)],
        cwd=str(REPO), capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(
            "陪伴证明生成失败 —— 含语义规则的策略**必须**有它，不能降级成"
            "「没有就不带」。\n"
            "（最常见的原因是响应长过图的上限 MAX_CHARS：图是定长的，编不进去就"
            "出不了证。这类响应本来也会撞上策略里的 length_bound，属于不合规响应 ——"
            "不出证是正确结果，而不是故障。）\n" + proc.stdout + proc.stderr)

    proof_path = SEMANTIC_ARTIFACTS / "proof.json"
    companions = [S.companion_entry(d["name"], proof_path, SEMANTIC_ARTIFACTS, d)
                  for d in delegated]

    # 出证方**自己先看一遍分数**。少了这一步，出证方会打印出 `passed: True` 而
    # 对「被委托出去的那条规则其实没过」一无所知 —— 而 `passed` 只覆盖判得了的
    # 那部分（它由电路给出，语义规则不在其中）。所以这里逐条算一遍，并把
    # **合规**的结论提前打在脸上：证书仍然签发（如实记录违规的证书是真证书），
    # 但出证方不该在没看见这一行的情况下把 `passed: True` 读成「合规」。
    score_bp = S.read_score_bp(proof_path, SEMANTIC_ARTIFACTS)
    print(f"  陪伴证明 P(有害) = {score_bp} bp（阈值判定如下）")
    for d in delegated:
        hits = S.threshold_holds(score_bp, int(d["threshold_bp"]), str(d["direction"]))
        mark = "满足" if hits else "**未满足**"
        print(f"  ⚠ 语义规则 {d['name']}: score {score_bp} bp "
              f"{d['direction']} {d['threshold_bp']} bp → {mark}")
        if not hits:
            print(f"    注意：证书里 outcome.passed=True 只覆盖**电路判得了的**约束；"
                  f"这条规则由陪伴证明判定，验证时会写进「合规」行（届时为 FAIL）。")
    return {"companions": companions}


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
    ap.add_argument("--no-semantic", action="store_true",
                    help="P2-9：跳过 ezkl 陪伴证明的生成。含语义规则的策略**不要**用"
                         "它 —— 证书会因缺少陪伴证明而验不过（fail closed）")
    ap.add_argument("--nonce", default="auto",
                    help="挑战值：auto（默认，现场生成 32 字节）| none（不绑定）| <hex>")
    ap.add_argument("--rpc", default=None, help="EVM RPC：把证书摘要同时登记上链")
    ap.add_argument("--contract", default=None, help="已部署的 Anchor 合约地址")
    ap.add_argument("--private-key", default=None, help="上链提交私钥（默认 Anvil #0）")
    ap.add_argument("--key", type=Path, default=None,
                    help="Ed25519 私钥文件（PKCS#8 PEM）。缺省读 $POP_SIGNING_KEY，"
                         "都没有则在 .pop-keys/signing.key 生成一把新的")
    args = ap.parse_args()

    policy = load_policy(args.pack)
    response = args.response.read_text(encoding="utf-8")
    spec = compile_policy(policy)
    out_dir = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # 挑战值：客户端/验证者给出的出题内容（默认现场生成一个一次性值）。
    nonce = resolve_nonce(args.nonce)

    # 构造单个证明请求向量
    vector = {"name": policy.id, "response": response,
              "spec_canonical": spec_canonical_text(spec),
              "nonce": list(nonce)}
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
        # 诚实标注（P0-4）：没有证明工件 ⇒ 只能记「未证明」，
        # 绝不写成 core/compressed（那会声称一档并不存在的证据）。
        proof_mode = cert.PROOF_MODE_UNPROVEN
    else:
        # 真实证明：产出 proof.bin + 元信息（含 vkey_hash）
        cmd = ["--vectors", str(vectors), "--out", str(results), "--proof-out", str(proof)]
        if args.proof_mode != "core":
            cmd += ["--proof-mode", args.proof_mode]
        run_pop(cmd)
        meta = json.loads(Path(f"{proof}.meta.json").read_text())
        vkey_hash = meta["vkey_hash"]
        # 证明模式取自 pop-script 写下的边车元信息（而不是命令行回显）——
        # 证书要如实转述**实际产出的**证明是哪一档；读不到就退回命令行取值。
        proof_mode = meta.get("proof_mode") or args.proof_mode
        proof_sha = sha256_file(proof)
        pv_file = Path(f"{proof}.pv")
        pv_sha = sha256_file(pv_file) if pv_file.exists() else None

    # 组装证书载荷（去掉 name/mode 元信息，得到纯 outcome）
    got = json.loads(results.read_text())[0]
    outcome = {k: v for k, v in got.items() if k not in ("name", "mode")}
    # P2-9：电路报告了「这些约束我没判」（delegated 非空）⇒ 必须补上陪伴证明。
    # 注意这里用的是**电路说的** delegated，不是策略里有什么 —— 出证方与电路对
    # 策略的理解必须一致，以电路为准。
    semantic_block = build_semantic_block(got.get("delegated") or [], args)
    # 挑战块：把 nonce 与**电路承诺的**绑定一并公开。绑定取自 outcome 而不是
    # 现场重算 —— 证书要如实转述证明说了什么。若证明的绑定与现场重算不一致，
    # 验证方的 response_binding 卡会当场发现（那正是它的用途）。
    binding = outcome.get("response_binding")
    if not isinstance(binding, str):
        raise SystemExit("电路输出里没有 response_binding —— pop-script 是旧版本？"
                         "（P0-2 之后它必须出现；缺了就无法把证明绑到送达的响应上）")
    payload = cert.build_payload(policy.id, policy.version, spec, args.mode, outcome,
                                 vkey_hash, proof_sha, public_values_sha256=pv_sha,
                                 challenge=challenge.challenge_block(nonce, binding),
                                 proof_mode=proof_mode,
                                 semantic=semantic_block or None)
    # 签名（P0-3）：Ed25519，私钥留在出证方；公钥单独落盘供第三方验签。
    signer = keys.signer_from_env(args.key)
    env = cert.sign_payload(payload, signer)
    (out_dir / "cert.json").write_text(json.dumps(env, indent=2))
    (out_dir / "payload.json").write_text(json.dumps(payload, indent=2))
    # 公钥不是秘密：把它放在证书旁边，验证方 `verify_cert.py` 缺省就会读它。
    (out_dir / "key.json").write_text(json.dumps(
        {"keyid": signer.keyid, "public_hex": signer.public_hex}, indent=2))

    # 锚定到账本（给了 --rpc/--contract 时同时上链，链上成功后回写本地 meta）
    digest = cert.cert_digest(payload)
    backend = anchor.backend_from_env(args.ledger, rpc_url=args.rpc, contract=args.contract,
                                      private_key=args.private_key)
    entry = backend.anchor(digest, {"policy": policy.id, "mode": args.mode,
                                    "proved": not args.no_prove})
    (out_dir / "anchor.json").write_text(json.dumps(entry, indent=2))

    print(f"policy_hash : {spec['sha256']}")
    print(f"vkey_hash   : {vkey_hash}")
    print(f"proof_mode  : {proof_mode} (hiding: {cert.proof_hiding(proof_mode)})")
    print(f"passed      : {outcome['passed']}")
    print(f"nonce       : {challenge.nonce_hex(nonce) or '(none — 未绑定挑战)'}")
    print(f"resp_binding: {binding}")
    print(f"cert_digest : {digest}")
    print(f"signer      : {signer.keyid}")
    if entry.get("backend") == "rpc":
        print(f"anchor      : backend=rpc status={entry['status']} tx={str(entry.get('tx_hash'))[:18]}… "
              f"contract={entry['contract']} chain_ts={entry.get('chain_ts')}")
        print(f"              local ledger seq={entry.get('ledger', {}).get('seq')} ({args.ledger})")
    else:
        print(f"anchor      : seq={entry['seq']} hash={entry['hash'][:16]}… ledger={args.ledger}")
    print(f"wrote       : {out_dir}/cert.json, payload.json, key.json, results.json" +
          ("" if args.no_prove else f", {proof.name}"))
    print(f"verify with : python3 scripts/verify_cert.py --cert {out_dir}/cert.json \\\n"
          f"                  --pack {args.pack} --ledger {args.ledger} \\\n"
          f"                  --keyring {out_dir}/key.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
