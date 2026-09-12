#!/usr/bin/env python3
"""组合证明驱动（P1-6）—— 分别出证 → 联合验证 → ``composite.json``。

```
Compose = (推理完整性 ∧ 策略合规)
```

本脚本把两半各出一次 SP1 证明（``--job policy`` 与 ``--job infer``，**两个不同的
ELF ⇒ 两个不同的 vkey**），再交给 :mod:`policydsl.compose` 合成一张组合证书并
当场独立验证一遍。

用法：

```bash
SP1_PROVER=cpu python3 scripts/compose_proof.py \\
  --pack policy_packs/eu_ai_act_v1.json \\
  --response scripts/examples/eu_agent_reply.txt \\
  [--out-dir DIR] [--no-prove] [--reuse-proofs] [--proof-mode core|compressed|groth16|plonk]
```

``--reuse-proofs`` 沿用 ``out-dir`` 里已有的两份证明，只重跑「合成 + 独立验证」
（出证各约 2 分钟，改 ``policydsl/compose.py`` 后不必重出）。它**不重新校验**证明
是否对应本次的 ``--response`` —— 但尾部验证会现场重算 ``response_binding``，
对不上即 FAIL，不会静默产出一张错证书。

**成本**（本机 12 GB 实测，见 ``bench/results/compose.md``）：两次 ``setup`` +
两次 ``prove``，各约 1.5–2 分钟、峰值 ~8.7 GiB。两半**必须分进程**跑 ——
一个进程内连续出两份证明会在第二份的 setup 阶段被 OOM killer 终止。

``--no-prove`` 只跑宿主校验（秒级）：它验证**判定逻辑**两端一致，但**不产组合
证书** —— 组合证书的输入是两份**证明**，没有证明就没有可组合的东西。这一点
如实报告，不静默降级成一张「看起来验过了」的证书。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import infer as I                      # noqa: E402
from policydsl import compose as C                    # noqa: E402
from policydsl import challenge                       # noqa: E402
from policydsl.compile import compile_policy          # noqa: E402
from policydsl.model import Policy, Rule, PolicyError # noqa: E402
from policydsl.serialize import spec_canonical_text   # noqa: E402

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"
POP_VERIFY = REPO / "circuits" / "target" / "release" / "pop-verify"


def load_policy(path: Path) -> Policy:
    """从 JSON 文件加载策略包。"""
    d = json.loads(path.read_text(encoding="utf-8"))
    rules = [Rule(kind=r["kind"], name=r.get("name", f"r{i}"), params=r.get("params", {}))
             for i, r in enumerate(d["rules"])]
    return Policy(d["id"], d.get("version", "0.1.0"), rules=rules)


def run_pop(args: list[str]) -> None:
    """调用 pop-script 驱动（强制 SP1_PROVER=cpu）。"""
    subprocess.run([str(POP_SCRIPT), *args], env=dict(os.environ, SP1_PROVER="cpu"),
                   check=True, cwd=str(REPO))


def write_vectors(path: Path, vectors: list[dict]) -> None:
    path.write_text(json.dumps({"vectors": vectors}, ensure_ascii=False, indent=2),
                    encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="组合证明（P1-6）")
    ap.add_argument("--pack", type=Path, required=True, help="策略包 JSON")
    ap.add_argument("--response", type=Path, required=True, help="被证明的响应 T")
    ap.add_argument("--out-dir", type=Path, default=REPO / "scripts" / "examples" / "out" / "compose")
    ap.add_argument("--nonce", default="auto", help="auto | none | <hex>（两条证明共用同一个）")
    ap.add_argument("--proof-mode", default="core",
                    choices=["core", "compressed", "groth16", "plonk"])
    ap.add_argument("--no-prove", action="store_true", help="只跑宿主校验（不产证明/组合证书）")
    ap.add_argument("--reuse-proofs", action="store_true",
                    help="沿用 out-dir 里已有的两份证明（出证各约 2 分钟，重跑合成/验证时不必再出）")
    args = ap.parse_args()

    if not POP_SCRIPT.exists():
        print(f"error: driver not built: {POP_SCRIPT}\n"
              "  cd circuits && cargo build --release -p pop-script", file=sys.stderr)
        return 2

    policy = load_policy(args.pack)
    response = args.response.read_text(encoding="utf-8")

    spec = compile_policy(policy)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    nonce_file = args.out_dir / "nonce.hex"

    # 两条证明**共用同一个挑战值**：组合义务要求它们说的是同一条 T，
    # 而 response_binding 的口径正是 (nonce, T)。
    #
    # --reuse-proofs 时**必须**沿用出证当时那个 nonce —— 绑定里含 nonce，
    # 重新随机一个会让「由送达 T′ 现场重算」与证书里的绑定必然对不上（FAIL）。
    if args.reuse_proofs and args.nonce == "auto":
        if not nonce_file.exists():
            print(f"error: --reuse-proofs 但找不到 {nonce_file} —— 无法还原出证时的挑战值。\n"
                  "  请显式 --nonce <hex>，或去掉 --reuse-proofs 重新出证。", file=sys.stderr)
            return 2
        nonce = challenge.parse_nonce(nonce_file.read_text(encoding="utf-8").strip())
    else:
        nonce = (challenge.new_nonce() if args.nonce == "auto"
                 else b"" if args.nonce == "none"
                 else challenge.parse_nonce(args.nonce))
    if not args.no_prove:
        # 落盘：让「重跑合成/验证」不必重新出证也能拿到同一个挑战值
        nonce_file.write_text(nonce.hex(), encoding="utf-8")

    pol_vectors = args.out_dir / "policy_vectors.json"
    inf_vectors = args.out_dir / "infer_vectors.json"
    write_vectors(pol_vectors, [{
        "name": policy.id,
        "response": response,
        "spec_canonical": spec_canonical_text(spec),
        "nonce": list(nonce),
    }])
    write_vectors(inf_vectors, [{
        "name": "inference",
        "response": response,
        "nonce": list(nonce),
    }])

    if args.no_prove:
        # 只做宿主校验：两端的**判定逻辑**对齐，但不产证明。
        print("--- host check: policy half ---")
        run_pop(["--check", "--job", "policy", "--vectors", str(pol_vectors),
                 "--out", str(args.out_dir / "policy_host.json")])
        print("--- host check: inference half ---")
        run_pop(["--check", "--job", "infer", "--vectors", str(inf_vectors),
                 "--out", str(args.out_dir / "infer_host.json")])
        pol_host = json.loads((args.out_dir / "policy_host.json").read_text())[0]
        inf_host = json.loads((args.out_dir / "infer_host.json").read_text())[0]

        # 与 Python 参考实现对照 —— 换实现就换结论，说明有一侧错了
        ref_inf = I.run(response, nonce)
        agree = all(inf_host.get(k) == ref_inf[k]
                    for k in ("model_hash", "response_binding", "input_binding", "output"))
        print(f"  policy   passed={pol_host.get('passed')} "
              f"violations={[v['rule'] for v in pol_host.get('violations', [])]}")
        print(f"  inference model={inf_host.get('model_hash', '')[:12]}… "
              f"output={inf_host.get('output')}")
        print(f"  Rust ↔ Python 参考实现逐位一致: {agree}")
        print("\n(--no-prove: 未产出组合证书 —— 组合证书的输入是两份**证明**，"
              "宿主校验不能替代)")
        print("\nRESULT: " + ("PASS" if agree else "FAIL"))
        return 0 if agree else 1

    # ---- 出证：两次独立进程（分进程是硬约束，见模块 docstring） ----
    pol_proof = args.out_dir / "policy.proof"
    inf_proof = args.out_dir / "inference.proof"

    if args.reuse_proofs:
        missing = [p for p in (pol_proof, inf_proof) if not p.exists()]
        if missing:
            print(f"error: --reuse-proofs 但缺少证明文件：{[str(m) for m in missing]}",
                  file=sys.stderr)
            return 2
        print(f"(--- 沿用已有证明：{pol_proof.name} / {inf_proof.name} ---)")
    else:
        print(f"--- proving POLICY half (SP1, ~2 min, job=policy) ---")
        run_pop(["--job", "policy", "--vectors", str(pol_vectors),
                 "--out", str(args.out_dir / "policy_results.json"),
                 "--proof-out", str(pol_proof), "--proof-mode", args.proof_mode])
        print(f"--- proving INFERENCE half (SP1, ~2 min, job=infer) ---")
        run_pop(["--job", "infer", "--vectors", str(inf_vectors),
                 "--out", str(args.out_dir / "infer_results.json"),
                 "--proof-out", str(inf_proof), "--proof-mode", args.proof_mode])

    # ---- 合成 ----
    pol_part = C.part_from_proof(pol_proof, C.KIND_POLICY, policy.id,
                                 relative_to=args.out_dir)
    inf_part = C.part_from_proof(inf_proof, C.KIND_INFERENCE, "proxy-inference",
                                 relative_to=args.out_dir)
    cert = C.build_composite(pol_part, inf_part, nonce)
    out_json = C.write_composite(cert, args.out_dir / "composite.json")
    print(f"\n组合证书 → {out_json}")
    print(f"  policy vkey    : {C.V.short_hash(pol_part.vkey_hash)}")
    print(f"  inference vkey : {C.V.short_hash(inf_part.vkey_hash)}  "
          f"（与上一个**不同** —— 键分离）")
    print(f"  response_binding: {C.V.short_hash(cert.response_binding)}")

    # ---- 独立验证（验证方视角：只给证书、工件目录、送达的 T） ----
    print("\n--- 独立验证（第三方路径） ---")
    reloaded = C.read_composite(out_json)
    ok, detail, satisfied = C.verify_composite(
        reloaded, response=response, base=args.out_dir, policy_pack=args.pack,
        expected_vkeys={C.KIND_POLICY: pol_part.vkey_hash,
                        C.KIND_INFERENCE: inf_part.vkey_hash},
        pop_verify=POP_VERIFY, pop_script=POP_SCRIPT)
    print(f"  {detail}")
    print("\nRESULT: " + ("PASS" if ok else "FAIL"))
    print("组合义务(Compose): " + ("PASS" if satisfied else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (PolicyError, NotImplementedError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
