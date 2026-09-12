#!/usr/bin/env python3
"""多证明者（P2-11）出证 demo：三个角色各证一段，缺谁都不成立。

给定一个策略包与一条真实 agent 响应，把策略按**规则类**切成三段
（模型方 / 工具网关 / 部署方），各角色用自己的键对**自己那一段**出证并签名，
合成一张 ``multiparty.json``，然后独立验证它 —— 顺带把计划 §P2-11 的两条验收
判据在**真工件**上跑一遍：

  ① 去掉任一角色的签名 → 必须被拒；
  ② 单角色的策略切片被换（拿另一段冒充，用该角色自己的键重签）→ 必须被拒。

用法：
  python3 scripts/prove_multiparty.py \
      --pack policy_packs/multiparty_demo_v1.json \
      --response scripts/examples/eu_agent_reply.txt
  # 只做「切完之后两端算的还对不对」的对拍（秒级；**不产生证书**）：
  python3 scripts/prove_multiparty.py --pack ... --response ... --no-prove

**边界（如实说明，不要读过头）**：
  - 三个角色各持一把键只是**责任划分**：三段共享同一个 ``pop-program``（同一个
    vkey）。「不同角色用不同电路」得各出 vkey，本仓库没有做，也不主张做到了。
  - 「聚合证明」是 N 份切片证明 + 一份把它们拴在一起的证书，**不是**递归聚合
    （验证成本 O(N)）。见 ``policydsl/multiparty.py`` 模块头。
  - 语义规则（若策略里有）归部署方那段，而那段**不判定**它、只把它记进
    ``delegated``：合规结论要另外合取 ezkl 陪伴证明（L7）。此脚本会如实打印。

以退出码 0 结束当且仅当：三段切片都出了证/签了名、验证通过、且两条验收判据都
按预期被拒。
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import keys  # noqa: E402
from policydsl import multiparty as M  # noqa: E402


def load_policy(path: Path):
    """从 JSON 载入策略包（与 ``prove_policy.load_policy`` 同口径）。"""
    from policydsl.model import Policy, Rule
    d = json.loads(path.read_text(encoding="utf-8"))
    return Policy(id=d["id"], version=d.get("version", "0.1.0"),
                  description=d.get("description", ""),
                  rules=[Rule(kind=r["kind"], name=r.get("name", f"rule-{i}"),
                              params=r.get("params", {}))
                         for i, r in enumerate(d.get("rules", []))],
                  semantic=d.get("semantic", "and"))


def role_signers(args) -> "tuple[dict, str]":
    """三个角色的键：``--role-keys DIR`` 给了就从那里 load_or_create，否则一次性。

    返回 ``(signers, 说明)``。演示用一次性键是**如实标注**的：它们不进任何证据
    链，重跑一次就没法再验旧证书 —— 真部署用 ``--role-keys``。
    """
    if args.role_keys:
        d = Path(args.role_keys)
        d.mkdir(parents=True, exist_ok=True)
        return ({r: keys.load_or_create(d / f"{r}.key") for r in M.ROLES},
                f"私钥来自 {d}/*.key（0600，未入库）")
    return ({r: keys.ephemeral_signer() for r in M.ROLES},
            "私钥是**一次性**的（仅本次运行有效，--role-keys 可改用落盘键）")


def write_keyring(path: Path, signers) -> Path:
    """把三个角色的公钥写成验证方可读的 keyring（**只有公钥**）。"""
    recs = [dict(keys.public_record(s.public_key), role=role)
            for role, s in signers.items()]
    path.write_text(json.dumps({"signers": recs}, ensure_ascii=False, indent=2),
                    encoding="utf-8")
    return path


def check(cert, *, policy, response, keyring, base, verify_proofs: bool, expected_vkey=None):
    return M.verify_multiparty(cert, response=response, base=base, keyring=keyring,
                               policy=policy, verify_proofs=verify_proofs,
                               expected_vkey=expected_vkey)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", type=Path, required=True, help="策略包 JSON")
    ap.add_argument("--response", type=Path, required=True, help="agent 响应文本")
    ap.add_argument("--out-dir", type=Path,
                    default=REPO / "scripts" / "examples" / "out" / "multiparty")
    ap.add_argument("--role-keys", default=None,
                    help="三个角色的私钥目录（{role}.key）；缺省用一次性键")
    ap.add_argument("--nonce-hex", default=None,
                    help="响应绑定的 nonce（十六进制）；缺省随机取 16 字节并打印")
    ap.add_argument("--receipts", type=Path, default=None,
                    help="工具回执链 JSON（P1-5）；缺省=空链（一次工具都没调用）")
    ap.add_argument("--proof-mode", default="core",
                    help="core（默认）/ compressed / groth16 / plonk")
    ap.add_argument("--no-prove", action="store_true",
                    help="不出 SP1 证明：只跑各切片的宿主校验对拍（**不产生证书**）")
    args = ap.parse_args()

    nonce = bytes.fromhex(args.nonce_hex) if args.nonce_hex else os.urandom(16)
    print(f"nonce (response_binding 的新鲜度来源): {nonce.hex()}")

    policy = load_policy(args.pack)
    response = args.response.read_text(encoding="utf-8")
    plan = M.plan_of(policy)
    print(f"\n策略 {policy.id}@{policy.version} → 按规则类切成三段：")
    for role in M.ROLES:
        rules = plan[role]["rules"]
        tag = "（空切片：仍要签名，但没有可证的东西）" if not rules else ""
        print(f"  {M.label(role):16s} {rules} {tag}")
    print(f"  plan_digest      {M.plan_digest(plan)}")

    receipts = None
    if args.receipts:
        receipts = json.loads(args.receipts.read_text(encoding="utf-8"))
        print(f"  回执链           {args.receipts}（**全量**发给每个切片）")

    signers, how = role_signers(args)
    print(f"\n角色键：{how}")
    for role, s in signers.items():
        print(f"  {M.label(role):16s} {s.keyid}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    keyring_path = write_keyring(args.out_dir / "multiparty.keyring.json", signers)
    keyring = keys.load_keyring(keyring_path)

    # ---- 出证 ----
    if args.no_prove:
        # 没有证明就组不出证书（build 会 fail closed）—— 于是这一档只做
        # 「切完之后两端算的还对不对」的对拍，并**明说**没有产生证书。
        print("\n--- 各切片的宿主校验对拍（--no-prove：**不产生证书**）---")
        sub = M.shard(policy)
        for role in M.ROLES:
            if not plan[role]["rules"]:
                print(f"  {M.label(role):16s} 空切片，无判定可跑")
                continue
            got = M.check_slice(sub[role], response, receipts=receipts, nonce=nonce)
            print(f"  {M.label(role):16s} passed={got.get('passed')} "
                  f"violations={len(got.get('violations') or [])} "
                  f"policy_hash={str(got.get('policy_hash'))[:12]}… "
                  f"trace_root={got.get('trace_root')}")
        print("\n  **注意**：以上是 Python 侧参考评估与 Rust 宿主校验的对拍结果，"
              "不是证明。\n  要出可独立验证的多证明者证书，去掉 --no-prove"
              "（每段约数分钟、峰值 ~10 GB）。")
        print("\nRESULT: PASS")
        return 0

    print("\n--- 各角色对自己那一段出证 ---（SP1 core，每段约数分钟）")
    cert = M.build_multiparty(
        policy, response, signers=signers, receipts=receipts, nonce=nonce,
        prove=True, proof_dir=args.out_dir, relative_to=args.out_dir,
        proof_mode=args.proof_mode)
    out = M.write_multiparty(cert, args.out_dir / "multiparty.json")
    back = M.read_multiparty(out)

    ok = True
    print("\n--- 验证（独立读回 multiparty.json）---")
    good, detail, satisfied = check(back, policy=policy, response=response,
                                    keyring=keyring, base=args.out_dir,
                                    verify_proofs=True)
    print(f"  [{' ok ' if good else 'FAIL'}] verify   {detail}")
    if not good:
        print("\nRESULT: FAIL")
        return 1
    print(f"  {'合规' if satisfied else '**不构成合规**'}：这份多证明者证书本身是真的，"
          f"整条策略{'' if satisfied else '**未**被满足（或仍有委托规则）'}")
    print(f"  证书工件：{out}\n  公钥环  ：{keyring_path}")

    # ---- 验收判据 ①：缺任一角色签名 → 拒绝 ----
    print("\n--- 验收 ①：去掉一个角色的签名 ---")
    for role in M.ROLES:
        forged = copy.deepcopy(back)
        next(p for p in forged.parts if p.role == role).envelope = {}
        got, why, _ = check(forged, policy=policy, response=response, keyring=keyring,
                            base=args.out_dir, verify_proofs=False)
        print(f"  [{' ok ' if not got else 'FAIL'}] 去掉 {M.label(role):16s} "
              f"{'' if not got else '**竟然通过了**'}{why if not got else ''}")
        ok &= not got

    # ---- 验收判据 ②：单角色切片被换 → 拒绝 ----
    # 攻击者视角：他有**自己那把键**，但没有别的角色的键。
    print("\n--- 验收 ②：单角色切片被换（用该角色自己的键重签）---")
    forged = copy.deepcopy(back)
    victim, donor = "model", "gateway"
    donor_part = next(p for p in back.parts if p.role == donor)
    swap = copy.deepcopy(next(p for p in forged.parts if p.role == victim))
    swap.rules = list(donor_part.rules)
    swap.slice_sha256 = donor_part.slice_sha256
    swap.proof_file, swap.proof_sha256 = donor_part.proof_file, donor_part.proof_sha256
    swap.outcome = dict(donor_part.outcome)
    M.sign_part(swap, signers[victim])
    forged.parts = [swap if p.role == victim else p for p in forged.parts]
    got, why, _ = check(forged, policy=policy, response=response, keyring=keyring,
                        base=args.out_dir, verify_proofs=False)
    print(f"  [{' ok ' if not got else 'FAIL'}] {M.label(victim)} 那段被换成 "
          f"{M.label(donor)} 那段：{'被拒 ✓' if not got else '**竟然通过了**'}")
    if not got:
        print(f"       理由：{why}")
    ok &= not got

    print("\nRESULT: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (M.MultipartyError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
