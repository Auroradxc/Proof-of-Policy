#!/usr/bin/env python3
"""会话层（P2-10）出证 demo：一个 run 的流式证书 → 一次聚合证明。

给定一个端到端会话包（`session.json`，与 ``scripts/verify_session.py`` 同格式），
把其中**同一个 run 的流式证书**按序取出，在 SP1 内证明三条义务成立：

  ① 所有证书的 `policy_hash` 全同（同一个策略约束了整条轨迹）；
  ② 流式链无缝拼接无缺口（第 i 张证书的 `chain.prev` == 第 i-1 张的叶子摘要，
     且 `chain.index` 连续从 0 起）；
  ③ 覆盖完整轨迹（链尾证书带 `trace_seal`，其 `keyid` 全域唯一）。

用 Merkle 根把 N 张证书摘要聚合进一次证明；证明公开值为
``(policy_hash, cert_count, merkle_root, session_binding, trace_root,
sealed_count, seal_keyid)``。验证方拿**交付的证书集**重算 Merkle 根与三条义务，
与证明公开值逐字段比对 —— 混入异策略证书 / 挖掉一张 / 换掉链尾都会失败。

用法：
  python3 scripts/prove_session.py --session scripts/examples/out/e2e/session.json
  # 只对某一个 run 出证，并钉住 nonce（重放新鲜度）：
  python3 scripts/prove_session.py --session ... --run 0 --nonce-hex 0011223344556677
  # 只做 Python↔Rust 宿主校验对拍（秒级，不出证）：
  python3 scripts/prove_session.py --session ... --no-prove

**边界（如实说明，不要读过头）**：
  - 电路**不验**网关对 `trace_seal` 的 Ed25519 签名（zkVM 里没有网关公钥）。
    「这条链网关真的签过」由 ``policydsl.trace.verify_seal`` 链下完成 ——
    本脚本给了 ``--keyring`` 才会走到那一步，否则输出里会注明**未验签名**。
  - 聚合只覆盖**一个 run**，且只覆盖**链上（流式）证书**。一个 run 的权威
    `on_llm_end` 证书没有 `streaming.chain`，是按内容被判出 run 之外的（见
    ``policydsl.session.runs_of``），不在本证明的覆盖范围内。

以退出码 0 结束当且仅当：每条选中的 run 都出了证、且验证方用交付证书集核对通过。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import cert as C  # noqa: E402
from policydsl import session as S  # noqa: E402


def _payload(envelope: Dict[str, Any]) -> Dict[str, Any]:
    """取信封的证书载荷（与 ``scripts/verify_session.py`` 同口径：用公开的
    ``cert.envelope_payload``，不走 session 模块内部的同名封装）。"""
    return C.envelope_payload(envelope)


def load_bundle(path: Path) -> "list[dict]":
    """从 `session.json` 取出全部证书信封（`certificates[*].envelope`）。

    **不做 kind 过滤**：哪张证书属于哪个 run、哪张不在链上，全交给
    :func:`policydsl.session.runs_of` 按内容判定 —— 那份判定是出证方与验证方
    共用的同一份，在这里再抄一遍就等于把口径分叉了。
    """
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    certs = bundle.get("certificates")
    if not isinstance(certs, list):
        raise S.SessionError(f"{path} 里没有 certificates 列表")
    out = []
    for i, e in enumerate(certs):
        env = e.get("envelope") if isinstance(e, dict) else None
        if not isinstance(env, dict):
            raise S.SessionError(f"certificates[{i}] 缺 envelope")
        out.append(env)
    return out


def describe(run: "list[dict]") -> str:
    """一行描述一个 run（便于多 run 时选错前的自查）。"""
    idx = []
    partial = []
    for e in run:
        chain = (_payload(e).get("streaming") or {}).get("chain") or {}
        idx.append(chain.get("index"))
        partial.append(bool((_payload(e).get("streaming") or {}).get("partial")))
    return (f"{len(run)} 张证书  index={idx}  "
            f"partial={partial}  链尾 passed="
            f"{(_payload(run[-1]).get('outcome') or {}).get('passed')}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", type=Path, required=True,
                    help="端到端会话包 session.json")
    ap.add_argument("--run", type=int, default=None,
                    help="只证明第 N 个 run（默认全部）")
    ap.add_argument("--nonce-hex", default=None,
                    help="响应绑定的 nonce（十六进制）；缺省随机取 16 字节并打印")
    ap.add_argument("--keyring", default=None,
                    help="网关公钥（key.json / *.pub.hex / hex 文本）；给出则额外核签名")
    ap.add_argument("--proof-out", type=Path, default=None,
                    help="把证明与边车写到该路径（供第三方独立验证）")
    ap.add_argument("--proof-mode", default="core",
                    help="core（默认）/ compressed / groth16 / plonk")
    ap.add_argument("--out-dir", type=Path,
                    default=REPO / "scripts" / "examples" / "out" / "session")
    ap.add_argument("--no-prove", action="store_true",
                    help="只做 Python↔Rust 宿主校验对拍，不出 SP1 证明")
    args = ap.parse_args()

    if args.nonce_hex:
        nonce = bytes.fromhex(args.nonce_hex)
    else:
        nonce = os.urandom(16)
    print(f"nonce (session_binding 的新鲜度来源): {nonce.hex()}")

    envelopes = load_bundle(args.session)
    runs = S.runs_of(envelopes)
    off_chain = len(envelopes) - sum(len(r) for r in runs)
    print(f"证书 {len(envelopes)} 张 → {len(runs)} 个 run"
          + (f"（另有 {off_chain} 张不在链上，不计入）" if off_chain else ""))
    for i, run in enumerate(runs):
        print(f"  run[{i}]: {describe(run)}")
    if not runs:
        print("\nRESULT: FAIL  没有任何可聚合的 run（证书里没有流式链）")
        return 1

    picked = list(range(len(runs))) if args.run is None else [args.run]
    if any(not (0 <= i < len(runs)) for i in picked):
        print(f"\nRESULT: FAIL  --run 越界（共 {len(runs)} 个 run）")
        return 2

    args.out_dir.mkdir(parents=True, exist_ok=True)
    ok = True
    for i in picked:
        run = runs[i]
        print(f"\n--- run[{i}]：{len(run)} 张证书 ---")

        # 1) Python 侧的现场重算（也是验证方要跑的同一份逻辑）
        want = S.run_session([S.cert_text(e) for e in run], nonce)
        print(f"  merkle_root    {want['merkle_root']}")
        print(f"  policy_hash    {want['policy_hash']}")
        print(f"  trace_root     {want['trace_root']}  "
              f"sealed_count={want['sealed_count']}  seal_keyid={want['seal_keyid']}")

        # 2) Rust 宿主校验对拍（两条独立实现的同一聚合，秒级）
        try:
            got = S.pop_check(run, nonce)
        except S.SessionError as exc:
            print(f"  [FAIL] pop-check  {exc}")
            ok = False
            continue
        # 六个公开字段**逐一**比对（含 session_binding）：两端算的必须是同一个聚合。
        # 少比一个字段，对拍就留下了恰好那个字段的盲区。
        diff = {k: (want[k], got.get(k)) for k in want if want[k] != got.get(k)}
        if diff:
            print(f"  [FAIL] parity       Python 与 Rust 的聚合不一致：{diff}")
            ok = False
            continue
        print(f"  [ ok ] parity       Python == Rust（{len(want)} 个公开字段逐一相等）")

        (args.out_dir / f"run{i}.outcome.json").write_text(
            json.dumps(want, indent=2, ensure_ascii=False), encoding="utf-8")

        # 3) 真实证明 + 独立验证
        if args.no_prove:
            print("  (--no-prove: 跳过 SP1 证明；**不要把上面的重算当成已出证**)")
            continue
        print("  --- 出证中（SP1 core，约数分钟）---")
        try:
            proof_out = args.proof_out or (args.out_dir / f"run{i}.proof")
            proof = S.prove_session(run, nonce=nonce, proof_out=proof_out,
                                    proof_mode=args.proof_mode)
        except S.SessionError as exc:
            print(f"  [FAIL] prove       {exc}")
            ok = False
            continue
        verified, detail, satisfied = S.verify_session_proof(
            proof["outcome"], envelopes=run, nonce=nonce, proof=proof_out,
            keyring=args.keyring)
        print(f"  [{' ok ' if verified else 'FAIL'}] verify      {detail}")
        if not verified:
            ok = False
            continue
        print(f"  {'合规' if satisfied else '**不合规**'}：这张聚合证明本身是真的，"
              f"它覆盖的轨迹{'' if satisfied else '不'}满足策略")
        print(f"  证明工件：{proof_out}")

    print("\nRESULT: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (S.SessionError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
