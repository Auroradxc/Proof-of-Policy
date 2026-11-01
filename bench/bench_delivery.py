#!/usr/bin/env python3
"""交付绑定基准（BHV 定理 C / P1-08）：f=0、verifier-only、end-user。

**三个场景 + 重放攻击**，每个场景重复 ``--trials`` 次：

===============  ======================  ================================
场景             谁出 nonce              说明
===============  ======================  ================================
``f=0``          没人（空 nonce）        旧证书可原样重放；接收方无法发现换货
``verifier-only`` V                        V 能核对 T_V，但 U 手上没有 nonce，
                                          换货仍被 U 接受（缺口）
``end-user``     U                         U 用 ``(nonce, T′)`` 重算新域绑定，
                                          换货被拒
===============  ======================  ================================

**判据**（脚本末尾打印 PASS/FAIL）：

1. f=0 的**重放**成功；
2. verifier-only 下 **divergent delivery 仍成功**（这正是缺口）；
3. end-user 下 divergent delivery **失败**，诚实交付成功。

**边界**：end-user nonce 是新域 ``pop-bind-enduser-v1``，作为证书 challenge
块的附加字段；电路公开值仍是 verifier 域（不改电路/vkey）。见
``docs/blockers/C1.md``。

用法::

    python3 bench/bench_delivery.py --out-dir bench/results
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from policydsl.core.compile import compile_policy          # noqa: E402
from policydsl.core.model import Policy, Rule              # noqa: E402
from policydsl.evidence import cert                       # noqa: E402
from policydsl.privacy import challenge, commit            # noqa: E402

POLICY = Policy("delivery-bench", "1.0.0", rules=[
    Rule("keyword_block", "no-secret", {"keywords": ["secret"]}),
])
#: 被证明的 T（合规）与送达的 T′（换货，不合规）。
T_VERIFIED = "all clear, nothing sensitive here"
T_DIVERGENT = "here is the secret you asked for"


def _issue(signer: cert.Ed25519Signer, response: str, nonce: bytes,
           issuer: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """O 对 ``response`` 出证；``issuer`` 决定 challenge 块的角色。"""
    spec = compile_policy(POLICY)
    outcome = {
        "policy_hash": spec["sha256"],
        "passed": True,
        "response_binding": commit.response_binding(nonce, response),
        "violations": [],
    }
    if issuer == challenge.ISSUER_END_USER:
        block = challenge.end_user_challenge_block(
            nonce, outcome["response_binding"], response)
    else:
        block = challenge.challenge_block(nonce, outcome["response_binding"])
    payload = cert.build_payload(POLICY.id, POLICY.version, spec, "public",
                                 outcome, vkey_hash="unproven",
                                 ts="2026-01-01T00:00:00Z", challenge=block)
    return payload, cert.sign_payload(payload, signer)


def _envelope_ok(env: Dict[str, Any], signer: cert.Ed25519Signer) -> bool:
    ok, payload = cert.verify_envelope(env, signer.public_key)
    return bool(ok and payload is not None)


def _run_scenario(signer, issuer: str, nonce_mode: str, trials: int) -> Dict[str, Any]:
    """跑一个场景；``nonce_mode`` = ``empty`` | ``fresh``。"""
    honest_ok = divergent_ok = replay_ok = 0
    for _ in range(trials):
        nonce = b"" if nonce_mode == "empty" else challenge.new_nonce()
        payload, env = _issue(signer, T_VERIFIED, nonce, issuer)
        signed = _envelope_ok(env, signer)

        # 诚实交付：接收方拿到 T_VERIFIED。
        if issuer == challenge.ISSUER_END_USER:
            honest = signed and challenge.check_challenge(
                payload, T_VERIFIED, issuer="end-user")
            divergent = signed and challenge.check_challenge(
                payload, T_DIVERGENT, issuer="end-user")
        else:
            # verifier-only / f=0：V 能核对；U 没有 nonce，也没有 end-user
            # 绑定，只能验签 —— 换货在 U 这一侧无法被发现。
            honest = signed and challenge.check_challenge(
                payload, T_VERIFIED, issuer="verifier")
            divergent = signed and (
                challenge.END_USER_BINDING_FIELD not in payload["challenge"])
        honest_ok += bool(honest)
        divergent_ok += bool(divergent)

        # 重放：把同一张证书/同一条 T 再送一次。
        if nonce_mode == "empty":
            replay = signed and challenge.check_challenge(
                payload, T_VERIFIED, issuer=issuer)
        else:
            # 新会话用新 nonce：把旧证书的 challenge 块换成新 nonce 再核对 ——
            # 旧绑定（verifier 或 end-user 域）都绑在旧 nonce 上，必然对不上。
            fresh = challenge.new_nonce()
            fresh_block = {**payload["challenge"], "nonce": fresh.hex()}
            replay = signed and challenge.check_challenge(
                {"challenge": fresh_block}, T_VERIFIED, issuer=issuer)
        replay_ok += bool(replay)

    return {
        "issuer": issuer,
        "nonce": nonce_mode,
        "f_bits": 0 if nonce_mode == "empty" else len(challenge.new_nonce()) * 8,
        "trials": trials,
        "honest_accept_rate": round(honest_ok / trials, 4),
        "divergent_accept_rate": round(divergent_ok / trials, 4),
        "replay_accept_rate": round(replay_ok / trials, 4),
    }


def run(out_dir: Path, trials: int) -> Dict[str, Any]:
    signer = cert.Ed25519Signer.generate()
    f0 = _run_scenario(signer, challenge.ISSUER_VERIFIER, "empty", trials)
    verifier = _run_scenario(signer, challenge.ISSUER_VERIFIER, "fresh", trials)
    end_user = _run_scenario(signer, challenge.ISSUER_END_USER, "fresh", trials)

    criteria = {
        "f0_replay_succeeds": f0["replay_accept_rate"] == 1.0,
        "verifier_only_divergent_succeeds": verifier["divergent_accept_rate"] == 1.0,
        "end_user_divergent_fails": end_user["divergent_accept_rate"] == 0.0,
        "end_user_honest_succeeds": end_user["honest_accept_rate"] == 1.0,
    }
    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trials": trials,
        "scenarios": [
            {"name": "f=0 (empty nonce)", **f0},
            {"name": "verifier-only (fresh V nonce)", **verifier},
            {"name": "end-user (fresh U nonce)", **end_user},
        ],
        "criteria": criteria,
        "all_criteria_met": all(criteria.values()),
        "notes": [
            "Replay is modeled as re-submitting the same certificate + same T. "
            "With a fresh nonce the old certificate no longer matches; f=0 has "
            "no freshness at all, so replay is accepted.",
            "verifier-only protects V's view of T, not U's delivery: U has no "
            "nonce and the certificate carries no end_user_binding, so a "
            "divergent delivery is accepted by U.",
            "end-user uses the separate domain pop-bind-enduser-v1 and rejects "
            "divergent delivery. The circuit still commits the verifier-domain "
            "response_binding; end_user_binding is a certificate-layer add-on.",
        ],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "delivery_binding.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out_dir / "delivery_binding.md").write_text(render_md(result), encoding="utf-8")
    return result


def render_md(r: Dict[str, Any]) -> str:
    rows = []
    for s in r["scenarios"]:
        rows.append(
            f"| {s['name']} | {s['issuer']} | {s['f_bits']} | "
            f"{s['honest_accept_rate']:.2f} | {s['divergent_accept_rate']:.2f} | "
            f"{s['replay_accept_rate']:.2f} |")
    table = "\n".join(rows)
    crit = "\n".join(
        f"- {'✅' if ok else '❌'} `{name}`" for name, ok in r["criteria"].items())
    return f"""# 交付绑定基准（f=0 / verifier-only / end-user）

**生成时间**：`{r['generated_at']}` ｜ **每场景 trial 数**：{r['trials']}
**代码**：`bench/bench_delivery.py`（标准库 + Ed25519，无证明器）

## 结果

| 场景 | issuer | f (bits) | 诚实交付接受率 | divergent 接受率 | 重放接受率 |
|---|---|---:|---:|---:|---:|
{table}

**判据**

{crit}

**总判定：{'PASS' if r['all_criteria_met'] else 'FAIL'}**

## 怎么读

- **f=0**：nonce 为空，重放的是同一张证书 + 同一条 T，所以重放接受率为 1；
  这不是实现缺陷，是「没有新鲜性」的定义性后果。
- **verifier-only**：V 的 nonce 让 V 能核对 T_V；但 U 手上没有 nonce，证书里
  也没有 end-user 绑定，U 只能验签 —— **divergent delivery 仍被接受**。
  这正是 §4.6.3 验证者能力表里「终端用户只能绑到自己收到的那串」的缺口。
- **end-user**：U 出 nonce，证书 challenge 块带 `issuer=end-user` 与
  `end_user_binding`（新域 `pop-bind-enduser-v1`）。U 用 `(nonce, T′)` 重算：
  诚实交付通过，换货被拒。
- **重放**：f>0 时旧证书绑的是旧 nonce；新会话换 nonce 后旧证书对不上。
  若允许复用 nonce 且不记录已用 nonce，重放仍会通过 —— 这就是
  `NonceStore` 存在的理由。

## 边界

- 只测**证书 challenge 块**的交付绑定；电路公开值仍是 verifier 域
  `pop-bind-v1`（不改电路 / vkey）。见 `docs/blockers/C1.md`。
- 判据是**场景级**的接受/拒绝率（离散），不是统计优势估计；trial 数只用于
  排除偶发实现错误。

## 复现

```bash
python3 bench/bench_delivery.py --out-dir bench/results
```
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", default=str(REPO / "bench" / "results"))
    ap.add_argument("--trials", type=int, default=200)
    args = ap.parse_args()
    result = run(Path(args.out_dir), args.trials)
    for s in result["scenarios"]:
        print(f"{s['name']}: honest={s['honest_accept_rate']:.2f} "
              f"divergent={s['divergent_accept_rate']:.2f} "
              f"replay={s['replay_accept_rate']:.2f}")
    print(f"all criteria met: {result['all_criteria_met']}")
    print(f"wrote {Path(args.out_dir) / 'delivery_binding.md'}")
    return 0 if result["all_criteria_met"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
