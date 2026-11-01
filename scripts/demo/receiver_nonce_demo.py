#!/usr/bin/env python3
"""接收方 nonce 演示（P1-07）：verifier nonce vs end-user nonce。

三个场景，全部离线、无需证明器：

1. **f=0 重放**：nonce 为空（``b""``）。同一张证书 + 同一条 T 在下一轮被原样
   重放，``check_challenge`` 仍然返回 True —— 空 nonce 不提供任何新鲜性。
2. **verifier-only 的 divergent delivery**：V 出 nonce，O 证明的是 T_V，却给
   U 送达 T_U ≠ T_V。V 的核对通过；U 手上没有 V 的 nonce、证书里也没有
   end-user 绑定 —— U **无法发现**换货，交付被接受（这就是缺口）。
3. **end-user nonce 的 divergent delivery**：U 出 nonce，O 用 T_V 生成
   ``end_user_binding``；U 收到 T_U 后重算，绑定对不上 → 拒绝。

同时演示诚实交付在 end-user 场景下通过。

用法::

    python3 scripts/demo/receiver_nonce_demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from policydsl.core.compile import compile_policy          # noqa: E402
from policydsl.core.model import Policy, Rule              # noqa: E402
from policydsl.evidence import cert                       # noqa: E402
from policydsl.privacy import challenge, commit            # noqa: E402

POLICY = Policy("receiver-demo", "1.0.0", rules=[
    Rule("keyword_block", "no-secret", {"keywords": ["secret"]}),
])
GOOD_T = "all clear, nothing sensitive here"
BAD_T = "here is the secret you asked for"


def _outcome(response: str, nonce: bytes) -> dict:
    """O 对 T 的判定 + verifier 域绑定（模拟电路公开值）。"""
    spec = compile_policy(POLICY)
    return {
        "policy_hash": spec["sha256"],
        "passed": True,
        "response_binding": commit.response_binding(nonce, response),
        "violations": [],
    }


def _issue(response: str, nonce: bytes, *, end_user: bool):
    """O 用被证明的 ``response`` 出证；返回 (payload, signer)。"""
    spec = compile_policy(POLICY)
    outcome = _outcome(response, nonce)
    if end_user:
        block = challenge.end_user_challenge_block(
            nonce, outcome["response_binding"], response)
    else:
        block = challenge.challenge_block(nonce, outcome["response_binding"])
    payload = cert.build_payload(POLICY.id, POLICY.version, spec, "public",
                                 outcome, vkey_hash="unproven",
                                 ts="2026-01-01T00:00:00Z", challenge=block)
    signer = cert.Ed25519Signer.generate()
    return payload, signer


def _envelope_ok(payload: dict, signer) -> bool:
    """U/V 只凭公钥验签。"""
    env = cert.sign_payload(payload, signer)
    ok, got = cert.verify_envelope(env, signer.public_key)
    return bool(ok and got == payload)


def scenario_f0_replay() -> dict:
    """空 nonce：第二轮原样重放仍被接受。"""
    payload, signer = _issue(GOOD_T, b"", end_user=False)
    first = challenge.check_challenge(payload, GOOD_T)
    replay = challenge.check_challenge(payload, GOOD_T)  # 同一张证书、同一 T
    return {"scenario": "f=0 replay", "issuer": "verifier",
            "first_accept": first, "replayed_accept": replay}


def scenario_verifier_only_divergent() -> dict:
    """V 出 nonce；O 给 V 的是 T_V，给 U 的是 T_U。U 无法发现。"""
    nonce_v = challenge.new_nonce()
    payload, signer = _issue(GOOD_T, nonce_v, end_user=False)
    v_accept = challenge.check_challenge(payload, GOOD_T, issuer="verifier")
    # U 没有 nonce_v，也没有 end_user_binding；它只能验签。
    u_can_check_delivery = challenge.END_USER_BINDING_FIELD in payload["challenge"]
    u_accept = _envelope_ok(payload, signer) and not u_can_check_delivery
    return {"scenario": "verifier-only divergent delivery", "issuer": "verifier",
            "v_accept": v_accept, "u_received": BAD_T,
            "u_has_delivery_binding": u_can_check_delivery,
            "u_accept": u_accept}


def scenario_end_user_divergent() -> dict:
    """U 出 nonce；O 用 T_V 生成 end-user 绑定；U 收到 T_U → 拒绝。"""
    nonce_u = challenge.new_nonce()
    payload, signer = _issue(GOOD_T, nonce_u, end_user=True)
    # 诚实交付：U 收到 T_V，重算通过
    honest = challenge.check_challenge(payload, GOOD_T, issuer="end-user")
    # 换货：U 收到 T_U，重算失败
    divergent = challenge.check_challenge(payload, BAD_T, issuer="end-user")
    return {"scenario": "end-user divergent delivery", "issuer": "end-user",
            "honest_accept": honest, "divergent_accept": divergent,
            "u_has_delivery_binding": challenge.END_USER_BINDING_FIELD in payload["challenge"]}


def main() -> int:
    results = [scenario_f0_replay(), scenario_verifier_only_divergent(),
               scenario_end_user_divergent()]
    print(json.dumps(results, indent=2, ensure_ascii=False))
    # 判据：f=0 重放必须成功；verifier-only 的 divergent 必须「成功」（缺口）；
    # end-user 的 divergent 必须失败。
    ok = (results[0]["replayed_accept"] is True
          and results[1]["u_accept"] is True
          and results[2]["honest_accept"] is True
          and results[2]["divergent_accept"] is False)
    print(f"\nDEMO: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
