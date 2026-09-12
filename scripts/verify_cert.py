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
  3c. 轨迹绑定（P1-5）：证书 outcome 内嵌的 trace_root == 证明公开值承诺的
     == 由**网关侧收到的回执链**现场重算的（带 --receipts 时这一路才齐全）。
     另：带 --gateway-key 时对回执链**逐条验签**（链下验签，与电路内的结构校验
     是两道独立的关）—— 摘要对得上只说明内容一致，不说明网关签过；
  3d. 会话末端承诺（P1-5b）：证书**载荷顶层**的 trace_seal（网关在会话结束时签的
     `{count, trace_root}`）验签通过，且其 trace_root == 被证明的 trace_root；带
     --receipts 时再核对 len(链) == seal.count 与链尾摘要。这一卡拦的是**截尾**：
     3c 比的是「证书绑的链」与「送检的链」两份检材，二者可以同时是那条被截断的
     链 —— 只有网关签过的 count/链尾能发现「后面还有没有」。
     **它不依赖 --receipts**（seal 自带 count/链尾），但**要求 --gateway-key**：
     没有网关公钥就无从判断 seal 真伪，此时「没有 seal」与「出证方没承诺会话末端」
     分不开，按 3c 的同类做法如实记 PASS + 说明（截尾不可排除），而不是假装核过；
     给了网关公钥却**没有** trace_seal 的证书则是 FAIL —— 验证方既然知道这段会话
     有网关，就该有它的末端承诺；
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
      [--receipts receipts.json --gateway-key gateway_pub.hex] \
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

from policydsl import anchor, cert, challenge, commit, keys, trace, verifier
from policydsl import semantic as S
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
    ap.add_argument("--receipts", type=Path, default=None,
                    help="P1-5：**网关侧收到的**工具回执链（JSON 数组）。给了才能把"
                         "「证明承诺的链尾」与「自己手上这条链」对上")
    ap.add_argument("--gateway-key", default=None,
                    help="工具网关公钥（P1-5，形式同 --keyring）：给了就对回执链逐条验签，"
                         "并核对会话末端承诺 trace_seal（P1-5b，拦截尾）")
    ap.add_argument("--semantic-dir", type=Path, default=None,
                    help="P2-9：语义规则的 ezkl 材料目录（vk.ezkl / settings.json / srs / "
                         "陪伴证明）。策略含 semantic_bound 时**必给** —— 那部分不在 SP1 "
                         "证明里，不给就核不了（本工具会 fail closed）")
    ap.add_argument("--semantic-skip-ezkl", action="store_true",
                    help="P2-9：只核对指纹与响应绑定，**不跑 ezkl 验证器**。用于没有 ezkl 的"
                         "环境；此时「证明本身有效」这一条未被核验，结果会如实标注")
    args = ap.parse_args()

    env = json.loads(args.cert.read_text(encoding="utf-8"))
    results = []
    # 送达的响应 T′ 原文（**不加工**，见 scripts/ezkl_prove.py::_read_response）。
    # 语义规则的陪伴证明要对着它核对 encode(T′)，逐字符都必须一致。
    response_text = (args.response.read_text(encoding="utf-8")
                     if args.response is not None else None)

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

    # 3c) 轨迹绑定（P1-5）：被证明的轨迹是不是**我手上这条**链。
    #
    #     与 3b 同构，但绑的对象从「响应」换成「工具回执链」。缺 `--receipts`
    #     时这一路来源就没有 —— 此时证书里那些 `trace_root` 只能证明「出证方
    #     前后自洽」，证明不了链里到底有什么。链长了也不必把链塞进公开值：
    #     验证方本来就持有网关发给它的回执，重算链尾即可。
    tr_cert = (payload.get("outcome") or {}).get("trace_root")
    tr_proof = verifier.committed_trace_root(proof_result) if proof_result else None

    # 网关公钥只加载一次，3c 的回执验签与 3d 的 seal 验签共用。**3d 不依赖
    # --receipts**：seal 自带 count/trace_root 与签名，所以「验证方手上没有链」
    # 时仍然能核对「被证明的那条链有没有被截尾」。
    gw_ring, gw_note = None, ""
    if args.gateway_key:
        try:
            gw_ring = keys.load_keyring(args.gateway_key)
        except (OSError, ValueError, TypeError) as exc:
            gw_note = f"网关公钥无法加载：{exc}"

    tr_gateway, tr_note = None, ""
    receipts = None
    if args.receipts is not None:
        receipts = trace.receipts_from_json(
            json.loads(args.receipts.read_text(encoding="utf-8")))
        tr_gateway = trace.trace_root(receipts)
        tr_note = f" — 网关侧 {len(receipts)} 条回执重算"
        # 验签是**另一件事**：摘要对得上只说明内容一致，不说明网关签过。
        # 给了网关公钥就顺带验一遍（这与电路内的结构校验是两道独立的关）。
        if not args.gateway_key:
            # 单独给了 --receipts 却没给网关公钥：如实说明「签名未验」
            results.append(("receipt_chain", True,
                            "只重算了链尾摘要；未给 --gateway-key，回执签名未验"))
        elif gw_ring is None:
            results.append(("receipt_chain", False, gw_note))
        else:
            ok_chain, why = trace.verify_chain(receipts, gw_ring)
            results.append(("receipt_chain", ok_chain,
                            f"{len(receipts)} 条回执验签通过" if ok_chain else why))
    if tr_cert is None and tr_proof is None:
        results.append(("trace_binding", True,
                        "certificate has no trace_root — skipped（P1-5 之前签发的证书）"))
    else:
        ok_tr, tr_detail = verifier.check_trace_binding([
            ("cert.outcome", tr_cert),
            ("proof", tr_proof),
            ("receipts", tr_gateway),
        ])
        if not ok_tr and tr_gateway is not None:
            tr_note = " — 网关侧回执链与证书对不上"
        results.append(("trace_binding", ok_tr, tr_detail + tr_note))

        # 3d) 会话末端承诺（P1-5b）：这条链**有没有被截尾**。
        #
        #     3c 回答「证明绑的是不是我手上这条链」，但它比的是**两份检材**，
        #     而两份都可以是那条被截断的链 —— 任何只看交付链的检查都无从知道
        #     「后面还有没有」。唯一的补法是让网关对会话末端签字：seal 里带
        #     `count` 与 `trace_root`，截尾必然让其中之一对不上。
        #
        #     三处一起比：seal 自称的链尾 == 证书/证明承诺的 trace_root（说明
        #     这条 seal 说的就是被证明的那条链）；再（有 --receipts 时）核对手上
        #     这条检材的长度与链尾。签名那一关与回执验签同级，都靠 --gateway-key。
        #
        #     它在载荷**顶层**而不是 outcome 里：outcome 是证明公开值的镜像
        #     （上面 proof_outcome 卡逐字段比过），而 seal 是链下网关签的，
        #     电路里没有这个东西。
        seal = trace.seal_from_json(payload.get("trace_seal"))
        if seal is None and args.gateway_key:
            # 验证方给了网关公钥 ⇒ 它知道这段会话由一个（这把钥匙的）网关经手，
            # 证书却没有任何末端承诺 —— 「链尾被整条删掉」无从排除。这是**矛盾**，
            # 不是「旧版证书」，所以判 FAIL 而不是跳过。
            results.append(("trace_seal", False,
                            "证书没有 trace_seal（P1-5b 之前签发，或出证方未承诺会话末端）"
                            "—— 无法排除链尾被整条删掉；请重签"))
        elif seal is None:
            # 没给网关公钥：seal 的真伪本来就核不了，「没有 seal」与「出证方没承诺」
            # 也分不开。如实记一条 PASS + 说明（与 3c 的「只有一份来源」同类），
            # 绝不写成「截尾已排除」。
            results.append(("trace_seal", True,
                            "证书未附 trace_seal —— 会话末端未被承诺，**截尾不可排除**；"
                            "未给 --gateway-key，此处无从进一步核对 (skipped)"))
        elif tr_cert is not None and seal.trace_root != tr_cert:
            results.append(("trace_seal", False,
                            f"seal.trace_root={seal.trace_root[:12]}… != 证书承诺的 "
                            f"trace_root={tr_cert[:12]}…"
                            "（seal 承诺的链尾与证书承诺的不一致：链被截尾或换成了另一条）"))
        elif args.gateway_key and gw_ring is None:
            # 给了钥匙却加载不了：不能降级成「结构对就算过」——那等于假装验过。
            results.append(("trace_seal", False, gw_note))
        else:
            ok_seal, why_seal = trace.verify_seal(seal, gw_ring, receipts)
            if ok_seal and not gw_ring:
                why_seal = ("seal 与链长/链尾一致；未给 --gateway-key，seal 签名未验")
            results.append(("trace_seal", ok_seal, why_seal))

    # 3e) 语义规则（P2-9）：**SP1 证明判不了的那部分**，必须由陪伴证明补上。
    #
    #     这一块的特殊之处：它是本项目里**唯一**一处「证明通过了、但结论还不完整」
    #     的地方。`outcome.delegated` 非空 == 电路在说「这几条我没判，你去找陪伴
    #     证明」。所以这里的默认行为必须是 **fail closed**：delegated 里有一条
    #     找不到对应的 companion，就是 FAIL —— 而不是「跳过」。
    #
    #     跳过会得到一个**静默的空壳**：证书看起来全绿，而语义规则那条根本没被
    #     判定。这正是 P0-1 的形态（「看起来验过了」），只是换了个位置。
    delegated = (payload.get("outcome") or {}).get("delegated") or []
    # 语义规则的**满足情况**（与证书真伪分开记，见下面的「合规」行）。
    semantic_satisfied: list = []
    if delegated:
        comps = ((payload.get("semantic") or {}).get("companions")) or []
        by_rule = {c.get("rule"): c for c in comps if isinstance(c, dict)}
        if not args.semantic_dir:
            results.append(("semantic", False,
                            f"策略里有 {len(delegated)} 条语义规则被委托给陪伴证明，"
                            f"但没有给 --semantic-dir —— 无法核验；"
                            f"（这些规则**没有被 SP1 证明判定**，不能默认通过）"))
        elif response_text is None:
            # 绑定核对要拿 T′ 重算 encode(T′)。没有 T′ 就核不了第 5 步，
            # 而第 5 步正是「这份 ezkl 证明说的是这条响应」的**唯一**依据。
            results.append(("semantic", False,
                            "策略含语义规则但没给 --response：无法把陪伴证明绑到送达的"
                            "响应上（信任边界 ③）—— 只验 ezkl 证明本身是不够的"))
        else:
            for dep in delegated:
                rule = dep.get("name")
                comp = by_rule.get(rule)
                if comp is None:
                    results.append((f"semantic[{rule}]", False,
                                    "证书里没有这条规则的陪伴证明（delegated 非空而 "
                                    "companions 缺失/不全）—— 语义规则未被判定"))
                    continue
                ok_c, why_c, hits = S.verify_companion(
                    dep, comp, response_text, args.semantic_dir,
                    verify_proof=not args.semantic_skip_ezkl)
                if ok_c and args.semantic_skip_ezkl:
                    why_c += "（--semantic-skip-ezkl：**未**跑 ezkl 验证器，证明有效性未核）"
                # 这一栏是**证书真伪**：证明是真的、绑在这条响应上。
                # 「规则是否满足」是证书内容，另记在下面的合规行里 —— 见
                # `policydsl.semantic.verify_companion` 的返回值说明。
                results.append((f"semantic[{rule}]", ok_c, why_c))
                if ok_c:
                    semantic_satisfied.append((rule, hits))
    else:
        # 电路说「我全判了」。但证书若**多带**了一份 companion，说明出证方与电路
        # 对策略的理解不一致 —— 宁可报出来，也不要默默忽略一个多余的证明。
        comps = ((payload.get("semantic") or {}).get("companions")) or []
        if comps:
            results.append(("semantic", False,
                            f"公开值里 delegated 为空，证书却带了 {len(comps)} 份陪伴证明"
                            f"—— 证书与证明对策略的描述不一致"))
        else:
            results.append(("semantic", True, "策略里没有语义规则（无需陪伴证明）"))

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

    # 合规行（P2-9）：**与 RESULT 分开**，因为二者是两件事。
    #
    #   RESULT  = 这张证书是**真的**吗（签名/绑定/证明都对得上）。一张如实记录
    #             违规的证书同样是真证书 —— 仓库里 `--expect violate` 的演示就
    #             靠这一点。所以它与 `passed` 无关。
    #   合规    = 证书**说的是不是「策略满足了」**。SP1 的 outcome.passed 只覆盖
    #             判得了的那部分；被委托出去的语义规则必须**逐条**满足，否则
    #             整体不算合规 —— 少了这一行，一张 `passed=true` 而语义规则没过
    #             的证书会被读成合规，那正是本项目的头号失败形态。
    #
    # 只有真的核过语义规则时才下结论：`--semantic-skip-ezkl` 下证明有效性未核，
    # 这里如实说「未核」，而不是顺着 outcome.passed 说「合规」。
    if semantic_satisfied:
        sp1_ok = bool(payload["outcome"].get("passed"))
        sem_ok = all(h for _, h in semantic_satisfied)
        if args.semantic_skip_ezkl:
            verdict = "未核（--semantic-skip-ezkl）"
        else:
            verdict = "PASS" if (sp1_ok and sem_ok) else "FAIL"
        unmet = [r for r, h in semantic_satisfied if not h]
        why = f"（SP1 部分 passed={sp1_ok}"
        if unmet:
            why += f"；未满足的语义规则：{', '.join(unmet)}"
        why += "）"
        print(f"合规: {verdict} {why}" if verdict != "未核（--semantic-skip-ezkl）"
              else f"合规: {verdict}")
    return 0 if ok_all else 1


def print_fail(results) -> None:
    """签名失败时打印已得结果并返回失败。"""
    for name, ok, detail in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:14s} {detail}")
    print("\nRESULT: FAIL")


if __name__ == "__main__":
    sys.exit(main())
