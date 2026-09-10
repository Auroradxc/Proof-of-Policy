#!/usr/bin/env python3
"""阶段四：私有模式 demo / 验证（+ 边界加固）。

端到端检查私有流水线：
  - 宿主校验（HOST CHECK）：pop-script --check（pop-types::evaluate_private）
    对比 Python golden（policydsl.commit.private_output）—— 逐字段，包括响应承诺、
    证据承诺、脱敏证明，以及边界性质 ``mask_covered``（掩码 ⊆ 真实匹配，电路内强制）。
  - 负例（NEGATIVE）：伪造的见证区间（掩码落在任何真实匹配之外）应得 mask_covered=false。
  - 泄露（LEAK）：验证器可见输出里没有响应/证据明文。
  - 绑定（BINDING）：承诺确定性、互不相同；伪造脱敏被拒绝。
  - 证据开示（EVIDENCE OPENING）：披露的片段能对照其承诺验证通过。
  - 证明（PROOF）：同一个私有任务在 SP1 内证明并复查（--no-prove 可跳过）。

用法：SP1_PROVER=cpu python3 scripts/private_demo.py [--no-prove]
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

from policydsl import commit, pii
from policydsl.compile import compile_policy
from policydsl.model import Policy, Rule
from policydsl.serialize import spec_to_rust_constraints

POP_SCRIPT = REPO / "circuits" / "target" / "release" / "pop-script"


def build_case() -> dict:
    """构造一个私有模式用例：含关键词、长度、邮箱正则三条规则，
    并预计算掩码/脱敏/见证区间/golden。"""
    policy = Policy("private-demo", "0.1", rules=[
        Rule("keyword_block", "no_bad", {"keywords": ["exploit", "doxxing"]}),
        Rule("length_bound", "len_ok", {"min": 1, "max": 2000}),
        Rule("pattern_block", "no_email", {"patterns": [pii.PII_PATTERNS["email"]]}),
    ])
    response = "Reach dev@example.com to continue; we will not doxxing anyone."
    spec = compile_policy(policy)
    mask = commit.mask_from_patterns([pii.PII_PATTERNS["email"]], response)
    redacted = commit.redact(response, mask)
    spans = commit.spec_spans(spec, response)
    golden = commit.private_output(spec, response, mask, redacted, spans)
    vector = {
        "name": policy.id,
        "response": response,
        "constraints": spec_to_rust_constraints(spec),
        "private": True,
        "mask": mask,
        "redacted": redacted,
        "spans": [list(s) for s in spans],
    }
    return {"policy": policy, "spec": spec, "response": response, "redacted": redacted,
            "mask": mask, "spans": spans, "golden": golden, "vector": vector}


def run_pop(check_mode: bool, vectors: Path, out: Path) -> None:
    """调用 pop-script；check_mode=True 时走宿主校验路径。"""
    args = [str(POP_SCRIPT)]
    if check_mode:
        args.append("--check")
    args += ["--vectors", str(vectors), "--out", str(out)]
    subprocess.run(args, env=dict(os.environ, SP1_PROVER="cpu"), check=True, cwd=str(REPO))


def compare_private(mode: str, name: str, golden: dict, got: dict) -> bool:
    """逐字段比对 golden 与 SP1 私有输出。"""
    g_rules = sorted((v["rule"], v["kind"], v["evidence_commitment"]) for v in golden["violations"])
    s_rules = sorted((v["rule"], v["kind"], v["evidence_commitment"]) for v in got["violations"])
    checks = {
        "passed": got["passed"] == golden["passed"],
        "response_commitment": got["response_commitment"] == golden["response_commitment"],
        "violations": g_rules == s_rules,
        "redaction": (got["redaction"] or {}) == (golden["redaction"] or {}),
    }
    ok = all(checks.values())
    print(f"[{'PASS' if ok else 'FAIL'}] {mode:5s} {name} passed={got['passed']} "
          f"rules={[(r, k) for r, k, _ in s_rules]} redaction={got['redaction']}")
    if not ok:
        for k, v in checks.items():
            if not v:
                print(f"   mismatch {k}: golden={golden.get(k)} got={got.get(k)}")
    return ok


def leak_experiment(case: dict, public_out: dict) -> bool:
    """泄露实验：验证器可见输出里不应含响应/证据明文，
    且承诺是 64 位十六进制、不等于原始响应。"""
    blob = json.dumps(public_out)
    leaks = [w for w in set(case["response"].split()) if len(w) >= 4 and w in blob]
    commit_ok = len(public_out["response_commitment"]) == 64
    commit_ok &= all(len(v["evidence_commitment"]) == 64 for v in public_out["violations"])
    ok = (not leaks) and commit_ok and public_out["response_commitment"] != case["response"]
    print(f"[{'PASS' if ok else 'FAIL'}] leak      no_tokens={not leaks} "
          f"commitments_64hex={commit_ok}")
    return ok


def binding_experiment(case: dict) -> bool:
    """绑定实验：承诺确定性、不同输入不同承诺、伪造脱敏被拒。"""
    a = commit.commitment(case["response"])
    deterministic = a == commit.commitment(case["response"])
    distinct = a != commit.commitment(case["response"] + "x")
    forged_ok = commit.redaction_ok(case["response"], "Q" + case["redacted"][1:], case["mask"])
    ok = deterministic and distinct and not forged_ok
    print(f"[{'PASS' if ok else 'FAIL'}] binding   deterministic={deterministic} "
          f"distinct={distinct} forged_rejected={not forged_ok}")
    return ok


def evidence_experiment(case: dict) -> bool:
    """证据开示实验：bundle 自洽、与证明中的承诺一致、篡改被拒。"""
    bundle = commit.evidence_bundle(case["spec"], case["response"])
    ok_open = commit.verify_bundle(bundle) and len(bundle) == len(case["golden"]["violations"])
    # 披露的承诺必须等于证明输出里的承诺
    proof_comms = {v["evidence_commitment"] for v in case["golden"]["violations"]}
    bundled = {e["evidence_commitment"] for e in bundle}
    ok_bind = proof_comms == bundled
    # 篡改会破坏校验
    bad = [dict(e) for e in bundle]
    bad[0]["evidence"] = "tampered"
    ok_reject = not commit.verify_bundle(bad)
    ok = ok_open and ok_bind and ok_reject
    print(f"[{'PASS' if ok else 'FAIL'}] opening   verified={ok_open} bound_to_proof={ok_bind} "
          f"tamper_rejected={ok_reject}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-prove", action="store_true")
    args = ap.parse_args()

    case = build_case()
    # 负例：伪造见证区间（未覆盖掩码）
    bad_vector = {**case["vector"], "name": "private-demo-badspan", "spans": [[0, 1]]}
    bad_golden = commit.private_output(case["spec"], case["response"], case["mask"],
                                       case["redacted"], [(0, 1)])

    out_dir = REPO / "scripts" / "examples" / "out" / "private"
    out_dir.mkdir(parents=True, exist_ok=True)

    check_vec = out_dir / "vectors_check.json"
    check_vec.write_text(json.dumps({"vectors": [case["vector"], bad_vector]}, indent=2))

    ok = True
    hout = out_dir / "host.json"
    run_pop(True, check_vec, hout)
    got = json.loads(hout.read_text())
    ok &= compare_private("check", "good", case["golden"], got[0])
    ok &= compare_private("check", "badspan", bad_golden, got[1])
    # 负例必须报告 mask_covered=false（电路内强制边界性质）
    neg_ok = got[1]["redaction"]["mask_covered"] is False
    print(f"[{'PASS' if neg_ok else 'FAIL'}] negative  bad-span mask_covered=false (got "
          f"{got[1]['redaction']['mask_covered']})")
    ok &= neg_ok

    ok &= leak_experiment(case, got[0])
    ok &= binding_experiment(case)
    ok &= evidence_experiment(case)

    if not args.no_prove:
        # 真实证明：单独证明「好」用例
        pout = out_dir / "proof.json"
        prove_vec = out_dir / "vectors_prove.json"
        prove_vec.write_text(json.dumps({"vectors": [case["vector"]]}, indent=2))
        print("--- proving private job (SP1, ~1 min) ---")
        run_pop(False, prove_vec, pout)
        got_p = json.loads(pout.read_text())[0]
        ok &= compare_private("prove", "good", case["golden"], got_p)
        ok &= leak_experiment(case, got_p)
    else:
        print("(--no-prove: skipped SP1 proof)")

    print("\nRESULT: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
