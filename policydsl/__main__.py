"""Proof-of-Policy DSL 工具链的 CLI 入口。

用法：
    python -m policydsl compile <policy.json>
    python -m policydsl check  <response.txt> --policy <policy.json> [--emit-proof-request]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .compile import compile_policy
from .evaluate import check
from .model import Policy, PolicyError, Rule


def _load_policy(path: Path) -> Policy:
    """从 JSON 文件加载策略包，并做基础容错（文件缺失/JSON 非法）。"""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"policy file not found: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in {path}: {exc}")
    rules = [
        Rule(kind=r.get("kind", ""), name=r.get("name", f"rule-{i}"), params=r.get("params", {}))
        for i, r in enumerate(data.get("rules", []))
    ]
    return Policy(
        id=data["id"],
        version=data.get("version", "0.1.0"),
        description=data.get("description", ""),
        rules=rules,
        semantic=data.get("semantic", "and"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="policydsl", description="Proof-of-Policy DSL toolchain")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # 子命令 compile：策略包 → ConstraintSpec JSON
    pc = sub.add_parser("compile", help="compile a policy pack to ConstraintSpec JSON")
    pc.add_argument("policy", type=Path)

    # 子命令 check：对响应做参考评估
    cc = sub.add_parser("check", help="reference-evaluate a response against a policy")
    cc.add_argument("response", type=Path)
    cc.add_argument("--policy", type=Path, required=True)
    cc.add_argument("--emit-proof-request", action="store_true",
                    help="also write proof-request.json for the SP1 prover (W4+)")

    args = parser.parse_args(argv)

    try:
        if args.cmd == "compile":
            spec = compile_policy(_load_policy(args.policy))
            print(json.dumps(spec, ensure_ascii=False, indent=2))
        elif args.cmd == "check":
            policy = _load_policy(args.policy)
            response = args.response.read_text(encoding="utf-8")
            result = check(policy, response)
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
            if args.emit_proof_request:
                # 生成可喂给 SP1 prover 的 proof-request.json（含 spec、响应、期望判定）
                req = {
                    "spec": compile_policy(policy),
                    "response": response,
                    "expected": result.passed,
                }
                Path("proof-request.json").write_text(
                    json.dumps(req, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                print("# proof-request.json written (feed to the SP1 prover in W4+)", file=sys.stderr)
    except PolicyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
