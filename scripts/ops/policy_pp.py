#!/usr/bin/env python3
"""P-PP 原型 CLI：签发 / 核验「带盐策略清单」。

两个子命令：

签发（权威侧，**需要私钥**）::

    python3 scripts/ops/policy_pp.py issue \\
        --pack policy_packs/agent_content_v1.json \\
        --nonce a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1 \\
        --key .pop-keys/authority.key --out manifest.json

核验（第三方侧，**只需公钥**）::

    python3 scripts/ops/policy_pp.py verify \\
        --manifest manifest.json --registry registry.json \\
        --cert cert.json --authority-key authority.pub.hex

``--nonce`` 缺省时按策略包**原样**签发；若包里没有 ``policy_nonce``，会打印一条
警告（无盐哈希可被枚举）。盐**不会**写进清单 —— 它由权威在审计时开示，或私下
交给运营方用于出证。

``verify`` 只核 P-PP 这一层：证书里的 ``policy_hash`` 是否对应一份被权威签发的
策略。它**不**验证证书本身（运营方签名 / SP1 证明 / 锚定）；需要时可加
``--operator-key`` 顺带验证书信封签名，其余检查仍由 ``scripts/verify/verify_cert.py``
负责。

退出码：PASS ⇒ 0，FAIL ⇒ 1。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # scripts/
from _bootstrap import REPO, bootstrap  # noqa: E402

bootstrap()

from policydsl.evidence import cert, keys  # noqa: E402
from policydsl.evidence.policy_registry import (  # noqa: E402
    PolicyRegistry,
    issue_manifest,
    verify_cert_policy,
    verify_manifest,
)
from policydsl.privacy.policy_commit import attach_nonce  # noqa: E402


def _read_json(path: str) -> Any:
    return json.loads(Path(path).expanduser().read_text(encoding="utf-8"))


def _write_json(path: str, obj: Any) -> Path:
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
                 encoding="utf-8")
    return p


def _cert_payload(path: str, operator_key: Optional[str]) -> Any:
    """读证书：信封则解码载荷（可选先验运营方签名），否则当作裸载荷。"""
    doc = _read_json(path)
    if not (isinstance(doc, dict) and "payload" in doc and "payloadType" in doc):
        return doc
    if operator_key:
        ok, payload = cert.verify_envelope(doc, keys.load_public(operator_key))
        if not ok:
            raise SystemExit(f"FAIL 证书信封验签失败（--operator-key）：{path}")
        return payload
    print("警告：未验证证书信封签名（只核对 P-PP 绑定）；"
          "需要时加 --operator-key。", file=sys.stderr)
    return cert.envelope_payload(doc)


def cmd_issue(args: argparse.Namespace) -> int:
    pack = _read_json(args.pack)
    if not isinstance(pack, dict):
        print(f"FAIL 策略包必须是 JSON 对象：{args.pack}", file=sys.stderr)
        return 1
    if args.nonce:
        pack = attach_nonce(pack, args.nonce)
    elif not pack.get("policy_nonce"):
        print("警告：策略包没有 policy_nonce，签发的是**无盐**哈希（可被枚举）。"
              "需要隐藏策略请加 --nonce。", file=sys.stderr)

    key_path = keys.key_path(args.key)
    existed = key_path.exists()
    signer = keys.signer_from_env(args.key)
    if not existed:
        print(f"注意：新建了权威私钥 {key_path}（权限 0600，勿入库）。",
              file=sys.stderr)

    manifest = issue_manifest(pack, signer, issued_at=args.issued_at)
    out = _write_json(args.out, manifest)
    print(json.dumps({
        "manifest": str(out),
        "policy_id": manifest["policy_id"],
        "policy_version": manifest["policy_version"],
        "policy_hash": manifest["policy_hash"],
        "authority_keyid": manifest["authority_keyid"],
        "salted": bool(pack.get("policy_nonce")),
    }, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


def _load_public_key(arg: str):
    """``--authority-key`` 接受：存在的文件路径 / 十六进制 / PEM。"""
    if "-----BEGIN" in arg:
        return keys.read_public_text(arg)
    path = Path(arg).expanduser()
    if path.exists():
        return keys.load_public(path)
    return keys.read_public_text(arg)        # 裸十六进制（含 0x/空白）


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        authority = _load_public_key(args.authority_key)
    except (OSError, ValueError, TypeError) as exc:
        print(f"FAIL 权威公钥无法读取：{exc}", file=sys.stderr)
        return 1

    registry: PolicyRegistry
    if args.registry:
        registry = PolicyRegistry.load(args.registry)
    else:
        registry = PolicyRegistry()

    # 显式给了 manifest 时先验它自己的签名 —— 不把未验签的记录塞进 registry。
    if args.manifest:
        manifest = _read_json(args.manifest)
        if not verify_manifest(manifest, authority):
            print("FAIL 清单签名无效：字段被篡改，或不是这把权威公钥签的。",
                  file=sys.stderr)
            return 1
        try:
            registry.add(manifest)
        except ValueError as exc:
            print(f"FAIL 清单与签发记录冲突：{exc}", file=sys.stderr)
            return 1
    if not args.manifest and not args.registry:
        print("FAIL 至少需要 --manifest 或 --registry 之一。", file=sys.stderr)
        return 1

    payload = _cert_payload(args.cert, args.operator_key)
    ok, detail = verify_cert_policy(payload, registry, authority)
    if args.json:
        print(json.dumps({"ok": ok, "detail": detail}, ensure_ascii=False))
    else:
        print(("[PASS] " if ok else "[FAIL] ") + detail)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="policy_pp.py",
        description="P-PP 原型：签发/核验带盐策略清单（证书层）。")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("issue", help="权威签发一份策略清单（需要私钥）")
    pi.add_argument("--pack", required=True, help="策略包 JSON 路径")
    pi.add_argument("--out", required=True, help="输出清单 JSON 路径")
    pi.add_argument("--key", default=None,
                    help="权威私钥路径（缺省 $POP_SIGNING_KEY 或 .pop-keys/signing.key）")
    pi.add_argument("--nonce", default=None,
                    help="给策略包附加的 128-bit 盐（十六进制）；缺省用包内已有的")
    pi.add_argument("--issued-at", default=None, help="签发时间（缺省当前 UTC）")
    pi.set_defaults(func=cmd_issue)

    pv = sub.add_parser("verify", help="第三方核验证书哈希是否被签发（只需公钥）")
    pv.add_argument("--cert", required=True, help="证书文件（信封或裸载荷 JSON）")
    pv.add_argument("--manifest", default=None, help="待核验的清单 JSON（可省略）")
    pv.add_argument("--registry", default=None, help="签发记录 JSON（可省略）")
    pv.add_argument("--authority-key", required=True,
                    help="权威公钥：文件路径 / 十六进制 / PEM")
    pv.add_argument("--operator-key", default=None,
                    help="可选：运营方公钥，给出时顺带验证书信封签名")
    pv.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    pv.set_defaults(func=cmd_verify)
    return p


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
