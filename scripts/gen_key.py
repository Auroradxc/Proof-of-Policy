#!/usr/bin/env python3
"""生成/查看 PoP 的 Ed25519 签名密钥对（P0-3）。

P0-3 之前证书用硬编码的公开 HMAC 密钥签名 —— 任何人都能伪造。现在签名与
验签分离：**私钥**留在出证方（agent 运营方），**公钥**交给验证方/审计方。
本脚本负责生成这对密钥，并打印验证方需要的那几样东西。

用法：
  # 生成到 .pop-keys/（已 gitignore；私钥 0600、不覆盖已有文件）
  python3 scripts/gen_key.py

  # 生成到指定目录，并把公钥单独存一份便于分发
  python3 scripts/gen_key.py --out-dir keys/ --name demo

  # 只打印已有密钥的 keyid / 公钥（不生成、不写盘）
  python3 scripts/gen_key.py --show

  # 由**公钥**算 keyid（验证方手上通常只有公钥）
  python3 scripts/gen_key.py --pubkey keys/demo.pub.hex

验证方需要的东西（脚本会打印）：
  keyid（``ed25519:<sha256(原始公钥)>``）—— 出现在证书信封里，用来选密钥；
  public key（hex 或 PEM）—— 拿去构造 keyring。

给证书验签：
  python3 scripts/verify_cert.py --cert c.json --pack p.json --ledger l.jsonl \\
      --keyring keys/demo.pub.hex
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import keys  # noqa: E402


def _print_public(pub, keyid: str, label: str = "") -> None:
    if label:
        print(f"\n[{label}]")
    print(f"keyid       : {keyid}")
    print(f"public (hex): {keys.public_hex(pub)}")
    print(keys.public_pem(pub).rstrip())


def main() -> int:
    ap = argparse.ArgumentParser(description="生成/查看 PoP 的 Ed25519 签名密钥")
    ap.add_argument("--out-dir", type=Path, default=None,
                    help="密钥输出目录（默认取 $POP_SIGNING_KEY 的所在目录，"
                         "否则 .pop-keys/）")
    ap.add_argument("--path", type=Path, default=None,
                    help="私钥文件路径（优先级最高；覆盖 --out-dir）")
    ap.add_argument("--name", default="signing",
                    help="文件名前缀（默认 signing；产出 <name>.key / <name>.pub.*）")
    ap.add_argument("--show", action="store_true",
                    help="只读已有私钥并打印公钥，不生成、不写盘")
    ap.add_argument("--pubkey", default=None,
                    help="由给定公钥（文件路径 / hex / PEM）算 keyid，不接触私钥")
    ap.add_argument("--force", action="store_true",
                    help="允许覆盖已存在的私钥文件（默认拒绝覆盖）")
    args = ap.parse_args()

    # -- 只算公钥的 keyid（验证方路径，永远不读私钥） --
    if args.pubkey:
        pub = keys.load_public(args.pubkey)
        _print_public(pub, keys.keyid(pub), "由公钥导出（无私有信息）")
        return 0

    key_file = args.path or (
        (args.out_dir / f"{args.name}.key") if args.out_dir
        else keys.key_path()
    )

    # -- 只读模式：不生成、不写盘 --
    if args.show:
        if not key_file.exists():
            print(f"私钥不存在：{key_file}", file=sys.stderr)
            return 1
        signer = keys.signer_from_env(key_file)
        _print_public(signer.public_key, signer.keyid, f"来自 {key_file}（未写盘）")
        return 0

    # -- 生成 --
    if key_file.exists() and not args.force:
        print(f"私钥已存在，拒绝覆盖：{key_file}\n"
              f"（要查看它用 --show；要轮换请先删除或换 --path/--name）", file=sys.stderr)
        return 1
    if key_file.exists() and args.force:
        key_file.unlink()

    signer = keys.signer_from_env(key_file)
    pub = signer.public_key

    # 公钥单独存两份（hex 便于命令行传递，PEM 便于人读/贴工单）
    out_dir = key_file.parent
    hex_file = out_dir / f"{args.name}.pub.hex"
    pem_file = out_dir / f"{args.name}.pub.pem"
    hex_file.write_text(keys.public_hex(pub) + "\n")
    pem_file.write_text(keys.public_pem(pub))

    print(f"private key : {key_file}  (PKCS#8 PEM, 0600, 已 gitignore)")
    _print_public(pub, signer.keyid)
    print(f"\npublic key  : {hex_file}")
    print(f"              {pem_file}")
    print(f"\n验证方只需要公钥：\n"
          f"  python3 scripts/verify_cert.py ... --keyring {hex_file}")
    print(json.dumps({"keyid": signer.keyid, "public_hex": keys.public_hex(pub)},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
