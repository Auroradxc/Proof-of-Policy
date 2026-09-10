#!/usr/bin/env python3
"""把锁定的 Anchor 合约部署到一条 EVM 链（默认本地 Anvil）。

合约字节码来自**入库**的 ``contracts/Anchor.json``（abi + bytecode），
因此部署**不需要 solc/forge**，只需要 foundry 的 `cast` 与一个 RPC 端点。

用法：
  # 1) 本地 Anvil（另开一个终端：anvil）
  python3 scripts/deploy_anchor.py --rpc http://127.0.0.1:8545
  # 2) 部署信息写进 .anchor_deploy.json（gitignore），供 demo / verify_session 复用
  #    脚本末尾会打印可 source 的环境变量

  # 任意测试网/本地节点
  python3 scripts/deploy_anchor.py --rpc $RPC --private-key $KEY --out deploy.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from policydsl import anchor  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:8545", help="EVM RPC 端点")
    ap.add_argument("--private-key", default=anchor.ANVIL_KEY,
                    help="部署者私钥（默认 Anvil #0；生产用 keystore/HSM）")
    ap.add_argument("--out", type=Path, default=REPO / ".anchor_deploy.json",
                    help="把部署结果写成 JSON（默认仓库根 .anchor_deploy.json，已 gitignore）")
    ap.add_argument("--artifact", type=Path, default=None, help="覆盖 contracts/Anchor.json")
    args = ap.parse_args()

    try:
        info = anchor.deploy_anchor_contract(args.rpc, args.private_key,
                                             artifact_path=args.artifact)
    except anchor.AnchorError as exc:
        print(f"[deploy] FAILED: {exc}", file=sys.stderr)
        print("[deploy] hint: is a node running? `anvil` (foundry) or pass --rpc", file=sys.stderr)
        return 1

    info["out"] = str(args.out)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")

    print(f"contract : {info['contract']}")
    print(f"address  : {info['address']}")
    print(f"chain_id : {info['chain_id']}")
    print(f"tx_hash  : {info['tx_hash']}")
    print(f"deployer : {info['deployer']}")
    print(f"written  : {args.out}")
    print("\nexport POP_ANCHOR_RPC=%s" % info["rpc_url"])
    print("export POP_ANCHOR_CONTRACT=%s" % info["address"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
