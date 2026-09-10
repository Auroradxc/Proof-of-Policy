"""合规证书的「仅追加、防篡改」锚定账本与链上锚定后端。

两种后端：

1. **文件账本（默认，离线可验证）** —— 每条记录都链接到上一条：

       {"seq": n, "prev": <上一条记录的哈希|"genesis">, "digest": <证书摘要>,
        "ts": "...", "meta": {...}, "hash": <去掉 "hash" 字段后本记录的哈希>}

   ``verify_ledger`` 重新计算整条链，可检测任意编辑/重排/删除。

2. **RPC 后端（真链，`RpcAnchorBackend`）** —— 把同一个 ``digest`` 作为
   ``bytes32`` 登记进 ``contracts/Anchor.sol``（``anchor(bytes32)`` → 映射 +
   ``Anchored`` 事件），得到一条**公共、带时间戳、与本地账本无关**的存在性证明。
   底层用 foundry 的 `cast` 发交易/查询（无需 web3.py 依赖；Anvil 端到端本来
   就需要 foundry）。链上只存 32 字节摘要，不存任何响应/策略内容。

两个后端的 ``anchor()`` 契约一致，因此上层（demo / issue_cert）可以不改判定逻辑，
只换后端：``backend_from_env(ledger)``。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .cert import canonical, sha256_hex, utc_now

GENESIS = "genesis"

# 仓库根（本文件在 <repo>/policydsl/anchor.py）
REPO = Path(__file__).resolve().parent.parent
ARTIFACT = REPO / "contracts" / "Anchor.json"

# Anvil 的公开测试私钥（`anvil` 默认账户 #0）。仅用于本地 demo；生产用 keystore/HSM。
ANVIL_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

ENV_RPC = "POP_ANCHOR_RPC"          # 例：http://127.0.0.1:8545
ENV_CONTRACT = "POP_ANCHOR_CONTRACT"  # 已部署的 Anchor 合约地址
ENV_KEY = "POP_ANCHOR_KEY"          # 提交交易的私钥（缺省用 Anvil 测试键）


class AnchorError(RuntimeError):
    """锚定后端（RPC/合约）调用失败。"""


# --------------------------------------------------------------------------
# 摘要 <-> bytes32
# --------------------------------------------------------------------------

def digest_to_bytes32(digest: str) -> str:
    """把 ``cert_digest``（64 位十六进制，可带 0x）转成合约要的 bytes32 字面量。"""
    d = digest[2:] if digest.startswith("0x") else digest
    if len(d) != 64 or any(c not in "0123456789abcdefABCDEF" for c in d):
        raise ValueError(f"digest must be 32 bytes of hex (sha256), got {digest!r}")
    return "0x" + d.lower()


def bytes32_to_digest(word: str) -> str:
    """把链上读回的 bytes32/uint256 字面量转回 ``cert_digest`` 的十六进制串。"""
    w = word[2:] if word.startswith("0x") else word
    return w.lower().zfill(64)[-64:]


# --------------------------------------------------------------------------
# 文件账本（默认后端）
# --------------------------------------------------------------------------

def _entry_hash(entry: Dict[str, Any]) -> str:
    """计算记录的哈希：去掉 "hash" 字段后对剩余字段做规范哈希。

    这样「hash」本身不参与计算，避免自引用。
    """
    body = {k: v for k, v in entry.items() if k != "hash"}
    return sha256_hex(canonical(body))


def read_ledger(path: Path) -> List[Dict[str, Any]]:
    """逐行读取账本（每行一条 JSON），不存在则返回空列表。"""
    p = Path(path)
    if not p.exists():
        return []
    out: List[Dict[str, Any]] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def append_anchor(path: Path, digest: str, meta: Optional[Dict[str, Any]] = None,
                  ts: Optional[str] = None) -> Dict[str, Any]:
    """为 ``digest`` 追加一条锚定记录并返回该记录。

    ``prev`` 取上一条记录的 hash，首条取 "genesis"，从而形成哈希链。
    """
    entries = read_ledger(path)
    prev = entries[-1]["hash"] if entries else GENESIS
    entry = {
        "seq": len(entries),
        "prev": prev,
        "digest": digest,
        "ts": ts or utc_now(),
        "meta": meta or {},
    }
    entry["hash"] = _entry_hash(entry)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def verify_ledger(path: Path) -> Tuple[bool, str]:
    """重新计算整条链；返回 (ok, reason)。

    依次校验：序号连续、prev 链接正确、每条 hash 与内容一致（防篡改）。
    """
    prev = GENESIS
    for i, e in enumerate(read_ledger(path)):
        if e.get("seq") != i:
            return False, f"entry {i}: bad seq {e.get('seq')}"
        if e.get("prev") != prev:
            return False, f"entry {i}: prev mismatch"
        if e.get("hash") != _entry_hash(e):
            return False, f"entry {i}: hash mismatch (tampered)"
        prev = e["hash"]
    return True, "ok"


def find_anchor(path: Path, digest: str) -> Optional[Dict[str, Any]]:
    """在账本中查找第一条 digest 匹配的记录；找不到返回 None。"""
    for e in read_ledger(path):
        if e.get("digest") == digest:
            return e
    return None


# --------------------------------------------------------------------------
# 后端抽象
# --------------------------------------------------------------------------

class AnchorBackend:
    """锚定后端接口：``anchor`` 写入 / ``get`` 读回。"""

    name = "abstract"

    def anchor(self, digest: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        raise NotImplementedError

    def get(self, digest: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class FileLedgerBackend(AnchorBackend):
    """本地仅追加账本（默认；离线可验证）。"""

    name = "file"

    def __init__(self, path: Path):
        self.path = Path(path)

    def anchor(self, digest: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        entry = append_anchor(self.path, digest, meta)
        return {"backend": self.name, "status": "appended", **entry}

    def get(self, digest: str) -> Optional[Dict[str, Any]]:
        return find_anchor(self.path, digest)


# --------------------------------------------------------------------------
# RPC 客户端（foundry `cast`；可注入以便离线单测）
# --------------------------------------------------------------------------

def _find_cast() -> str:
    """定位 cast：PATH → ~/.foundry/bin。找不到给出可执行的安装提示。"""
    found = shutil.which("cast")
    if found:
        return found
    for cand in (Path.home() / ".foundry" / "bin" / "cast",):
        if cand.exists():
            return str(cand)
    raise AnchorError(
        "`cast` not found (foundry). Install: bash scripts/retry_install_foundry.sh "
        "(or run `foundryup`), or use the file ledger backend for offline verification.")


class CastRpc:
    """用 foundry `cast` 与 EVM 链交互的最小客户端（发交易 / eth_call）。

    只依赖外部二进制 `cast`，不引入 web3.py/eth-account 依赖；Anvil 端到端本来
    就需要 foundry。私钥以命令行参数传给 `cast`（本地 demo 可接受；生产应改用
    keystore/hardware signer，见 docs/plan-p7.md）。
    """

    def __init__(self, rpc_url: str, cast_bin: Optional[str] = None, timeout: int = 120):
        self.rpc_url = rpc_url
        self.cast = cast_bin or _find_cast()
        self.timeout = timeout

    # -- 内部：执行 cast 并返回 stdout ------------------------------------
    def _run(self, *args: str, tail: Tuple[str, ...] = (), allow_error: bool = False,
             with_rpc: bool = True) -> str:
        """跑一次 cast。

        参数顺序要点：``--rpc-url`` 必须紧跟子命令（`cast send --create <CODE> ...`
        会把 `--create` 之后的参数都当位置参数，此时再放 `--rpc-url` 会解析失败）；
        ``tail`` 是必须排在**最后**的位置参数（如 `--create` 的字节码）。
        """
        cmd = ([self.cast] + list(args) if not with_rpc
               else [self.cast, args[0], "--rpc-url", self.rpc_url, *args[1:]])
        cmd = [*cmd, *tail]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise AnchorError(f"cast timed out after {self.timeout}s: {' '.join(args)}") from exc
        if p.returncode != 0 and not allow_error:
            raise AnchorError(f"cast {' '.join(args[:3])} failed: {p.stderr.strip()[:400]}")
        return p.stdout.strip()

    def chain_id(self) -> int:
        return int(self._run("chain-id"))

    def block_number(self) -> int:
        return int(self._run("block-number"))

    def deploy(self, bytecode: str, private_key: str) -> Dict[str, Any]:
        """部署合约字节码，返回 {address, tx_hash, block}。"""
        out = self._run("send", "--json", "--private-key", private_key, "--create",
                        tail=(bytecode,), allow_error=True)
        j = _first_json(out, strict=False)
        if j is None or j.get("contractAddress") in (None, "", "0x0000000000000000000000000000000000000000"):
            raise AnchorError(f"deploy failed: {out[:400]}")
        return {"address": j["contractAddress"], "tx_hash": j.get("transactionHash"),
                "block": _to_int(j.get("blockNumber"))}

    def send_anchor(self, contract: str, digest_b32: str, private_key: str) -> Dict[str, Any]:
        """调用 ``anchor(bytes32)``；重复登记时抛 ``AnchorError``（含 already anchored）。"""
        out = self._run("send", "--json", "--private-key", private_key, contract,
                        "anchor(bytes32)", tail=(digest_b32,), allow_error=True)
        j = _first_json(out, strict=False)
        if j is None:
            # cast 把 revert 写在 stdout/stderr 上：交给调用方判断「已登记」
            raise AnchorError(f"anchor() failed: {out[:400]}")
        if j.get("success") is False or j.get("status") not in (None, "0x1", 1):
            raise AnchorError(f"anchor() reverted: {_error_message(j) or json.dumps(j)[:300]}")
        if not j.get("transactionHash"):
            raise AnchorError(f"anchor() produced no tx hash: {out[:300]}")
        return {"tx_hash": j["transactionHash"], "block": _to_int(j.get("blockNumber"))}

    def call_uint(self, contract: str, sig: str, *args: str) -> int:
        """``eth_call`` 一个返回 uint256 的 view 函数。"""
        out = self._run("call", contract, sig, *args)
        return _to_int(out) or 0

    def call_address(self, contract: str, sig: str, *args: str) -> str:
        """``eth_call`` 一个返回 address 的 view 函数。"""
        return self._run("call", contract, sig, *args)

    def call_bool(self, contract: str, sig: str, *args: str) -> bool:
        """``eth_call`` 一个返回 bool 的 view 函数。"""
        return self._run("call", contract, sig, *args).strip().lower() in ("true", "0x1", "1")

    def timestamp_of_block(self, block: int) -> int:
        """读某区块的时间戳（秒）。"""
        return _to_int(self._run("block", str(block), "--field", "timestamp")) or 0

    def address_of_key(self, private_key: str) -> str:
        """由私钥推导地址（用于把「提交者」写进本地账本 meta）。"""
        # `cast wallet` 是本地子命令，不接受 --rpc-url
        return self._run("wallet", "address", "--private-key", private_key,
                         with_rpc=False).strip()


def _first_json(out: str, strict: bool = True) -> Optional[Dict[str, Any]]:
    """从 cast 输出里取第一个 JSON 对象（`--json` 可能打印多行）。"""
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            return json.loads(line)
        except ValueError:
            continue
    if strict:
        raise AnchorError(f"no JSON in cast output: {out[:300]}")
    return None


def _error_message(j: Dict[str, Any]) -> str:
    """从 cast 的 JSON 错误输出里取人类可读的错误信息。"""
    errs = j.get("errors") or []
    if errs and isinstance(errs[0], dict):
        return str(errs[0].get("message", ""))
    return ""


def _to_int(v: Any) -> Optional[int]:
    """把十进制/十六进制字符串（或 int）转 int；失败返回 None。

    `cast call` 会给大整数附一个人类可读后缀（如 ``1789041583 [1.789e9]``），
    这里只取第一个 token。
    """
    if v is None:
        return None
    if isinstance(v, int):
        return v
    s = str(v).strip().split()[0] if str(v).strip() else ""
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# RPC 锚定后端
# --------------------------------------------------------------------------

class RpcAnchorBackend(AnchorBackend):
    """把证书摘要登记进链上 ``Anchor`` 合约，并（可选）回写本地账本。

    - ``anchor()`` 幂等：先 ``anchoredAt`` 查询；已登记则直接返回既有记录，
      并发情况下遇到 ``already anchored`` revert 也按幂等处理。
    - 给了 ``ledger_path`` 时，**在链上成功之后**把 ``tx_hash`` / 区块号 / 链上
      时间戳写进本地账本条目的 ``meta``（哈希链因此保持自洽：先有 tx 再入账）。
    """

    name = "rpc"

    def __init__(self, rpc_url: str, contract: str, private_key: Optional[str] = None,
                 ledger_path: Optional[Path] = None, client: Any = None,
                 from_address: Optional[str] = None):
        if not rpc_url:
            raise AnchorError("RpcAnchorBackend needs an rpc_url")
        if not contract:
            raise AnchorError("RpcAnchorBackend needs a deployed contract address")
        self.rpc_url = rpc_url
        self.contract = contract
        self.private_key = private_key or ANVIL_KEY
        self.ledger_path = Path(ledger_path) if ledger_path else None
        self.client = client if client is not None else CastRpc(rpc_url)
        self._from = from_address

    def get(self, digest: str) -> Optional[Dict[str, Any]]:
        """读回锚定记录；未登记返回 None。"""
        d = digest_to_bytes32(digest)
        ts = self.client.call_uint(self.contract, "anchoredAt(bytes32)(uint256)", d)
        if not ts:
            return None
        return {
            "backend": self.name,
            "digest": digest.lower().removeprefix("0x"),
            "chain_ts": ts,
            "chain_ts_iso": _iso(ts),
            "contract": self.contract,
            "anchored_by": self.client.call_address(self.contract, "anchoredBy(bytes32)(address)", d),
        }

    def anchor(self, digest: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        d = digest_to_bytes32(digest)
        existing = self.get(digest)
        if existing is not None:
            return {"status": "already_anchored", **existing}
        try:
            tx = self.client.send_anchor(self.contract, d, self.private_key)
        except AnchorError as exc:
            if "already anchored" in str(exc):  # 竞态：别人刚登记了同一个摘要
                again = self.get(digest)
                if again is not None:
                    return {"status": "already_anchored", **again}
            raise
        rec = {
            "backend": self.name,
            "status": "anchored",
            "digest": digest.lower().removeprefix("0x"),
            "contract": self.contract,
            "chain_ts": self.client.call_uint(self.contract, "anchoredAt(bytes32)(uint256)", d),
            "anchored_by": self._from or self._sender(),
            "tx_hash": tx["tx_hash"],
            "block": tx["block"],
        }
        rec["chain_ts_iso"] = _iso(rec["chain_ts"])
        if self.ledger_path is not None:
            # 链上成功后才落本地账本：meta 里带上链上证据（tx/区块/合约/链上时间戳）
            chain_meta = {k: rec[k] for k in ("contract", "tx_hash", "block", "chain_ts", "chain_ts_iso")}
            entry = append_anchor(self.ledger_path, digest, {**(meta or {}), "on_chain": chain_meta})
            rec["ledger"] = {"seq": entry["seq"], "hash": entry["hash"]}
        return rec

    def _sender(self) -> Optional[str]:
        """由私钥推导提交者地址（写进本地 meta，便于审计）。"""
        if getattr(self.client, "address_of_key", None) is None:
            return None
        try:
            return self.client.address_of_key(self.private_key)
        except AnchorError:
            return None

    def healthy(self) -> Tuple[bool, str]:
        """连通性自检：链上有合约字节码。"""
        try:
            code = self.client._run("code", self.contract)
        except AnchorError as exc:
            return False, str(exc)
        if not code or code in ("0x", "0x0"):
            return False, f"no contract code at {self.contract}"
        return True, "ok"


def _iso(ts: Optional[int]) -> Optional[str]:
    """unix 秒 → ISO-8601 UTC 字符串。"""
    if not ts:
        return None
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# 便捷入口
# --------------------------------------------------------------------------

def load_artifact(path: Optional[Path] = None) -> Dict[str, Any]:
    """读入库的 ``contracts/Anchor.json``（abi + bytecode）。"""
    p = Path(path) if path else ARTIFACT
    if not p.exists():
        raise AnchorError(f"contract artifact missing: {p} (build it: cd contracts && forge build)")
    return json.loads(p.read_text(encoding="utf-8"))


def deploy_anchor_contract(rpc_url: str, private_key: Optional[str] = None,
                           client: Any = None, artifact_path: Optional[Path] = None,
                           from_address: Optional[str] = None) -> Dict[str, Any]:
    """把 Anchor 合约部署到 ``rpc_url`` 指向的链，返回部署信息。"""
    art = load_artifact(artifact_path)
    cli = client if client is not None else CastRpc(rpc_url)
    info = cli.deploy(art["bytecode"], private_key or ANVIL_KEY)
    return {
        "contract": art["contractName"],
        "address": info["address"],
        "tx_hash": info["tx_hash"],
        "block": info["block"],
        "chain_id": cli.chain_id(),
        "rpc_url": rpc_url,
        "deployer": from_address or (cli.address_of_key(private_key or ANVIL_KEY)
                                     if getattr(cli, "address_of_key", None) else None),
    }


def backend_from_env(ledger_path: Optional[Path] = None, rpc_url: Optional[str] = None,
                     contract: Optional[str] = None, private_key: Optional[str] = None,
                     require: bool = False) -> AnchorBackend:
    """按环境/参数选后端：给了 RPC 与合约地址 → 链上；否则 → 文件账本。

    ``require=True`` 时，配置不全直接报错（供 ``--rpc`` 这类显式请求使用），
    避免调用方以为「已经上链」其实只写了本地文件。
    """
    rpc = rpc_url or os.environ.get(ENV_RPC)
    ctr = contract or os.environ.get(ENV_CONTRACT)
    key = private_key or os.environ.get(ENV_KEY)
    if rpc and ctr:
        return RpcAnchorBackend(rpc, ctr, key, ledger_path=ledger_path)
    if require:
        raise AnchorError(
            "on-chain anchoring requested but not configured: pass --rpc and --contract "
            f"(or set {ENV_RPC} / {ENV_CONTRACT})")
    return FileLedgerBackend(ledger_path) if ledger_path else FileLedgerBackend(Path("ledger.jsonl"))


def anchor_on_chain(digest: str, rpc_url: Optional[str] = None,
                    contract: Optional[str] = None,
                    private_key: Optional[str] = None,
                    ledger_path: Optional[Path] = None) -> Dict[str, Any]:
    """把 ``digest`` 登记到链上 Anchor 合约（缺配置时报明确错误）。

    文件账本是默认的、可离线验证的后端。真实部署通过 ``rpc_url`` + 已部署的
    ``contract`` 把 digest 作为 calldata/事件提交；未配置时本钩子显式报错，
    避免调用方误以为锚定已发生。
    """
    rpc = rpc_url or os.environ.get(ENV_RPC)
    ctr = contract or os.environ.get(ENV_CONTRACT)
    if not (rpc and ctr):
        raise NotImplementedError(
            "on-chain anchoring backend not configured: pass rpc_url + contract "
            f"(or set {ENV_RPC} / {ENV_CONTRACT}) or use the file ledger backend "
            "for offline verification")
    return RpcAnchorBackend(rpc, ctr, private_key or os.environ.get(ENV_KEY),
                            ledger_path=ledger_path).anchor(digest)


def verify_digest_on_chain(digest: str, rpc_url: str, contract: str,
                           client: Any = None) -> Optional[Dict[str, Any]]:
    """只读核对：返回链上记录（未登记为 None）。供 verify_session --rpc 使用。"""
    b = RpcAnchorBackend(rpc_url, contract, client=client)
    return b.get(digest)
