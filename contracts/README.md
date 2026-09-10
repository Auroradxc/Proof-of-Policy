# contracts/ —— 链上锚定合约

| 文件 | 说明 |
|---|---|
| `Anchor.sol` | 锚定登记合约源码（`anchor(bytes32)` / `anchoredAt` / `anchoredBy` / `isAnchored` / `count` + `Anchored` 事件） |
| `Anchor.json` | **入库**的编译产物 = `abi` + `bytecode`。运行期部署/锚定/读回**不需要 solc 或 forge**，只需要这个文件 + `cast`（或任何 EVM RPC 客户端） |
| `foundry.toml` | 只用于重新生成 `Anchor.json` |

## 语义

- `anchor(digest)` 把证书摘要（`cert_digest` = 证书载荷的 SHA-256，32 字节）登记进 `anchoredAt` 映射，并发出
  `Anchored(digest, ts, by, seq)` 事件。
- **首次即最终**：同一摘要重复登记会 revert（`Anchor: already anchored`）——链上时间戳不可被后来的提交者覆盖。
  调用方重试前应先 `anchoredAt()` 查询；`policydsl.anchor.RpcAnchorBackend` 已内置该逻辑（幂等）。
- `anchoredAt(d) == 0` 表示未登记（区块时间戳不为 0，该约定安全）。
- 链上**只存 32 字节摘要**，不存响应/策略内容（隐私）。

## 重新生成 Anchor.json

```bash
cd contracts
forge build
python3 - <<'PY'
import json, pathlib
art = json.loads(pathlib.Path("out/Anchor.sol/Anchor.json").read_text())
pathlib.Path("Anchor.json").write_text(json.dumps({
    "_comment": "由 `forge build` 生成并入库：运行期部署/锚定不需要 solc/forge。",
    "contractName": "Anchor",
    "solc": art["metadata"]["compiler"]["version"],
    "abi": art["abi"],
    "bytecode": art["bytecode"]["object"],
}, indent=2) + "\n")
PY
```

> `Anchor.json` 是唯一入库的产物；`contracts/out/`、`contracts/cache/` 已 gitignore。
> 校验一致性：`python3 -m unittest tests.test_anchor_chain -v`（含 abi 形状与 bytecode 冒烟检查）。
