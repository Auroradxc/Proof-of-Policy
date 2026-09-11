# EU AI Act 映射（Art.12 / Art.13）

> 说明：本文是 Proof-of-Policy 证书字段与 EU AI Act 透明义务的**工程映射**，
> 非法律意见。用于论文与落地叙事对齐。

## Art.12 — Record-keeping（记录保存 / 自动日志）

| 要求（概括） | PoP 对应 |
|---|---|
| 高风险 AI 系统在生命周期内保留**自动记录** | 每次 `on_generate` / `on_tool_call` 产出一张证书（`cert_version`、`ts`） |
| 记录可追溯、可作为事后审计依据 | 证书 `policy_hash`（策略版本绑定）+ `binding.{vkey_hash, proof_sha256, proof_mode}`（电路/证明绑定 + **证据档位诚实标注**，P0-4）+ `challenge.response_binding`（**本次响应绑定**，P0-2），`cert_digest` 入**防篡改锚定账本** |
| 日志完整性 | 锚定账本为哈希链（`prev`/`hash`），`verify_ledger` 可检测任何增删改 |
| 按次（per-invocation）记录 | 证书粒度为单次响应/单次工具调用 |

## Art.13 — Transparency（透明度 / 部署者信息）

| 要求（概括） | PoP 对应 |
|---|---|
| 向部署者提供系统能力与限制 | `mode`（public/private）与 `outcome` 告知验证方：内容是否公开、是否合规 |
| 决策可核验 | 验证方可**独立**验证：DSSE 签名 + 复算 `policy_hash` + **用送达的 T′ 与 nonce 复算 `response_binding`** + 锚定查询 + SP1 证明密码学验证（`scripts/verify_cert.py --response T′`） |
| 内容最小暴露 | 私有模式只公开响应**承诺**与**证据承诺**（+ 脱敏证明 `mask_covered`），不泄露原文 |

## 证书字段 → 义务映射（摘要）

```
payload = {
  cert_version, ts,                 # Art.12：可识别、可时序化的记录
  policy{id,version}, policy_hash,  # Art.12/13：策略版本绑定、可复算
  mode, outcome,                    # Art.13：透明度（内容/结果披露程度）
  binding{vkey_hash, proof_sha256, proof_mode}, # Art.12：电路、证明工件与证据档位绑定
  challenge{scheme, nonce, response_binding},  # Art.12：本次响应与会话绑定（P0-2）
  ai_act{art12_record_keeping, art13_transparency}
}
envelope = DSSE-like { payloadType, payload(b64), signatures }   # 完整性/来源
anchor   = { seq, prev, digest, ts, hash }                       # 防篡改记录链（文件后端）
anchor   = Anchor.anchor(digest) { ts, by, seq } + Anchored 事件 # 链上登记（RPC 后端）
```

## 尚未覆盖（后续）

- ~~真实链上锚定（`anchor_on_chain` RPC 后端）与智能合约事件~~ → **已实现**（`contracts/Anchor.sol` + `RpcAnchorBackend`，本地 Anvil 端到端 PASS，见 `docs/reproduce.md` §10；公共测试网/生产部署与密钥托管仍待补）；
- ~~Ed25519/HSM 签名替换 demo HMAC~~ → **Ed25519 已落地**（P0-3：私钥不动、公钥随 `key.json`/`session.json` 分发，`verify_cert.py --keyring`）；HSM/KMS 托管仍待补；
- **工具调用轨迹的绑定**：`tool_arg_guard` / `budget_bound` 的规则本身**已入电路**（证书 `zk:true` 即此意），
  但 `tool_calls` / `token_count` 仍是证明者自填的**私有输入**，不是被证明的事实 —— 即「规则可证」
  不等于「轨迹为真」。把轨迹本身拴住是 P1-5（工具回执链 / MCP 签名）；
- 训练数据/模型卡（Art.11 等）超出本系统范围。
