# EU AI Act 映射（Art.12 / Art.13）

> 说明：本文是 Proof-of-Policy 证书字段与 EU AI Act 透明义务的**工程映射**，
> 非法律意见。用于论文与落地叙事对齐。

## Art.12 — Record-keeping（记录保存 / 自动日志）

| 要求（概括） | PoP 对应 |
|---|---|
| 高风险 AI 系统在生命周期内保留**自动记录** | 每次 `on_generate` / `on_tool_call` 产出一张证书（`cert_version`、`ts`） |
| 记录可追溯、可作为事后审计依据 | 证书 `policy_hash`（策略版本绑定）+ `binding.{vkey_hash, proof_sha256}`（电路/证明绑定），`cert_digest` 入**防篡改锚定账本** |
| 日志完整性 | 锚定账本为哈希链（`prev`/`hash`），`verify_ledger` 可检测任何增删改 |
| 按次（per-invocation）记录 | 证书粒度为单次响应/单次工具调用 |

## Art.13 — Transparency（透明度 / 部署者信息）

| 要求（概括） | PoP 对应 |
|---|---|
| 向部署者提供系统能力与限制 | `mode`（public/private）与 `outcome` 告知验证方：内容是否公开、是否合规 |
| 决策可核验 | 验证方可**独立**验证：DSSE 签名 + 复算 `policy_hash` + 锚定查询 + SP1 证明密码学验证（`scripts/verify_cert.py`） |
| 内容最小暴露 | 私有模式只公开响应**承诺**与**证据承诺**（+ 脱敏证明 `mask_covered`），不泄露原文 |

## 证书字段 → 义务映射（摘要）

```
payload = {
  cert_version, ts,                 # Art.12：可识别、可时序化的记录
  policy{id,version}, policy_hash,  # Art.12/13：策略版本绑定、可复算
  mode, outcome,                    # Art.13：透明度（内容/结果披露程度）
  binding{vkey_hash, proof_sha256}, # Art.12：电路与证明工件绑定
  ai_act{art12_record_keeping, art13_transparency}
}
envelope = DSSE-like { payloadType, payload(b64), signatures }   # 完整性/来源
anchor   = { seq, prev, digest, ts, hash }                       # 防篡改记录链
```

## 尚未覆盖（后续）

- 真实链上锚定（`anchor_on_chain` RPC 后端）与智能合约事件；
- Ed25519/HSM 签名替换 demo HMAC；
- 工具调用路径的**电路内**证明（当前为 Python 参考层，证书标 `zk:false`）；
- 训练数据/模型卡（Art.11 等）超出本系统范围。
