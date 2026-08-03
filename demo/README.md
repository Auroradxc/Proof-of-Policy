# demo/ —— Agent 集成（W6）

目标（W6）：把 PoP 插进一个 LangGraph / MCP agent 的**生成路径**与**关键工具调用路径**，产出可验证的合规证书。

## 当前状态

占位。W6 填充：
- `agent/`：一个最小的 LangGraph agent（工具调用示例）；
- `hooks/`：在 `generate` 与 `call_tool` 后调用 `policydsl.evaluate()` 出证；
- `cert/`：合规证书格式 `{π版本, circuit_hash, response_commitment, proof, ts}`（DSSE/JSON）；
- `scripts/`：链上锚定（SP1 verify 合约）。

## 证书示例（目标形态）

```jsonc
{
  "cert_version": "v1",
  "policy": { "policy_id": "eu-ai-act-v1", "policy_version": "0.1.0" },
  "policy_hash": "<constraint spec sha256>",
  "response_commitment": "<sha256(response)>",
  "passed": true,
  "proof": "<SP1 proof>",
  "ts": "2026-..."
}
```
